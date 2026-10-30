"""Single entry point for every model call.

:func:`call_model` composes the pieces that already exist (config,
price book, spend, transport, attempts, payload preparation,
pseudonymizer, egress filter, injection predicate). Nothing else in
the codebase may talk to a model: only :mod:`corvus.llm.transport`
sends HTTP, and only this module calls it.

Order of operations on every call, per backend:

1. Payload and guardrail setup with no hold yet: stored-signal
   wiring check, dictionary availability, then
   :func:`corvus.guardrails.payload.prepare_payload` for the
   backend's trust level (cloud drops ``raw_data``, pseudonymizes
   and redacts; on-prem reads raw evidence).
2. Budget reservation (:func:`corvus.llm.spend.reserve`) before
   EACH transport try, for the worst case of one attempt. When the
   cap would be crossed before anything was sent the call is
   refused with outcome ``"pending_ai"`` and the model is never
   contacted; a refusal mid-loop stops the loop and ends
   ``ai_failed``. Exactly one live hold exists per in-flight try,
   never more.
3. Egress check (:class:`corvus.guardrails.egress.EgressFilter`)
   for cloud backends, before anything is sent.
4. Transport attempt (:func:`corvus.llm.transport.run_attempt`).
5. Validators, in order: syntax, schema, semantics, policy,
   security. Each returns structured errors (code, path, message).
6. :func:`corvus.llm.attempts.record_attempt` with that try's
   reservation id — always, for every transport answer including
   failed and empty ones. For billed (cloud) backends the attempt
   row, the reservation conversion and the spend row land in one
   transaction and that conversion writes the only spend row. A
   try that produced no answer object (transport exception,
   egress block, payload error) releases its hold instead of
   recording.

Self-correction: at most 3 transport tries per backend. Attempt 2
repeats the conversation plus the structured errors. Attempt 3
escalates (temperature 0, one reasoning step up within the
configured token cap, simplified schema when the response model
offers one). The loop stops early when the same error code repeats
twice. Then the other backend of the routing profile is tried
(again through egress, budget and guardrails), then the
deterministic fallback marked "AI analysis failed" (``ai_failed``).

Validator-5 (security) failures are never retried and never fall
back: the output is quarantined (``quarantined``, never stored as
an answer), the deterministic result is kept, a ``security_events``
row is inserted, the incident is marked ``review_required``, and
the attempt is recorded with failed validator
``security_injection_echo``.

Empty and invalid outputs (D23): a reply whose final channel is
empty, or whose content holds no parseable JSON matching the
schema, fails like a schema failure and is retried. When every
recorded attempt on every backend failed before semantics (only
syntax/schema failures), the outcome is ``indeterminate`` with
``needs_human_review`` True and the incident escalated
(``review_required``); the value is None — never dismissed, never
benign, never a swallowed exception. ``indeterminate`` is a
first-class :class:`CallOutcome` status and matches the
``incident_analyses.status`` value from migration
``0004_llm_audit.sql``.

Reasoning capture (D24): on-prem attempts store
``message.reasoning`` in ``llm_attempts.reasoning`` (audit only —
it is never placed in any outbound payload); cloud attempts store
NULL and keep only the token count. This module never renders
reasoning; any consumer that shows it must label it "unverified".
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import psycopg
from pydantic import BaseModel, ValidationError

from corvus.attack.dictionary import AttackDictionary, load_dictionary
from corvus.guardrails.egress import (
    EgressBlocked,
    EgressFilter,
    default_allowed_hosts,
)
from corvus.guardrails.injection import (
    InjectionSignal,
    echoes_injection,
    signals_for_incident,
)
from corvus.guardrails.payload import prepare_payload
from corvus.guardrails.pseudonymizer import PSEUDONYM_PATTERN
from corvus.llm import transport as transport_module
from corvus.llm.attempts import record_attempt
from corvus.llm.config import BackendConfig, get_backend
from corvus.llm.price_book import ModelPrice, cost_usd, load_price_book
from corvus.llm.spend import (
    BudgetExceededError,
    hold_ttl,
    release_reservation,
    reserve,
)
from corvus.llm.transport import (
    Attempt,
    AttemptError,
    LimiterTimeoutError,
    TransportError,
)

__all__ = [
    "AI_FAILED",
    "INDETERMINATE",
    "PENDING_AI",
    "QUARANTINED",
    "RESOLVED",
    "CallContext",
    "CallOutcome",
    "StructuredError",
    "call_model",
    "validate_policy",
    "validate_schema",
    "validate_security",
    "validate_semantics",
    "validate_syntax",
]

_log = logging.getLogger(__name__)

RESOLVED = "resolved"
INDETERMINATE = "indeterminate"
AI_FAILED = "ai_failed"
PENDING_AI = "pending_ai"
QUARANTINED = "quarantined"

OutcomeStatus = Literal[
    "resolved", "indeterminate", "ai_failed", "pending_ai", "quarantined"
]

MAX_ATTEMPTS = 3
REASONING_ORDER = ("low", "medium", "high")
DEFAULT_TEMPERATURE = 0.2
DEFAULT_REASONING_STRENGTH = "medium"

#: Model-output keys that may cite supporting evidence event uids:
#: :data:`corvus.guardrails.injection.EVIDENCE_FIELDS` plus the
#: analysis-loop names. Nested triage citations
#: (``key_events[].event_uid``, ``timeline[].event_uid``) are found
#: by :func:`_walk_event_uids`, not by this tuple.
EVIDENCE_KEYS = (
    "evidence_event_uids",
    "supporting_event_uids",
    "cited_events",
    "suspicious_event_uids",
    "event_uids",
    "evidence_uids",
)

#: Technique-id token shape (same rule as the evidence masker).
_TECHNIQUE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9])",
    re.IGNORECASE | re.ASCII,
)

#: Words that must appear for the cheap language-agreement check.
_EN_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "of",
        "to",
        "in",
        "is",
        "was",
        "are",
        "for",
        "with",
        "that",
        "this",
        "from",
        "have",
        "were",
        "been",
        "will",
        "there",
        "their",
        "about",
        "which",
        "when",
        "into",
        "than",
        "then",
        "only",
        "after",
        "because",
        "these",
        "most",
    }
)
_ES_STOPWORDS = frozenset(
    {
        "el",
        "la",
        "de",
        "que",
        "en",
        "los",
        "las",
        "una",
        "por",
        "con",
        "del",
        "para",
        "como",
        "está",
        "están",
        "fue",
        "son",
        "sus",
        "este",
        "esta",
        "pero",
        "más",
        "todo",
        "entre",
        "cuando",
        "donde",
    }
)
_WORD = re.compile(r"[a-záéíóúñü]+")

#: String severity suggestions mapped onto OCSF severity ids
#: (Informational 1 .. Fatal 6).
_SEVERITY_WORDS = {
    "info": 1,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "fatal": 6,
}

#: Validators that mean "empty or invalid": no parseable, schema
#: valid output ever existed, so an all-such run is indeterminate.
EMPTY_INVALID_VALIDATORS = frozenset({"syntax", "schema"})


@dataclass(frozen=True)
class StructuredError:
    """One validator finding: machine-readable code, path, message."""

    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        """Return the JSON-serializable mapping stored and re-prompted."""
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class CallOutcome:
    """The result of :func:`call_model`.

    ``status`` is one of ``resolved`` (``value`` is the validated
    response model), ``quarantined`` (validator 5 fired; ``value``
    is the deterministic fallback), ``ai_failed`` (all validation
    and the fallback backend failed; ``value`` is the deterministic
    fallback marked "AI analysis failed"), ``indeterminate`` (every
    attempt was empty or invalid; ``value`` is None, never benign),
    or ``pending_ai`` (budget refused; ``value`` is None, nothing
    was sent). ``errors`` carries the last structured errors and
    never contains secrets. ``attempts`` counts recorded tries
    (every transport try is recorded, including raised failures).
    ``error_codes`` lists the per-try error codes in order, so a
    caller can store the whole failure trail (for example
    ``["context_overflow", "timeout", "timeout"]``).
    """

    status: str
    value: Any
    errors: tuple[dict[str, str], ...]
    attempts: int
    needs_human_review: bool
    model: str | None
    failed_validator: str | None = None
    error_codes: tuple[str, ...] = ()


@dataclass
class CallContext:
    """Everything validators and guardrails need besides the payload.

    - ``event_uids``: the incident's valid evidence event uids.
    - ``deterministic_floor``: required; a missing floor is a
      policy error, never a pass.
    - ``language``: ``en``/``english`` or ``es``/``spanish``.
    - ``valid_techniques`` / ``attack_dictionary``: technique
      membership (explicit set wins; else the given dictionary;
      else the default dictionary file when loadable).
    - ``valid_pseudonyms``: known pseudonyms (explicit set wins;
      else read from the ``pseudonyms`` table when a database URL
      is available; else well-formed tokens pass).
    - ``injection_signals`` / ``payload_texts`` /
      ``requested_verdict``: inputs to the security predicate.
    - ``payload`` / ``entities``: structured incident payload for
      :func:`prepare_payload` and typed entities registered before
      pseudonymizing (cloud only).
    - ``deterministic_value``: returned for ``quarantined`` and
      ``ai_failed`` outcomes.
    - ``incident_id``: audit key for attempts, quarantine and
      escalation writes; None skips incident-scoped writes.
    """

    event_uids: Sequence[str] = ()
    deterministic_floor: int | None = None
    language: str = "en"
    valid_techniques: set[str] | None = None
    attack_dictionary: AttackDictionary | None = None
    valid_pseudonyms: set[str] | None = None
    injection_signals: Sequence[InjectionSignal] = ()
    payload_texts: Mapping[tuple[str, str], str] | None = None
    requested_verdict: str | None = None
    payload: Any = None
    entities: Sequence[tuple[str, str]] | None = None
    deterministic_value: Any = None
    incident_id: int | None = None
    database_url: str | None = None
    fallback_value_note: str = "AI analysis failed"
    extra: dict[str, Any] = field(default_factory=dict)


def _err(code: str, path: str, message: str) -> StructuredError:
    """Build one structured validator error."""
    return StructuredError(code=code, path=path, message=message)


def _extract_json_object(content: str) -> dict[str, Any] | None:
    """Return the first JSON object inside ``content``, or None.

    Strict parse first, then ``raw_decode`` from each ``{`` in
    order, so prose around one JSON object is accepted but
    non-JSON text is not guessed at.
    """
    text = content.strip()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    decoder = json.JSONDecoder()
    starts = [index for index, char in enumerate(text) if char == "{"]
    for start in starts[:20]:
        try:
            candidate, _ = decoder.raw_decode(text[start:])
        except ValueError:
            continue
        if isinstance(candidate, dict):
            return candidate
    return None


def validate_syntax(
    content: str | None, finish_reason: str | None
) -> tuple[dict[str, Any] | None, list[StructuredError]]:
    """Validator 1: non-empty content holding one JSON object.

    Empty content and content with no JSON object share the
    ``invalid_output`` code (one trigger: Glimmer sometimes closes
    its reasoning channel and stops without a final message, and
    one retry recovers it). ``finish_reason == "length"`` reports
    the distinct ``truncated`` code so the next attempt stays at
    the configured token cap.
    """
    if finish_reason == "length":
        return None, [
            _err(
                "truncated",
                "",
                "model stopped for length before completing the JSON "
                "object; retry at the configured token cap",
            )
        ]
    if content is None or content.strip() == "":
        return None, [_err("invalid_output", "", "model returned empty content")]
    parsed = _extract_json_object(content)
    if parsed is None:
        return None, [
            _err(
                "invalid_output",
                "",
                "content holds no parseable JSON object",
            )
        ]
    return parsed, []


def _active_model(response_model: type[BaseModel], escalated: bool) -> type[BaseModel]:
    """Return the schema for this attempt.

    Attempt 3 uses the simplified schema when the response model
    offers one as a ``simplified()`` classmethod returning another
    pydantic model; every other attempt uses the full model. A
    ``simplified()`` failure propagates: it is our configuration
    error, never the model's fault.
    """
    if not escalated:
        return response_model
    simplified = getattr(response_model, "simplified", None)
    if callable(simplified):
        candidate = simplified()
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return response_model


def validate_schema(
    parsed: Mapping[str, Any], response_model: type[BaseModel]
) -> tuple[BaseModel | None, list[StructuredError]]:
    """Validator 2: the pydantic response model validates.

    Unknown fields are rejected even when the model itself would
    allow extra keys.
    """
    errors: list[StructuredError] = []
    try:
        value = response_model.model_validate(dict(parsed))
    except ValidationError as exc:
        for item in exc.errors(include_url=False):
            loc = ".".join(str(part) for part in item.get("loc", ()))
            errors.append(_err("schema", loc, f"{item.get('msg', 'invalid value')}"))
        return None, errors
    if response_model.model_config.get("extra") != "forbid":
        known = set(response_model.model_fields)
        for key in parsed:
            if key not in known:
                errors.append(_err("schema", str(key), f"unknown field {key!r}"))
        if errors:
            return None, errors
    return value, []


def _walk_event_uids(value: Any) -> list[str]:
    """Collect nested ``event_uid`` string values (triage citations).

    Triage schemas cite events inside objects (``key_events[].event_uid``,
    ``timeline[].event_uid``), not in the top-level uid lists above, so
    the membership check must walk the whole output. Every found value
    counts as cited: quoting an event still requires it to belong to
    the incident.
    """
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "event_uid" and isinstance(item, str) and item.strip():
                found.append(item.strip())
            else:
                found.extend(_walk_event_uids(item))
        return found
    if isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_walk_event_uids(item))
    return found


def _cited_uids(parsed: Mapping[str, Any]) -> dict[str, str]:
    """Map each cited evidence uid to the output key that cited it."""
    cited: dict[str, str] = {}
    for key in EVIDENCE_KEYS:
        value = parsed.get(key)
        if isinstance(value, str):
            if value.strip():
                cited.setdefault(value.strip(), key)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item.strip():
                    cited.setdefault(item.strip(), key)
    for uid in _walk_event_uids(parsed):
        cited.setdefault(uid, "event_uid")
    return cited


def _walk_strings(value: Any, skip_quote: bool) -> list[str]:
    """Collect string leaves; skip ``quoted_evidence`` when asked."""
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
        return found
    if isinstance(value, Mapping):
        for key, item in value.items():
            if skip_quote and key == "quoted_evidence":
                continue
            found.extend(_walk_strings(item, skip_quote))
        return found
    if isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_walk_strings(item, skip_quote))
    return found


_default_attack: AttackDictionary | None | bool = False


def _resolve_attack(context: CallContext) -> AttackDictionary | None:
    """Return the ATT&CK dictionary for technique checks, if any.

    A dictionary-load failure propagates: a missing dictionary is
    our configuration error, and reporting every technique as
    unknown would blame the model for it.
    """
    if context.attack_dictionary is not None:
        return context.attack_dictionary
    global _default_attack
    if _default_attack is False:
        _default_attack = load_dictionary()
    assert not isinstance(_default_attack, bool)
    return _default_attack


def _technique_known(
    raw: str, context: CallContext, attack: AttackDictionary | None
) -> bool:
    """True when a technique token resolves to a live technique."""
    candidate = raw.strip().upper()
    if context.valid_techniques is not None:
        return candidate in {item.upper() for item in context.valid_techniques}
    if attack is None:
        return False
    return attack.resolve(candidate) is not None


def _known_pseudonyms(
    context: CallContext, database_url: str | None
) -> set[str] | None:
    """Return known pseudonyms, or None for pattern-only checking."""
    if context.valid_pseudonyms is not None:
        return set(context.valid_pseudonyms)
    if not database_url:
        return None
    try:
        with psycopg.connect(database_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pseudonym FROM pseudonyms")
                return {str(row[0]) for row in cur.fetchall()}
    except Exception:
        return None


def _normalize_language(raw: Any) -> str | None:
    """Map a language value to ``en`` / ``es``, or None."""
    if not isinstance(raw, str):
        return None
    token = raw.strip().casefold()
    if token in ("en", "english"):
        return "en"
    if token in ("es", "spanish", "español"):
        return "es"
    return None


def _model_semantic_errors(
    response_model: type[BaseModel] | None,
    parsed: Mapping[str, Any],
    context: CallContext,
) -> list[StructuredError]:
    """Run a response model's own semantic hook, if it offers one.

    A model class may define ``semantic_errors(parsed, context)``
    returning a list of ``{"code", "path", "message"}`` mappings
    (for example the triage entity-grounding check). A malformed
    hook result propagates: it is our configuration error, never
    the model's fault.
    """
    if response_model is None:
        return []
    hook = getattr(response_model, "semantic_errors", None)
    if hook is None:
        return []
    items = hook(parsed, context)
    if items is None:
        return []
    errors: list[StructuredError] = []
    for item in items:
        if (
            isinstance(item, Mapping)
            and isinstance(item.get("code"), str)
            and isinstance(item.get("path"), str)
            and isinstance(item.get("message"), str)
        ):
            errors.append(
                _err(str(item["code"]), str(item["path"]), str(item["message"]))
            )
        else:
            raise TypeError(
                f"{response_model.__name__}.semantic_errors must return "
                f"a list of code/path/message mappings, got {item!r}"
            )
    return errors


def _schema_language_default(
    response_model: type[BaseModel] | None,
) -> tuple[Any, bool]:
    """Return the schema's ``language`` default and whether one exists.

    Generic across response models (triage today, analysis tomorrow):
    an omitted ``language`` counts as this default, so a default of
    ``"en"`` satisfies an English request without a retry.
    """
    fields = getattr(response_model, "model_fields", None)
    if not isinstance(fields, dict) or "language" not in fields:
        return None, False
    field = fields["language"]
    required_check = getattr(field, "is_required", None)
    if callable(required_check) and required_check():
        return None, False
    return field.default, True


def validate_semantics(
    parsed: Mapping[str, Any],
    context: CallContext,
    database_url: str | None = None,
    *,
    response_model: type[BaseModel] | None = None,
) -> list[StructuredError]:
    """Validator 3: uids, techniques, pseudonyms, language, model hook.

    Every cited event uid must belong to the incident; every
    ATT&CK technique token must resolve in the dictionary;
    pseudonym tokens must be known; the ``language`` field must
    equal the request and a cheap stopword check must agree. An
    omitted ``language`` counts as the schema default (see
    :func:`_schema_language_default`), so it passes only when that
    default matches the request. When ``response_model`` offers a
    ``semantic_errors`` hook, its findings are appended
    (schema-specific grounding).
    """
    errors: list[StructuredError] = []
    valid_uids = set(context.event_uids)
    for uid, key in _cited_uids(parsed).items():
        if uid not in valid_uids:
            errors.append(
                _err(
                    "unknown_event_uid",
                    key,
                    f"cited event uid {uid!r} is not part of the incident",
                )
            )
    seen_techniques: set[str] = set()
    for text in _walk_strings(parsed, skip_quote=True):
        for match in _TECHNIQUE_TOKEN.finditer(text):
            seen_techniques.add(match.group(0).upper())
    attack: AttackDictionary | None = context.attack_dictionary
    if seen_techniques and context.valid_techniques is None and attack is None:
        attack = _resolve_attack(context)
    for technique in sorted(seen_techniques):
        if not _technique_known(technique, context, attack):
            errors.append(
                _err(
                    "unknown_technique",
                    "techniques",
                    f"ATT&CK technique {technique!r} is not in the dictionary",
                )
            )
    known_pseudos = _known_pseudonyms(context, database_url)
    seen_pseudos: set[str] = set()
    for text in _walk_strings(parsed, skip_quote=False):
        for match in PSEUDONYM_PATTERN.finditer(text):
            seen_pseudos.add(match.group(0))
    for pseudo in sorted(seen_pseudos):
        if known_pseudos is not None and pseudo not in known_pseudos:
            errors.append(
                _err(
                    "invalid_pseudonym",
                    "",
                    f"pseudonym {pseudo!r} is not a known pseudonym",
                )
            )
    requested = _normalize_language(context.language)
    if requested is None:
        errors.append(
            _err(
                "language_mismatch",
                "language",
                f"request language {context.language!r} is not en or es",
            )
        )
    else:
        agreed: str | None = None
        if "language" in parsed:
            claimed = _normalize_language(parsed.get("language"))
            if claimed != requested:
                errors.append(
                    _err(
                        "language_mismatch",
                        "language",
                        f"output language {parsed.get('language')!r} does not match "
                        f"the requested language {context.language!r}",
                    )
                )
            else:
                agreed = claimed
        else:
            default_raw, has_default = _schema_language_default(response_model)
            effective = _normalize_language(default_raw) if has_default else None
            if effective is not None and effective == requested:
                agreed = effective
            else:
                if has_default:
                    detail = (
                        f"output omits `language` (schema default "
                        f"{default_raw!r} does not match the requested "
                        f"language {context.language!r}); set `language` "
                        "explicitly to the requested language"
                    )
                else:
                    detail = (
                        "output omits `language`; set `language` explicitly "
                        f"to the requested language {context.language!r}"
                    )
                errors.append(_err("language_mismatch", "language", detail))
        if agreed is not None:
            words = _WORD.findall(" ".join(_walk_strings(parsed, True)).lower())
            if len(words) >= 3:
                stopwords = _EN_STOPWORDS if requested == "en" else _ES_STOPWORDS
                if not any(word in stopwords for word in words):
                    errors.append(
                        _err(
                            "language_mismatch",
                            "language",
                            "no stopwords of the requested language found "
                            "in the output text",
                        )
                    )
    errors.extend(_model_semantic_errors(response_model, parsed, context))
    return errors


def _output_severity(parsed: Mapping[str, Any]) -> tuple[int | None, str | None]:
    """Return (severity_id, error_code) for the policy check."""
    raw = parsed.get("severity_id", parsed.get("severity"))
    if raw is None:
        raw = parsed.get("severity_suggestion")
        if raw is None:
            return None, None
        if isinstance(raw, str) and raw.strip().casefold() in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[raw.strip().casefold()], None
        return None, "unknown_severity"
    if isinstance(raw, bool) or not isinstance(raw, int):
        if isinstance(raw, str) and raw.strip().casefold() in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[raw.strip().casefold()], None
        return None, "unknown_severity"
    return raw, None


def validate_policy(
    parsed: Mapping[str, Any], context: CallContext
) -> list[StructuredError]:
    """Validator 4: the verdict respects the deterministic floor.

    The model may raise severity by at most one level, only while
    citing validated event uids, and may never lower it. A missing
    floor in context is an error, not a pass.
    """
    floor = context.deterministic_floor
    if floor is None:
        return [
            _err(
                "missing_floor",
                "",
                "no deterministic severity floor in context; refusing to pass",
            )
        ]
    severity, problem = _output_severity(parsed)
    if problem is not None:
        return [_err(problem, "severity_id", "output severity is not usable")]
    if severity is None:
        return []
    if severity < floor:
        return [
            _err(
                "severity_below_floor",
                "severity_id",
                f"severity {severity} is below the deterministic floor {floor}",
            )
        ]
    if severity > floor + 1:
        return [
            _err(
                "severity_above_cap",
                "severity_id",
                f"severity {severity} is more than one above the floor {floor}",
            )
        ]
    if severity == floor + 1:
        cited = _cited_uids(parsed)
        if not any(uid in set(context.event_uids) for uid in cited):
            return [
                _err(
                    "unjustified_escalation",
                    "severity_id",
                    "raised severity cites no validated incident event uid",
                )
            ]
    return []


def validate_security(
    parsed: Mapping[str, Any], context: CallContext
) -> list[StructuredError]:
    """Validator 5: the output must not echo injected instructions.

    Runs :func:`corvus.guardrails.injection.echoes_injection` over
    the incident's stored signals. Any finding is one
    ``security_injection_echo`` error; the caller quarantines
    instead of retrying.
    """
    signals = list(context.injection_signals or [])
    if not signals:
        return []
    floor = context.deterministic_floor if context.deterministic_floor else 0
    findings = echoes_injection(
        parsed,
        signals,
        floor,
        context.requested_verdict,
        context.payload_texts,
    )
    return [
        _err(
            "security_injection_echo",
            "",
            f"{finding.code}: {finding.message}",
        )
        for finding in findings
    ]


def _resolve_database_url(explicit: str | None) -> str:
    """Return the database URL or raise before any model contact."""
    url = explicit or os.environ.get("DATABASE_URL")
    if not url:
        raise ValueError(
            "missing database URL: pass database_url or set DATABASE_URL "
            "(every attempt is recorded in llm_attempts)"
        )
    return url


def _worst_case_usd(backend: BackendConfig, prices: Mapping[str, ModelPrice]) -> float:
    """Worst-case single-attempt USD cost under the price book."""
    return cost_usd(
        prices,
        backend.model,
        backend.max_input_tokens,
        0,
        backend.max_output_tokens,
    )


def _egress_filter_for(
    backend: BackendConfig, provided: EgressFilter | None
) -> EgressFilter | None:
    """Return the egress filter for cloud backends, None on-prem."""
    if backend.trust != "cloud":
        return None
    if provided is not None:
        return provided
    return EgressFilter(default_allowed_hosts())


def _check_egress(backend: BackendConfig, egress: EgressFilter | None) -> None:
    """Raise :class:`EgressBlocked` unless the chat URL may be sent."""
    if egress is None:
        return
    chat_url = f"{backend.base_url.rstrip('/')}/chat/completions"
    egress.check_url(chat_url)


def _quarantine_side_effects(
    database_url: str,
    incident_id: int | None,
    *,
    call_id: str,
    model: str,
    purpose: str,
    errors: list[StructuredError],
) -> None:
    """Insert the security event and escalate the incident for review."""
    detail = {
        "call_id": call_id,
        "model": model,
        "purpose": purpose,
        "findings": [error.to_dict() for error in errors],
    }
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO security_events (incident_id, kind, detail) "
                "VALUES (%s, 'injection_echo', %s)",
                (incident_id, json.dumps(detail)),
            )
            if incident_id is not None:
                cur.execute(
                    "UPDATE incidents SET review_required = TRUE, "
                    "updated_at = NOW() WHERE id = %s",
                    (incident_id,),
                )
        conn.commit()


def _escalate_review(database_url: str, incident_id: int | None) -> None:
    """Mark the incident as needing human review (indeterminate)."""
    if incident_id is None:
        return
    with psycopg.connect(database_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET review_required = TRUE, "
                "updated_at = NOW() WHERE id = %s",
                (incident_id,),
            )


def _step_up(reasoning_strength: str) -> str:
    """Return one reasoning step up (low->medium->high, capped)."""
    if reasoning_strength == "low":
        return "medium"
    return "high"


def _correction_message(errors: list[StructuredError]) -> str:
    """Build the delimited retry prompt carrying structured errors."""
    body = json.dumps([error.to_dict() for error in errors])
    return (
        "The previous output failed validation with these structured "
        f"errors:\n---errors\n{body}\n---\n"
        "Return only the corrected JSON object."
    )


def _response_schema_kwargs(
    active_model: type[BaseModel],
) -> dict[str, Any]:
    """Build the response_format kwargs for one attempt, if possible."""
    try:
        schema = active_model.model_json_schema()
    except Exception:
        return {"response_schema_name": active_model.__name__}
    if not isinstance(schema, dict):
        return {"response_schema_name": active_model.__name__}
    return {
        "response_schema_name": active_model.__name__,
        "response_schema": schema,
    }


@dataclass
class _LoopResult:
    """Bookkeeping for one backend's attempt loop."""

    resolved_value: Any = None
    resolved_model: str | None = None
    quarantined: bool = False
    quarantine_errors: list[StructuredError] = field(default_factory=list)
    last_errors: list[StructuredError] = field(default_factory=list)
    last_validator: str | None = None
    recorded: int = 0
    tries: int = 0
    fatal_code: str | None = None
    fatal_errors: list[StructuredError] = field(default_factory=list)
    #: True when a mid-loop reserve refusal stopped the loop: the
    #: recorded attempts stand and the outcome is ai_failed, never
    #: pending_ai and never indeterminate.
    budget_stopped: bool = False
    #: First-error code per recorded attempt, in order.
    error_codes: list[str] = field(default_factory=list)
    #: Failed validator per recorded attempt, in order.
    validators: list[str] = field(default_factory=list)


def _budget_error() -> StructuredError:
    """Structured error for a reserve refusal (spend cap crossed)."""
    return _err(
        "budget_exceeded",
        "",
        "spend cap would be crossed; no further model contact on this backend",
    )


def _logged_release(reservation_id: int, call_id: str, database_url: str) -> None:
    """Release one hold, logging (never raising) when the release fails.

    Only the call id, the reservation id and the exception type are
    logged — never secrets. The hold TTL stays the documented
    fallback that frees a hold whose release is lost.
    """
    try:
        release_reservation(reservation_id, database_url)
    except Exception as exc:
        _log.warning(
            "call %s: failed to release reservation %s: %s",
            call_id,
            reservation_id,
            type(exc).__name__,
        )


def _coerce_messages(
    raw: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    """Validate builder output shape; raise ValueError when malformed."""
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)) or not raw:
        raise ValueError("messages_builder must return a non-empty sequence")
    coerced: list[dict[str, str]] = []
    for position, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"messages[{position}] must be a mapping")
        role = item.get("role")
        content = item.get("content")
        if role not in ("system", "user", "assistant", "tool"):
            raise ValueError(f"messages[{position}].role must be a known role")
        if not isinstance(content, str):
            raise ValueError(f"messages[{position}].content must be a string")
        coerced.append({"role": str(role), "content": content})
    return coerced


def _record_one(
    *,
    call_id: str,
    attempt_number: int,
    backend: BackendConfig,
    purpose: str,
    context: CallContext,
    attempt: Attempt,
    failed_validator: str | None,
    errors: list[StructuredError],
    outcome: str,
    reservation_id: int | None,
    database_url: str,
    prices: Mapping[str, ModelPrice],
) -> None:
    """Record one attempt; release the hold when the write itself fails."""
    billed = backend.trust == "cloud"
    reasoning = attempt.reasoning if backend.trust == "onprem" else None
    try:
        record_attempt(
            call_id=call_id,
            incident_id=context.incident_id,
            model=backend.model,
            purpose=purpose,
            attempt_number=attempt_number,
            failed_validator=failed_validator,
            errors=[error.to_dict() for error in errors],
            prompt_tokens=attempt.prompt_tokens,
            cached_tokens=attempt.cached_tokens,
            reasoning_tokens=attempt.reasoning_tokens,
            answer_tokens=attempt.answer_tokens,
            overhead_tokens=attempt.overhead_tokens,
            token_source=attempt.token_source,
            latency_ms=attempt.latency_ms,
            outcome=outcome,
            reasoning=reasoning,
            billed=billed,
            reservation_id=reservation_id,
            database_url=database_url,
            prices=prices,
        )
    except Exception:
        if reservation_id is not None:
            _logged_release(reservation_id, call_id, database_url)
        raise


#: Fraction of the evidence budget kept when a context-overflow 400
#: forces one reselection before the next try.
_OVERFLOW_SHRINK_FACTOR = 0.75

#: Case-insensitive markers identifying a context-length refusal in a
#: provider error message. Kept tight: only phrasings about context
#: or token capacity, so ordinary 400s stay generic transport errors.
_OVERFLOW_MARKERS = (
    "maximum context length",
    "context length",
    "context window",
    "too many tokens",
    "token limit",
    "input tokens exceed",
    "prompt is too long",
    "maximum tokens",
)


def _is_context_overflow(error: AttemptError | None) -> bool:
    """True for an HTTP 400 whose message reports context exhaustion."""
    if error is None or error.http_status != 400:
        return False
    text = (error.message or "").lower()
    return any(marker in text for marker in _OVERFLOW_MARKERS)


def _run_backend_loop(
    *,
    purpose: str,
    backend: BackendConfig,
    messages_builder: Callable[[Any], Sequence[Mapping[str, str]]],
    response_model: type[BaseModel],
    context: CallContext,
    database_url: str,
    prices: Mapping[str, ModelPrice],
    call_id: str,
    start_attempt_number: int,
    run_attempt_fn: Callable[..., Attempt] | None,
    egress_filter: EgressFilter | None,
    temperature: float,
    reasoning_strength: str,
    cap_usd: float | None,
    reselect_payload: Callable[[float], Any] | None = None,
) -> _LoopResult:
    """Run the 3-try self-correction loop against one backend.

    One hold is reserved per transport try for the worst case of a
    single attempt, so at most one hold is ever live per in-flight
    try. A try that produced no answer object releases its hold
    instead of recording; a recorded try converts its hold (billed)
    or releases it (unbilled) through the id it reserved. The
    ``finally`` clause frees any leftover hold on every exit, so no
    path escapes with a live hold. A context-overflow 400 (see
    :func:`_is_context_overflow`) or a first read timeout shrinks the
    evidence budget once via ``reselect_payload`` (25% off) and
    rebuilds the base messages for the next try; the shrunk attempt
    is recorded with its own error code, and a second identical code
    stops the loop through the same-code early-stop rule. Timeout and
    connection-error codes take part in that early stop like every
    other error: two consecutive identical codes end the backend loop.
    """
    result = _LoopResult()
    worst_single = _worst_case_usd(backend, prices)
    ttl = hold_ttl(backend.read_timeout_seconds, 1)
    billed = backend.trust == "cloud"

    def _try_reserve() -> int | None:
        """Reserve one try's hold, or None when the cap refuses."""
        try:
            return reserve(
                worst_single,
                database_url=database_url,
                cap_usd=cap_usd,
                ttl_seconds=ttl,
            ).id
        except BudgetExceededError:
            return None

    hold = _try_reserve()
    if hold is None:
        result.fatal_code = "budget_exceeded"
        result.fatal_errors = [_budget_error()]
        return result

    def _release() -> None:
        nonlocal hold
        if hold is not None:
            _logged_release(hold, call_id, database_url)
            hold = None

    try:
        try:
            prepared = prepare_payload(
                context.payload,
                backend,
                database_url=database_url,
                entities=context.entities,
            )
        except Exception as exc:
            result.fatal_code = "payload_error"
            result.fatal_errors = [_err("payload_error", "", f"{exc}")]
            return result
        try:
            egress = _egress_filter_for(backend, egress_filter)
        except Exception as exc:
            result.fatal_code = "payload_error"
            result.fatal_errors = [
                _err("payload_error", "egress", f"cannot build egress filter: {exc}")
            ]
            return result
        try:
            _check_egress(backend, egress)
        except EgressBlocked as exc:
            result.fatal_code = "egress_blocked"
            result.fatal_errors = [_err("egress_blocked", "", f"{exc}")]
            return result
        try:
            base_messages = _coerce_messages(messages_builder(prepared.payload))
        except Exception:
            raise
        corrections: list[dict[str, str]] = []
        attempt_number = start_attempt_number
        overflow_shrunk = False
        for index in range(MAX_ATTEMPTS):
            if index > 0:
                hold = _try_reserve()
                if hold is None:
                    result.fatal_code = "budget_exceeded"
                    result.budget_stopped = True
                    result.last_errors = [_budget_error()]
                    result.last_validator = "budget_exceeded"
                    break
            assert hold is not None
            escalated = index == MAX_ATTEMPTS - 1
            active_model = _active_model(response_model, escalated)
            attempt_temperature = 0.0 if escalated else temperature
            attempt_strength = (
                _step_up(reasoning_strength) if escalated else reasoning_strength
            )
            messages: list[dict[str, str]] = list(base_messages) + corrections
            schema_kwargs = _response_schema_kwargs(active_model)
            try:
                if run_attempt_fn is not None:
                    attempt = run_attempt_fn(
                        backend,
                        messages,
                        temperature=attempt_temperature,
                        max_tokens=backend.max_output_tokens,
                        reasoning_strength=attempt_strength,
                        glimmer=(backend.model == "glimmer"),
                        egress_filter=egress,
                        read_timeout=backend.read_timeout_seconds,
                        **schema_kwargs,
                    )
                else:
                    attempt = transport_module.run_attempt(
                        backend,
                        messages,
                        temperature=attempt_temperature,
                        max_tokens=backend.max_output_tokens,
                        reasoning_strength=attempt_strength,
                        glimmer=(backend.model == "glimmer"),
                        egress_filter=egress,
                        read_timeout=backend.read_timeout_seconds,
                        **schema_kwargs,
                    )
            except EgressBlocked as exc:
                _release()
                result.fatal_code = "egress_blocked"
                result.fatal_errors = [_err("egress_blocked", "", f"{exc}")]
                return result
            except (TransportError, LimiterTimeoutError) as exc:
                # A raised transport failure (read timeout, connection
                # error) is recorded like any other try — one row,
                # zero tokens, token_source estimated — so timeouts
                # are visible instead of vanishing. The code comes
                # from the exception type only; no message text and
                # no URLs are stored. Timeout and connection-error
                # codes take part in the same-code early stop like
                # every other error, and a first timeout shrinks the
                # evidence budget once, like the overflow path.
                if isinstance(exc, TimeoutError):
                    exception_code = "timeout"
                else:
                    exception_code = "connection_error"
                raised_errors = [_err(exception_code, "", "transport raised")]
                synthetic = Attempt(
                    http_status=0,
                    content=None,
                    reasoning=None,
                    finish_reason=None,
                    tool_calls=(),
                    tool_call_errors=(),
                    prompt_tokens=0,
                    cached_tokens=0,
                    reasoning_tokens=0,
                    answer_tokens=0,
                    overhead_tokens=0,
                    token_source="estimated",
                    latency_ms=0,
                    error=AttemptError(
                        http_status=0,
                        code=exception_code,
                        message="",
                        error_type=None,
                    ),
                )
                _record_one(
                    call_id=call_id,
                    attempt_number=attempt_number,
                    backend=backend,
                    purpose=purpose,
                    context=context,
                    attempt=synthetic,
                    failed_validator="transport",
                    errors=raised_errors,
                    outcome="transport_error",
                    reservation_id=hold if billed else None,
                    database_url=database_url,
                    prices=prices,
                )
                if not billed:
                    _logged_release(hold, call_id, database_url)
                hold = None
                attempt_number += 1
                result.tries += 1
                result.recorded += 1
                result.last_errors = raised_errors
                result.last_validator = "transport"
                result.error_codes.append(exception_code)
                result.validators.append("transport")
                if len(result.error_codes) >= 2 and (
                    result.error_codes[-1] == result.error_codes[-2]
                ):
                    break
                if (
                    exception_code == "timeout"
                    and not overflow_shrunk
                    and reselect_payload is not None
                ):
                    shrunk_payload = reselect_payload(_OVERFLOW_SHRINK_FACTOR)
                    if shrunk_payload is not None:
                        context.payload = shrunk_payload
                        try:
                            shrunk_prepared = prepare_payload(
                                shrunk_payload,
                                backend,
                                database_url=database_url,
                                entities=context.entities,
                            )
                            base_messages = _coerce_messages(
                                messages_builder(shrunk_prepared.payload)
                            )
                        except Exception as exc:
                            result.fatal_code = "payload_error"
                            result.fatal_errors = [_err("payload_error", "", f"{exc}")]
                            return result
                        corrections = []
                        overflow_shrunk = True
                continue
            result.tries += 1
            if attempt.error is not None:
                overflow = _is_context_overflow(attempt.error)
                error_code = "context_overflow" if overflow else "transport_error"
                transport_errors = [
                    _err(
                        error_code,
                        "",
                        f"backend answered HTTP {attempt.error.http_status}: "
                        f"{attempt.error.message}",
                    )
                ]
                _record_one(
                    call_id=call_id,
                    attempt_number=attempt_number,
                    backend=backend,
                    purpose=purpose,
                    context=context,
                    attempt=attempt,
                    failed_validator="transport",
                    errors=transport_errors,
                    outcome="transport_error",
                    reservation_id=hold if billed else None,
                    database_url=database_url,
                    prices=prices,
                )
                if not billed:
                    _logged_release(hold, call_id, database_url)
                hold = None
                attempt_number += 1
                result.recorded += 1
                result.last_errors = transport_errors
                result.last_validator = "transport"
                result.error_codes.append(error_code)
                result.validators.append("transport")
                if overflow and not overflow_shrunk and reselect_payload is not None:
                    shrunk_payload = reselect_payload(_OVERFLOW_SHRINK_FACTOR)
                    if shrunk_payload is not None:
                        context.payload = shrunk_payload
                        try:
                            shrunk_prepared = prepare_payload(
                                shrunk_payload,
                                backend,
                                database_url=database_url,
                                entities=context.entities,
                            )
                            base_messages = _coerce_messages(
                                messages_builder(shrunk_prepared.payload)
                            )
                        except Exception as exc:
                            result.fatal_code = "payload_error"
                            result.fatal_errors = [_err("payload_error", "", f"{exc}")]
                            return result
                        corrections = []
                        overflow_shrunk = True
                        continue
                corrections = [
                    {"role": "assistant", "content": attempt.content or ""},
                    {
                        "role": "user",
                        "content": _correction_message(transport_errors),
                    },
                ]
            else:
                parsed, syntax_errors = validate_syntax(
                    attempt.content, attempt.finish_reason
                )
                failed_validator: str | None = None
                errors: list[StructuredError] = []
                value: BaseModel | None = None
                if syntax_errors:
                    failed_validator = "syntax"
                    errors = syntax_errors
                else:
                    assert parsed is not None
                    value, schema_errors = validate_schema(parsed, active_model)
                    if schema_errors:
                        failed_validator = "schema"
                        errors = schema_errors
                    else:
                        semantics_errors = validate_semantics(
                            parsed,
                            context,
                            database_url,
                            response_model=active_model,
                        )
                        if semantics_errors:
                            failed_validator = "semantics"
                            errors = semantics_errors
                        else:
                            policy_errors = validate_policy(parsed, context)
                            if policy_errors:
                                failed_validator = "policy"
                                errors = policy_errors
                            else:
                                security_errors = validate_security(parsed, context)
                                if security_errors:
                                    _record_one(
                                        call_id=call_id,
                                        attempt_number=attempt_number,
                                        backend=backend,
                                        purpose=purpose,
                                        context=context,
                                        attempt=attempt,
                                        failed_validator=("security_injection_echo"),
                                        errors=security_errors,
                                        outcome="quarantined",
                                        reservation_id=(hold if billed else None),
                                        database_url=database_url,
                                        prices=prices,
                                    )
                                    if not billed:
                                        _logged_release(hold, call_id, database_url)
                                    hold = None
                                    result.recorded += 1
                                    _quarantine_side_effects(
                                        database_url,
                                        context.incident_id,
                                        call_id=call_id,
                                        model=backend.model,
                                        purpose=purpose,
                                        errors=security_errors,
                                    )
                                    result.quarantined = True
                                    result.quarantine_errors = security_errors
                                    result.last_errors = security_errors
                                    result.last_validator = "security_injection_echo"
                                    return result
                if failed_validator is None:
                    assert value is not None
                    _record_one(
                        call_id=call_id,
                        attempt_number=attempt_number,
                        backend=backend,
                        purpose=purpose,
                        context=context,
                        attempt=attempt,
                        failed_validator=None,
                        errors=[],
                        outcome="ok",
                        reservation_id=hold if billed else None,
                        database_url=database_url,
                        prices=prices,
                    )
                    if not billed:
                        _logged_release(hold, call_id, database_url)
                    hold = None
                    result.recorded += 1
                    result.resolved_value = value
                    result.resolved_model = backend.model
                    result.last_errors = []
                    result.last_validator = None
                    return result
                _record_one(
                    call_id=call_id,
                    attempt_number=attempt_number,
                    backend=backend,
                    purpose=purpose,
                    context=context,
                    attempt=attempt,
                    failed_validator=failed_validator,
                    errors=errors,
                    outcome="invalid",
                    reservation_id=hold if billed else None,
                    database_url=database_url,
                    prices=prices,
                )
                if not billed:
                    _logged_release(hold, call_id, database_url)
                hold = None
                attempt_number += 1
                result.recorded += 1
                result.last_errors = errors
                result.last_validator = failed_validator
                result.error_codes.append(errors[0].code if errors else "")
                assert failed_validator is not None
                result.validators.append(failed_validator)
                corrections = [
                    {"role": "assistant", "content": attempt.content or ""},
                    {"role": "user", "content": _correction_message(errors)},
                ]
            if len(result.error_codes) >= 2 and (
                result.error_codes[-1] == result.error_codes[-2]
            ):
                break
    finally:
        _release()
    return result


def _fallback_backend(
    purpose: str,
    primary: BackendConfig,
    fallback_override: BackendConfig | None | str,
    primary_overridden: bool,
) -> BackendConfig | None:
    """Return the fallback backend for the routing profile, if any.

    ``hybrid`` falls back to the other purpose's serving backend;
    ``all-local`` / ``all-cloud`` serve both purposes from one
    backend, so there is no second backend to try. An explicitly
    injected primary (tests) disables auto-fallback.
    """
    if isinstance(fallback_override, BackendConfig):
        return fallback_override
    if fallback_override is None:
        return None
    if primary_overridden:
        return None
    try:
        from corvus.settings import get_settings

        profile = get_settings().model_profile
    except Exception:
        return None
    if profile != "hybrid":
        return None
    other = "analysis" if purpose == "triage" else "triage"
    try:
        candidate = get_backend(other)
    except Exception:
        return None
    if candidate.model == primary.model and candidate.base_url == primary.base_url:
        return None
    return candidate


def call_model(
    purpose: str,
    messages_builder: Callable[[Any], Sequence[Mapping[str, str]]],
    response_model: type[BaseModel],
    context: CallContext,
    *,
    database_url: str | None = None,
    prices: Mapping[str, ModelPrice] | None = None,
    run_attempt_fn: Callable[..., Attempt] | None = None,
    backend_override: BackendConfig | None = None,
    fallback_backend_override: BackendConfig | None | str = "auto",
    egress_filter: EgressFilter | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    reasoning_strength: str = DEFAULT_REASONING_STRENGTH,
    cap_usd: float | None = None,
    call_id: str | None = None,
    reselect_payload: Callable[[float], Any] | None = None,
) -> CallOutcome:
    """Run one validated model call for ``purpose`` and return its outcome.

    ``messages_builder`` maps the prepared payload to the chat
    messages; ``response_model`` is the pydantic schema every
    answer must validate against; ``context`` carries the incident
    evidence keys, floor, language, dictionary, signals and the
    deterministic fallback value. ``reselect_payload``, when given,
    rebuilds a smaller raw payload from a shrink factor after a
    context-overflow 400, once per backend loop. Test seams
    (``run_attempt_fn``, ``backend_override``, ``prices``,
    ``cap_usd``, ``egress_filter``) are keyword-only and default to
    production wiring; the stub-transport tests drive them with no
    network.
    """
    if purpose not in ("triage", "analysis"):
        raise ValueError(
            f"unknown LLM purpose {purpose!r}; expected 'triage' or 'analysis'"
        )
    if not callable(messages_builder):
        raise ValueError("messages_builder must be callable")
    if not (isinstance(response_model, type) and issubclass(response_model, BaseModel)):
        raise TypeError("response_model must be a pydantic BaseModel subclass")
    if _normalize_language(context.language) is None:
        raise ValueError(f"context language {context.language!r} is not en or es")
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
        raise ValueError(f"temperature must be a number, got {temperature!r}")
    if reasoning_strength not in REASONING_ORDER:
        raise ValueError(
            f"reasoning_strength must be one of {REASONING_ORDER}, "
            f"got {reasoning_strength!r}"
        )
    db_url = _resolve_database_url(database_url or context.database_url)
    if context.incident_id is not None:
        stored = signals_for_incident(db_url, context.incident_id)
        if stored and not context.injection_signals:
            raise ValueError(
                f"incident {context.incident_id}: {len(stored)} stored injection "
                "signal(s) but context carries none; re-run detect and pass "
                "injection_signals and payload_texts"
            )
    if context.valid_techniques is None and context.attack_dictionary is None:
        _resolve_attack(context)
    price_map = prices if prices is not None else load_price_book()
    primary = backend_override if backend_override is not None else get_backend(purpose)
    active_call_id = call_id or uuid.uuid4().hex
    first = _run_backend_loop(
        purpose=purpose,
        backend=primary,
        messages_builder=messages_builder,
        response_model=response_model,
        context=context,
        database_url=db_url,
        prices=price_map,
        call_id=active_call_id,
        start_attempt_number=1,
        run_attempt_fn=run_attempt_fn,
        egress_filter=egress_filter,
        temperature=float(temperature),
        reasoning_strength=reasoning_strength,
        cap_usd=cap_usd,
        reselect_payload=reselect_payload,
    )
    if first.resolved_value is not None:
        return CallOutcome(
            status=RESOLVED,
            value=first.resolved_value,
            errors=(),
            attempts=first.recorded,
            needs_human_review=False,
            model=first.resolved_model,
            failed_validator=None,
        )
    if first.quarantined:
        return CallOutcome(
            status=QUARANTINED,
            value=context.deterministic_value,
            errors=tuple(error.to_dict() for error in first.quarantine_errors),
            attempts=first.recorded,
            needs_human_review=True,
            model=primary.model,
            failed_validator="security_injection_echo",
        )
    fallback = _fallback_backend(
        purpose, primary, fallback_backend_override, backend_override is not None
    )
    second: _LoopResult | None = None
    if fallback is not None:
        second = _run_backend_loop(
            purpose=purpose,
            backend=fallback,
            messages_builder=messages_builder,
            response_model=response_model,
            context=context,
            database_url=db_url,
            prices=price_map,
            call_id=active_call_id,
            start_attempt_number=first.recorded + 1,
            run_attempt_fn=run_attempt_fn,
            egress_filter=egress_filter,
            temperature=float(temperature),
            reasoning_strength=reasoning_strength,
            cap_usd=cap_usd,
            reselect_payload=reselect_payload,
        )
        if second.resolved_value is not None:
            return CallOutcome(
                status=RESOLVED,
                value=second.resolved_value,
                errors=(),
                attempts=first.recorded + second.recorded,
                needs_human_review=False,
                model=second.resolved_model,
                failed_validator=None,
            )
        if second.quarantined:
            return CallOutcome(
                status=QUARANTINED,
                value=context.deterministic_value,
                errors=tuple(error.to_dict() for error in second.quarantine_errors),
                attempts=first.recorded + second.recorded,
                needs_human_review=True,
                model=fallback.model,
                failed_validator="security_injection_echo",
            )
    if second is not None:
        recorded_total = first.recorded + second.recorded
        tries_total = first.tries + second.tries
        failed_validators = list(first.validators) + list(second.validators)
        last_errors = second.last_errors or first.last_errors
        last_validator = second.last_validator or first.last_validator
        error_codes = tuple(first.error_codes) + tuple(second.error_codes)
        if last_validator is None:
            last_validator = second.fatal_code or first.fatal_code
    else:
        recorded_total = first.recorded
        tries_total = first.tries
        failed_validators = list(first.validators)
        last_errors = first.last_errors or first.fatal_errors
        last_validator = first.last_validator
        error_codes = tuple(first.error_codes)
        if last_validator is None and first.fatal_code is not None:
            last_validator = first.fatal_code
    both_refused_budget = first.fatal_code == "budget_exceeded" and (
        second is None or second.fatal_code == "budget_exceeded"
    )
    if recorded_total == 0 and tries_total == 0 and both_refused_budget:
        return CallOutcome(
            status=PENDING_AI,
            value=None,
            errors=tuple(error.to_dict() for error in first.fatal_errors),
            attempts=0,
            needs_human_review=False,
            model=primary.model,
            failed_validator="budget_exceeded",
        )
    stopped_for_budget = first.budget_stopped or (
        second is not None and second.budget_stopped
    )
    if (
        recorded_total > 0
        and not stopped_for_budget
        and all(
            validator in EMPTY_INVALID_VALIDATORS for validator in failed_validators
        )
    ):
        _escalate_review(db_url, context.incident_id)
        return CallOutcome(
            status=INDETERMINATE,
            value=None,
            errors=tuple(error.to_dict() for error in last_errors),
            attempts=recorded_total,
            needs_human_review=True,
            model=None,
            failed_validator=last_validator,
            error_codes=error_codes,
        )
    _escalate_review(db_url, context.incident_id)
    return CallOutcome(
        status=AI_FAILED,
        value=context.deterministic_value,
        errors=tuple(error.to_dict() for error in last_errors),
        attempts=recorded_total,
        needs_human_review=True,
        model=None,
        failed_validator=last_validator,
        error_codes=error_codes,
    )


#: Backends this module drives through transport. Anything else
#: importing :func:`corvus.llm.transport.run_attempt` is a layering
#: violation; ``tests/test_llm_call.py`` asserts it.
_MODEL_CALL_ENTRY_POINT = "corvus.llm.call.call_model"
