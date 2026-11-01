"""Sigma (linux/process_creation) -> Wazuh XML for ``local_rules.xml``.

A pure function from a stored rule (Sigma text, native rule id, mode
``shadow`` or ``active``) to the Wazuh rule XML plus a structured
report. Supported subset only; anything else is a typed refusal
(``translation_unsupported`` with the reason, never partial output).

Decisions, each checked against the real data and the decoder files
under ``data/wazuh-ruleset/`` (never from memory):

- ``sudo`` source: decoder ``sudo`` (``program_name ^sudo`` in
  ``0320-sudo_decoders.xml``) decodes the command into the
  ``command`` field (``COMMAND=(\\.+)``); the lab records carry it
  both there and at the top level.
- ``auditd`` source: decoder ``auditd`` (``0040-auditd_decoders.xml``)
  captures ``a0..a7`` quoted only (``a0="(\\S+)"``), so a bare
  hex-encoded argument (auditd hex-encodes any argument holding a
  space or special character, always uppercase) never reaches a
  decoded field — the lab records prove it (``a3=6466202D50`` with
  only ``a0..a2`` decoded). Hex arguments therefore match only
  against ``full_log``, so the auditd rule uses one ``<regex>`` over
  the log with a ``plain|HEX`` alternation per literal. An
  ``EXECVE``/``USER_CMD`` guard keeps file-operation SYSCALL blobs
  (same decoder, no command line) from firing.
- Sibling precedence (verified on the lab manager, Wazuh 4.14.9):
  among sibling rules under one decoder group the FIRST matching
  sibling wins and later siblings are never reached, so chaining
  our rule under only the decoder group root (``5400``/``80700``)
  leaves it dead whenever a stock sibling matches first (a
  sudo-to-root line fires ``5403`` on first sight, ``5402``
  afterwards). Each rule is therefore parented under the decoder
  group root AND every stock sibling that could match one of our
  records first, as a comma ``if_sid`` list: for ``sudo`` every
  child of ``5400`` with a match/regex (``5401``, ``5402``,
  ``5405``, ``5406``, ``5407``, covering success and failure
  outcomes, since Sigma matches ``COMMAND`` regardless of outcome)
  plus the first-time-seen ``5403``; for ``auditd`` every child of
  ``80700`` whose criteria can hit an ``EXECVE``/``USER_CMD``
  record (the ``audit.key`` list children ``80780``, ``80783``,
  ``80786``, ``80789``, ``80792`` — CDB content is unknown
  offline, so they are kept conservatively). Children gated on
  ``audit.type`` values outside our record types (``SYSCALL``,
  ``USER_CMD``) cannot intercept and are dropped — that gate also
  removes the high-level anomaly rules (verified in the shipped
  ``0365`` file). Grandchildren (``5404``, ``80781`` and friends)
  are covered transitively: they can only match after their own
  parent matched. The parent lists are COMPUTED from the shipped
  ruleset files passed to :func:`translate`, never hard-coded; an
  empty list or an id missing from those files is a typed refusal.
- Levels: a matching child REPLACES its parent's alert, so a shadow
  rule below a parent's level would hide an existing alert. Each
  shadow rule therefore sits at the highest level among the parents
  it replaces (never a downgrade; upgrades stay identifiable via
  the ``corvus_shadow`` group), floored at one below the lab
  manager's ``log_alert_level`` of ``3`` so chains under level-0
  noalert parents (``80700`` alone) stay archives-only. Active is
  ``7`` on promotion (operator-tunable; a higher active level
  replaces the parent's alert with its own).
- Case-insensitivity: the Sigma engine compares with ``ILIKE``; the
  emitted PCRE2 opens with ``(?i)`` so both sources match
  case-insensitively, including lowercase hex spellings.
- One ``<field>`` (sudo, on ``command``) or one ``<regex>`` (auditd,
  on the log) carries the WHOLE condition, so no meaning rides on
  how Wazuh combines sibling elements. Both elements use
  ``type="pcre2"`` (lookaheads need it); if the manager rejects the
  type attribute the bundle's configuration test
  (``wazuh-analysisd -t``) fails before anything deploys.
- Group: ``corvus_<sigma id>`` wrapping exactly one rule per source;
  rollback removes the group. Inner rule groups are
  ``corvus_shadow`` / ``corvus_active`` so operators can ``if_group``
  on them.
- Two native ids per stored rule: ``N`` (sudo) and the next free
  id above ``N`` (auditd), skipping every id already present in
  ``local_rules.xml`` or passed in the exclusion list (``100001``
  is taken in this lab, so the first stored rule lands on
  ``100000``/``100002``). Both are range-checked; the anchor ``N``
  itself taken is a refusal.
- ``mitre`` ids come only from ``attack.*`` tags resolving in the
  pinned ATT&CK dictionary; anything else is dropped, never guessed.

Safety: literals are refused on control characters, NUL, newlines,
``"]>"``, past a documented length, or past a documented pattern
cost; ``|re`` is always refused (a user-controlled regex is never
emitted). Title/description pass the same screen and are XML-escaped
on output. The output is re-parsed with the standard library parser
before it is returned.
"""

from __future__ import annotations

import re
import uuid as uuid_module
import xml.etree.ElementTree as ET
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from corvus.learning.rules import NATIVE_ID_MAX, NATIVE_ID_MIN

__all__ = [
    "ACTIVE_LEVEL",
    "GROUP_PREFIX",
    "LOG_ALERT_LEVEL",
    "MAX_LITERAL_LEN",
    "MAX_PATTERN_CHARS",
    "MIN_LITERAL_LEN",
    "SHADOW_LEVEL",
    "TranslationReport",
    "derive_parents",
    "local_rules_ids",
    "parse_ruleset",
    "shipped_ruleset_paths",
    "translate",
]

#: The lab manager's ``log_alert_level``: alerts need this level.
LOG_ALERT_LEVEL = 3

#: Shadow floor: one below the alert threshold, so chains under
#: level-0 noalert parents stay archives-only.
SHADOW_LEVEL = LOG_ALERT_LEVEL - 1

#: Active rules alert on promotion (operator-tunable; documented in
#: the deploy plan).
ACTIVE_LEVEL = 7

#: Group-name prefix; the Sigma id follows verbatim for grep-ability.
GROUP_PREFIX = "corvus_"

#: A single literal longer than this is refused (hex doubles it).
MAX_LITERAL_LEN = 256

#: The two emitted patterns together past this are refused.
MAX_PATTERN_CHARS = 4000

#: Effective (non-wildcard) literal characters needed, mirroring the
#: backtest floor so a translator-only check agrees with it.
MIN_LITERAL_LEN = 4

#: Sigma fields the translator can express.
_SUPPORTED_FIELDS = frozenset({"CommandLine", "Image"})

#: Modifier class names the translator can express (plus the ``all``
#: linker, which only changes value combination, never matching).
_MOD_CONTAINS = "SigmaContainsModifier"
_MOD_STARTS = "SigmaStartswithModifier"
_MOD_ENDS = "SigmaEndswithModifier"
_MOD_ALL = "SigmaAllModifier"
_MOD_REGEX = "SigmaRegularExpressionModifier"
_ALLOWED_MODIFIERS = frozenset({_MOD_CONTAINS, _MOD_STARTS, _MOD_ENDS, _MOD_ALL})

#: Control characters refused in literals, titles and descriptions
#: (NUL and newlines can never appear in a Wazuh rule safely).
_CONTROL_CHARS = frozenset("\x00\n\r")


@dataclass(frozen=True)
class TranslationReport:
    """The outcome of :func:`translate` (always well-formed)."""

    ok: bool
    code: str
    reason: str
    xml: str | None = None
    sigma_rule_id: str | None = None
    native_rule_ids: tuple[int, int] | None = None
    mode: str | None = None
    group: str | None = None
    level: int | None = None
    mitre_ids: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)


def _refuse(code: str, reason: str) -> TranslationReport:
    """Build a refusal (never partial output: ``xml`` stays None)."""
    return TranslationReport(ok=False, code=code, reason=reason)


class _Unsupported(Exception):
    """Internal: the rule leaves the supported subset (reason carried)."""


def _parse_rules_xml(path: str | Path) -> Any:
    """Parse one Wazuh rules file, fragment or document.

    Shipped ruleset files (``0020``/``0365``) are fragments with
    several top-level groups, which the stock parser rejects, so
    every file is wrapped in a synthetic root first (a no-op for
    single-root files like ``local_rules.xml``).
    """
    text = Path(path).read_text(encoding="utf-8")
    text = re.sub(r"<\?xml[^?]*\?>\s*", "", text, count=1)
    try:
        return ET.fromstring(f"<corvus_ruleset_root>{text}</corvus_ruleset_root>")
    except ET.ParseError as exc:
        raise ValueError(f"ruleset file {path} does not parse: {exc}") from None


def local_rules_ids(ruleset_path: str | Path) -> set[int]:
    """Return every numeric rule ``id`` in a Wazuh rules XML file.

    Raises ``OSError`` when the file cannot be read and
    ``ValueError`` when it does not parse: callers fail closed.
    """
    try:
        root = _parse_rules_xml(ruleset_path)
    except OSError:
        raise
    found: set[int] = set()
    for rule in root.iter("rule"):
        raw = (rule.get("id") or "").strip()
        if raw.isdigit():
            found.add(int(raw))
    if not found:
        raise ValueError(f"no rule ids parsed from {ruleset_path}")
    return found


def shipped_ruleset_paths(ruleset_dir: str | Path) -> list[str]:
    """List the shipped Wazuh RULES files in a directory.

    Every ``*_rules.xml`` file except ``local_rules.xml`` (decoder
    files such as ``0320-sudo_decoders.xml`` are not rules and the
    deploy target's example rule must not pollute the derivation).
    Raises ``OSError`` when the directory cannot be read.
    """
    found = sorted(
        str(path)
        for path in Path(ruleset_dir).glob("*_rules.xml")
        if path.name != "local_rules.xml"
    )
    if not found:
        raise ValueError(f"no shipped ruleset files in {ruleset_dir}")
    return found


@dataclass(frozen=True)
class _ShippedRule:
    """One parsed stock rule: identity, level, chain and criteria."""

    rule_id: int
    level: int
    decoded_as: tuple[str, ...]
    if_sids: tuple[int, ...]
    has_match: bool
    has_regex: bool
    has_list: bool
    has_field: bool
    has_if_fts: bool
    type_scope: tuple[str, ...]


def _if_sid_list(element: Any) -> list[int]:
    """Split ``if_sid`` elements (comma lists) into rule ids."""
    found: list[int] = []
    for child in element.findall("if_sid"):
        for part in (child.text or "").split(","):
            part = part.strip()
            if part.isdigit():
                found.append(int(part))
    return found


def parse_ruleset(paths: Sequence[str | Path]) -> dict[int, _ShippedRule]:
    """Parse shipped ruleset files into rules keyed by id.

    Raises ``ValueError`` naming the file when one does not parse;
    rules without an integer id or level are skipped (they can
    never parent or shadow ours).
    """
    rules: dict[int, _ShippedRule] = {}
    for path in paths:
        try:
            root = _parse_rules_xml(path)
        except OSError as exc:
            raise ValueError(f"cannot read ruleset file {path}: {exc}") from None
        for element in root.iter("rule"):
            raw_id = (element.get("id") or "").strip()
            raw_level = (element.get("level") or "").strip()
            if not raw_id.isdigit() or not raw_level.isdigit():
                continue
            decoded = tuple(
                (child.text or "").strip()
                for child in element.findall("decoded_as")
                if (child.text or "").strip()
            )
            fields: dict[str, list[str]] = {}
            for child in element.findall("field"):
                name = (child.get("name") or "").strip()
                fields.setdefault(name, []).extend(
                    part.strip()
                    for part in (child.text or "").split("|")
                    if part.strip()
                )
            rules[int(raw_id)] = _ShippedRule(
                rule_id=int(raw_id),
                level=int(raw_level),
                decoded_as=decoded,
                if_sids=tuple(_if_sid_list(element)),
                has_match=any(
                    (child.text or "").strip() for child in element.findall("match")
                ),
                has_regex=any(
                    (child.text or "").strip() for child in element.findall("regex")
                ),
                has_list=len(element.findall("list")) > 0,
                has_field=len(fields) > 0,
                has_if_fts=len(element.findall("if_fts")) > 0,
                type_scope=tuple(fields.get("audit.type", ())),
            )
    if not rules:
        raise ValueError("no rules parsed from the passed ruleset files")
    return rules


#: Decoder per supported source (the ``decoded_as`` group to chain under).
_SOURCE_DECODERS = {"sudo": "sudo", "auditd": "auditd"}

#: Record types our events carry per source (Sigma-visible kinds only;
#: standalone companions are unmapped and carry no Sigma verdict).
_SOURCE_RECORD_TYPES = {
    "sudo": frozenset({"SUDO"}),
    "auditd": frozenset({"SYSCALL", "USER_CMD"}),
}


def derive_parents(source: str, rules: Mapping[int, _ShippedRule]) -> list[int]:
    """Compute the ``if_sid`` parent chain for one source.

    The decoder group root first, then every direct child (``if_sid``
    naming the root, shipped-file order) whose criteria could match
    one of our records ahead of ours — first matching sibling wins,
    so each of them must parent us or we are never reached. A child
    gated on ``audit.type`` values outside our record types cannot
    intercept and is dropped. Grandchildren are covered transitively
    (they match only after their own parent matched). Raises
    ``_Unsupported`` when no decoder group exists (empty parent list
    is a refusal, never a bare root guess).
    """
    if source not in _SOURCE_DECODERS:
        raise _Unsupported(f"source {source!r} has no decoder mapping")
    decoder = _SOURCE_DECODERS[source]
    roots = [rule.rule_id for rule in rules.values() if decoder in rule.decoded_as]
    if not roots:
        raise _Unsupported(f"no decoder group for {decoder!r} in the passed ruleset")
    root = roots[0]
    wanted = _SOURCE_RECORD_TYPES[source]
    parents = [root]
    for rule in rules.values():
        if root not in rule.if_sids or rule.rule_id == root:
            continue
        if rule.type_scope and wanted.isdisjoint(rule.type_scope):
            continue
        parents.append(rule.rule_id)
    return parents


def _check_text(value: str, what: str) -> None:
    """Refuse control characters in a literal, title or description."""
    for char in value:
        if char in _CONTROL_CHARS or (ord(char) < 32 and char not in ("\t",)):
            raise _Unsupported(f"{what} holds a control character")
        if ord(char) == 127:
            raise _Unsupported(f"{what} holds a control character")
    if "]]>" in value:
        raise _Unsupported(f"{what} holds ']]>'")


def _sigma_parts(value: Any) -> list[tuple[str, str]] | None:
    """Split a Sigma value into literal/wildcard parts.

    Returns ``[("lit", text), ("multi", ""), ("single", ""), ...]``,
    or None when the value is not a plain string (numbers, CIDR and
    regex objects have no literal form here).
    """
    from sigma.types import SigmaString, SpecialChars

    if not isinstance(value, SigmaString):
        return None
    parts: list[tuple[str, str]] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(("multi", ""))
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(("single", ""))
        elif isinstance(part, str):
            parts.append(("lit", part))
        else:
            return None
    return parts


def _literal_len(parts: Sequence[tuple[str, str]]) -> int:
    """Count effective (non-wildcard) characters."""
    return sum(len(text) for kind, text in parts if kind == "lit")


def _wildcard_regex(
    parts: Sequence[tuple[str, str]],
    *,
    strip_leading_multi: bool = False,
    strip_trailing_multi: bool = False,
) -> str:
    """Render parts as PCRE2 (``*`` -> ``.*``, ``?`` -> ``.``)."""
    tokens: list[str] = []
    for kind, text in parts:
        if kind == "lit":
            tokens.append(re.escape(text))
        elif kind == "multi":
            tokens.append(".*")
        else:
            tokens.append(".")
    if strip_leading_multi and tokens[:1] == [".*"]:
        tokens.pop(0)
    if strip_trailing_multi and tokens[-1:] == [".*"]:
        tokens.pop()
    return "".join(tokens)


def _hex_alternative(parts: Sequence[tuple[str, str]]) -> str:
    """Render the auditd hex form of a CommandLine value.

    Maximal literal runs become uppercase hex (the form auditd
    emits); ``?`` is one byte and ``*`` is any run of bytes, both
    kept inside the hex alphabet so the gap cannot swallow the
    closing quote of a neighbouring field.
    """
    run: list[str] = []
    chunks: list[str] = []

    def flush() -> None:
        if run:
            chunks.append("".join(run).encode("utf-8").hex().upper())
            run.clear()

    for kind, text in parts:
        if kind == "lit":
            run.append(text)
        else:
            flush()
            chunks.append("[0-9A-Fa-f]{2}" if kind == "single" else "[0-9A-Fa-f]*")
    flush()
    return "".join(chunks)


@dataclass(frozen=True)
class _Atom:
    """One field predicate: ``field`` with a modifier kind and parts."""

    field: str
    kind: str  # contains | startswith | endswith | equals
    parts: tuple[tuple[str, str], ...]


def _atom_of(field_name: str, modifiers: Collection[str], value: Any) -> _Atom:
    """Build one atom; raise ``_Unsupported`` outside the subset."""
    if field_name not in _SUPPORTED_FIELDS:
        raise _Unsupported(f"field {field_name!r} has no Wazuh match surface")
    names = set(modifiers)
    if _MOD_REGEX in names:
        raise _Unsupported("the |re modifier is refused (never emit a regex)")
    unknown = names - _ALLOWED_MODIFIERS
    if unknown:
        raise _Unsupported(
            f"modifier {sorted(unknown)[0]!r} on {field_name!r} is not supported"
        )
    if _MOD_CONTAINS in names:
        kind = "contains"
    elif _MOD_STARTS in names:
        kind = "startswith"
    elif _MOD_ENDS in names:
        kind = "endswith"
    else:
        kind = "equals"
    parts = _sigma_parts(value)
    if parts is None:
        raise _Unsupported(f"{field_name!r} value is not a plain string")
    for part_kind, text in parts:
        if part_kind == "lit":
            _check_text(text, f"{field_name!r} literal")
    effective = _literal_len(parts)
    if effective < MIN_LITERAL_LEN:
        raise _Unsupported(
            f"{field_name!r} literal is shorter than {MIN_LITERAL_LEN} characters"
        )
    if effective > MAX_LITERAL_LEN:
        raise _Unsupported(
            f"{field_name!r} literal is longer than {MAX_LITERAL_LEN} characters"
        )
    return _Atom(field=field_name, kind=kind, parts=tuple(parts))


def _selection_formula(name: str, detection: Any) -> Any:
    """Reduce one named selection to ``("and"|"or", [...])`` over atoms."""
    from sigma.conditions import ConditionAND

    item_groups: list[Any] = []
    negations = 0
    for item in detection.detection_items:
        nested = getattr(item, "detection_items", None)
        if nested:
            raise _Unsupported(f"selection {name!r} nests selections")
        if item.field is None:
            raise _Unsupported(f"selection {name!r} has a fieldless keyword")
        modifiers = [
            mod.__name__ if isinstance(mod, type) else type(mod).__name__
            for mod in item.modifiers or []
        ]
        values = item.value if isinstance(item.value, list) else [item.value]
        atoms: list[Any] = []
        for value in values:
            atoms.append(("atom", _atom_of(str(item.field), modifiers, value)))
        linker = (
            "and"
            if item.value_linking is ConditionAND or _MOD_ALL in modifiers
            else "or"
        )
        group: Any = atoms[0] if len(atoms) == 1 else (linker, atoms)
        if bool(getattr(item, "negated", False)):
            negations += 1
            group = ("not", group)
        item_groups.append(group)
    linking = "and" if detection.item_linking is ConditionAND else "or"
    formula: Any = item_groups[0] if len(item_groups) == 1 else (linking, item_groups)
    return formula, negations


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)\s*")


def _tokenize_condition(text: str) -> list[str]:
    """Split a Sigma condition into identifiers, parens and keywords."""
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _TOKEN.match(text, pos)
        if match is None or match.start() == match.end():
            raise _Unsupported(
                f"condition has an unsupported token near {text[pos:]!r}"
            )
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


def _parse_condition(tokens: list[str]) -> Any:
    """Parse ``or > and > not`` over identifiers; count the NOTs."""

    def parse_or(pos: int) -> tuple[Any, int]:
        node, pos = parse_and(pos)
        children = [node]
        while pos < len(tokens) and tokens[pos].lower() == "or":
            sibling, pos = parse_and(pos + 1)
            children.append(sibling)
        return (children[0] if len(children) == 1 else ("or", children), pos)

    def parse_and(pos: int) -> tuple[Any, int]:
        node, pos = parse_not(pos)
        children = [node]
        while pos < len(tokens) and tokens[pos].lower() == "and":
            sibling, pos = parse_not(pos + 1)
            children.append(sibling)
        return (children[0] if len(children) == 1 else ("and", children), pos)

    def parse_not(pos: int) -> tuple[Any, int]:
        if pos < len(tokens) and tokens[pos].lower() == "not":
            child, pos = parse_not(pos + 1)
            return ("not", child), pos
        return parse_primary(pos)

    def parse_primary(pos: int) -> tuple[Any, int]:
        if pos >= len(tokens):
            raise _Unsupported("condition ends unexpectedly")
        token = tokens[pos]
        if token == "(":
            node, pos = parse_or(pos + 1)
            if pos >= len(tokens) or tokens[pos] != ")":
                raise _Unsupported("condition has an unbalanced parenthesis")
            return node, pos + 1
        lowered = token.lower()
        if lowered in ("and", "or", "not", "of", "by", "near"):
            raise _Unsupported(f"condition keyword {token!r} is not supported here")
        if token in ("(", ")"):
            raise _Unsupported("condition has an unbalanced parenthesis")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            raise _Unsupported(f"condition has an unsupported token {token!r}")
        return ("sel", token), pos + 1

    node, pos = parse_or(0)
    if pos != len(tokens):
        raise _Unsupported("condition has trailing tokens")
    return node


def _count_nots(node: Any) -> int:
    """Count ``not`` nodes in a parsed condition."""
    if not isinstance(node, tuple):
        return 0
    if node[0] == "not":
        return 1 + _count_nots(node[1])
    if node[0] in ("and", "or"):
        return sum(_count_nots(child) for child in node[1])
    return 0


def _sudo_atom(atom: _Atom) -> str:
    """Render one atom as PCRE2 over the sudo ``command`` string."""
    parts = list(atom.parts)
    if atom.field == "Image":
        # The image is the first whitespace-delimited token.
        if atom.kind == "contains":
            core = _wildcard_regex(
                parts, strip_leading_multi=True, strip_trailing_multi=True
            )
            return f"(?:^[^\\s]*{core})"
        if atom.kind == "startswith":
            core = _wildcard_regex(parts, strip_trailing_multi=True)
            return f"(?:^{core}[^\\s]*)"
        if atom.kind == "endswith":
            core = _wildcard_regex(parts, strip_leading_multi=True)
            return f"(?:^[^\\s]*{core}(?=\\s|$))"
        full = _wildcard_regex(parts)
        return f"(?:^{full}(?=\\s|$))"
    if atom.kind == "contains":
        return f"(?:{_wildcard_regex(parts)})"
    if atom.kind == "startswith":
        return f"(?:^{_wildcard_regex(parts, strip_trailing_multi=True)})"
    if atom.kind == "endswith":
        return f"(?:{_wildcard_regex(parts, strip_leading_multi=True)}$)"
    return f"(?:^{_wildcard_regex(parts)}$)"


def _audit_atom(atom: _Atom) -> str:
    """Render one atom as PCRE2 over the auditd ``full_log`` blob."""
    parts = list(atom.parts)
    if atom.field == "Image":
        # The image is the decoded ``exe`` (never hex-encoded).
        if atom.kind == "contains":
            core = _wildcard_regex(
                parts, strip_leading_multi=True, strip_trailing_multi=True
            )
            return f'(?:exe="[^"]*{core}[^"]*")'
        if atom.kind == "startswith":
            core = _wildcard_regex(parts, strip_trailing_multi=True)
            return f'(?:exe="{core}[^"]*")'
        if atom.kind == "endswith":
            core = _wildcard_regex(parts, strip_leading_multi=True)
            return f'(?:exe="[^"]*{core}")'
        return f'(?:exe="{_wildcard_regex(parts)}")'
    # CommandLine: the argv live quoted or hex-encoded in EXECVE, or
    # hex-only in USER_CMD/proctitle, so every literal matches both.
    if atom.kind != "contains":
        raise _Unsupported(
            f"CommandLine|{atom.kind} has no full_log form on auditd "
            "(only contains is expressible there)"
        )
    plain = _wildcard_regex(parts)
    hexed = _hex_alternative(parts)
    return f"(?:{plain}|{hexed})"


def _render(node: Any, atom_fn: Any) -> str:
    """Render a formula as PCRE2 (AND via lookaheads, OR via ``|``)."""
    if not isinstance(node, tuple):
        raise _Unsupported("condition references an unknown selection")
    kind = node[0]
    if kind == "atom":
        # Self-searching: the fragment decides anywhere ahead, so a
        # bare atom (top-level or under an OR) still finds a match
        # past leading text its first token cannot consume (hex after
        # non-hex). Anchored (``^``) fragments keep working: the
        # search backtracks to empty at the evaluation point.
        return f"(?:(?=[\\s\\S]*{atom_fn(node[1])})[\\s\\S]*)"
    if kind == "sel":
        raise _Unsupported(f"condition references unknown selection {node[1]!r}")
    if kind == "and":
        # Every positive conjunct searches from the evaluation point
        # on its own: conjoined bare lookaheads would demand all
        # fragments at the same position. A negated conjunct stays
        # pinned (a searching ``not`` would pass from past the
        # forbidden literal). The group consumes the line after
        # checking (a bare lookahead chain would match the empty
        # string and trip the empty-match guard).
        inner = "".join(
            (
                # A negated conjunct renders pinned: its inner
                # fragments search from the evaluation point on
                # their own, so no search prefix is added here.
                _render(child, atom_fn)
                if isinstance(child, tuple) and child[0] == "not"
                else f"(?=[\\s\\S]*{_render(child, atom_fn)})"
            )
            for child in node[1]
        )
        return f"(?:{inner}[\\s\\S]*)"
    if kind == "or":
        return "(?:" + "|".join(_render(child, atom_fn) for child in node[1]) + ")"
    if kind == "not":
        return f"(?!{_render(node[1], atom_fn)})"
    raise _Unsupported("condition shape is not supported")


def _substitute(node: Any, selections: Mapping[str, Any]) -> Any:
    """Replace ``("sel", name)`` leaves with selection formulas."""
    if not isinstance(node, tuple):
        return node
    if node[0] == "sel":
        name = node[1]
        if name not in selections:
            raise _Unsupported(f"condition references unknown selection {name!r}")
        return selections[name]
    if node[0] in ("and", "or"):
        return (node[0], [_substitute(child, selections) for child in node[1]])
    if node[0] == "not":
        return ("not", _substitute(node[1], selections))
    return node


def _formula_literals(node: Any) -> list[str]:
    """Collect maximal literal runs (length >= 4) under a formula.

    Used for baseline screening: a baseline line holding one run
    could plausibly match the rule. Runs below 4 characters are
    dropped (documented recall trade: they match too widely to
    screen on); the capped context sample still covers those
    decoders.
    """
    runs: list[str] = []
    if not isinstance(node, tuple):
        return runs
    if node[0] == "atom":
        current: list[str] = []
        for kind, text in node[1].parts:
            if kind == "lit":
                current.append(text)
                continue
            if len("".join(current)) >= 4:
                runs.append("".join(current))
            current = []
        if len("".join(current)) >= 4:
            runs.append("".join(current))
        return runs
    if node[0] in ("and", "or"):
        for child in node[1]:
            runs.extend(_formula_literals(child))
        return runs
    if node[0] == "not":
        return _formula_literals(node[1])
    return runs


def _mitre_ids(rule: Any, attack: Any | None) -> tuple[str, ...]:
    """Keep ``attack.*`` tags resolving in the pinned dictionary."""
    if attack is None:
        return ()
    kept: list[str] = []
    for tag in rule.tags or []:
        if getattr(tag, "namespace", "") != "attack":
            continue
        raw = str(getattr(tag, "name", "")).lower().replace("_", ".")
        if not re.fullmatch(r"t\d+(\.\d+)?", raw):
            continue
        try:
            entry = attack.resolve(raw)
        except Exception:
            continue
        if entry is not None and str(getattr(entry, "id", "")).upper() not in kept:
            kept.append(str(entry.id).upper())
    return tuple(kept)


def _parse_sigma_rule(sigma_text: str) -> Any:
    """Parse exactly one Sigma rule; raise ``_Unsupported`` otherwise."""
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule

    try:
        collection = SigmaCollection.from_yaml(sigma_text)
    except Exception as exc:
        raise _Unsupported(f"sigma parse error: {exc}") from None
    plain = [
        rule for rule in collection.rules if not isinstance(rule, SigmaCorrelationRule)
    ]
    if len(plain) != 1 or len(collection.rules) != 1:
        raise _Unsupported(f"expected exactly 1 rule, found {len(collection.rules)}")
    return plain[0]


def _build_xml(
    *,
    group_name: str,
    sudo_id: int,
    audit_id: int,
    parents_sudo: Sequence[int],
    parents_audit: Sequence[int],
    level_sudo: int,
    level_audit: int,
    inner_group: str,
    description: str,
    pattern_sudo: str,
    pattern_audit: str,
    mitre_ids: Sequence[str],
) -> str:
    """Assemble the group XML (ElementTree escapes every text node)."""
    group = ET.Element("group", {"name": f"{group_name},"})
    sudo_rule = ET.SubElement(
        group, "rule", {"id": str(sudo_id), "level": str(level_sudo)}
    )
    ET.SubElement(sudo_rule, "if_sid").text = ", ".join(
        str(pid) for pid in parents_sudo
    )
    ET.SubElement(
        sudo_rule, "field", {"name": "command", "type": "pcre2"}
    ).text = pattern_sudo
    ET.SubElement(sudo_rule, "description").text = description
    if mitre_ids:
        mitre = ET.SubElement(sudo_rule, "mitre")
        for mid in mitre_ids:
            ET.SubElement(mitre, "id").text = mid
    ET.SubElement(sudo_rule, "group").text = f"{inner_group},"
    audit_rule = ET.SubElement(
        group, "rule", {"id": str(audit_id), "level": str(level_audit)}
    )
    ET.SubElement(audit_rule, "if_sid").text = ", ".join(
        str(pid) for pid in parents_audit
    )
    ET.SubElement(audit_rule, "regex", {"type": "pcre2"}).text = pattern_audit
    ET.SubElement(audit_rule, "description").text = description
    if mitre_ids:
        mitre = ET.SubElement(audit_rule, "mitre")
        for mid in mitre_ids:
            ET.SubElement(mitre, "id").text = mid
    ET.SubElement(audit_rule, "group").text = f"{inner_group},"
    ET.indent(group)
    return ET.tostring(group, encoding="unicode")


class _UnknownParent(Exception):
    """Internal: the parent chain is empty or names unknown ids."""


def _resolve_parents(
    source: str,
    rules: Mapping[int, _ShippedRule],
    override: Mapping[str, Sequence[int]] | None,
) -> list[int]:
    """Return the validated parent chain for one source.

    An explicit ``override`` list replaces the derivation and every
    id must exist in the passed ruleset files (unknown ids are the
    ``unknown_parent`` refusal); otherwise the chain is derived by
    :func:`derive_parents`. An empty list either way is a refusal.
    """
    if override is not None and source in override:
        wanted = [int(pid) for pid in override[source]]
        if not wanted:
            raise _UnknownParent(f"empty parent list for source {source!r}")
        unknown = [pid for pid in wanted if pid not in rules]
        if unknown:
            raise _UnknownParent(f"parent ids not in the passed ruleset: {unknown}")
        return wanted
    return derive_parents(source, rules)


def translate(
    sigma_text: str,
    native_rule_id: int,
    mode: str,
    *,
    ruleset_paths: Sequence[str | Path],
    exclude_ids: Collection[int] = (),
    attack: Any | None = None,
    parent_ids: Mapping[str, Sequence[int]] | None = None,
) -> TranslationReport:
    """Translate one stored Sigma rule to Wazuh XML; never partially.

    ``native_rule_id`` feeds the sudo rule; the auditd rule takes
    the next free id above it, skipping ``exclude_ids`` (every id
    already taken: local rules plus the store). ``ruleset_paths``
    holds the shipped ruleset files the parent chains are computed
    from (required: without them no chain exists); ``parent_ids``
    optionally pins per-source chains (``{"sudo": [...]}``), each id
    validated against those files. Returns a
    :class:`TranslationReport`: ``ok`` with the XML, or a typed
    refusal (``translation_unsupported``, ``unknown_parent``,
    ``id_collision``, ``id_range``, ``bad_input``) with ``xml``
    None.
    """
    if not isinstance(sigma_text, str) or not sigma_text.strip():
        return _refuse("bad_input", "sigma_text must be a non-empty string")
    if mode not in ("shadow", "active"):
        return _refuse("bad_input", f"mode must be shadow|active, got {mode!r}")
    if isinstance(native_rule_id, bool) or not isinstance(native_rule_id, int):
        return _refuse("bad_input", "native_rule_id must be an integer")
    if not ruleset_paths:
        return _refuse("bad_input", "ruleset_paths must not be empty")
    if parent_ids is not None:
        unknown_sources = sorted(set(parent_ids) - {"sudo", "auditd"})
        if unknown_sources:
            return _refuse(
                "bad_input", f"unknown parent source: {unknown_sources[0]!r}"
            )
    try:
        shipped = parse_ruleset(ruleset_paths)
    except ValueError as exc:
        return _refuse("bad_input", str(exc))
    sudo_id = native_rule_id
    if not (NATIVE_ID_MIN <= sudo_id <= NATIVE_ID_MAX):
        return _refuse(
            "id_range",
            f"native rule id {sudo_id} is outside {NATIVE_ID_MIN}-{NATIVE_ID_MAX}",
        )
    taken = {
        int(item)
        for item in exclude_ids
        if isinstance(item, int) and not isinstance(item, bool)
    }
    if sudo_id in taken:
        return _refuse("id_collision", f"native rule id {sudo_id} is already taken")
    audit_id = sudo_id + 1
    while audit_id in taken:
        audit_id += 1
    if audit_id > NATIVE_ID_MAX:
        return _refuse(
            "id_range",
            f"no free native rule id above {sudo_id} inside "
            f"{NATIVE_ID_MIN}-{NATIVE_ID_MAX}",
        )
    try:
        rule = _parse_sigma_rule(sigma_text)
        logsource = rule.logsource
        if (
            logsource.product != "linux"
            or logsource.category != "process_creation"
            or logsource.service is not None
        ):
            raise _Unsupported(
                "logsource "
                f"{logsource.product}/{logsource.category}/{logsource.service} "
                "is not linux/process_creation"
            )
        selections: dict[str, Any] = {}
        item_negations = 0
        for name, detection in rule.detection.detections.items():
            formula, negations = _selection_formula(str(name), detection)
            selections[str(name)] = formula
            item_negations += negations
        if len(rule.detection.parsed_condition) != 1:
            raise _Unsupported("the rule has more than one condition")
        raw_condition = rule.detection.parsed_condition[0].condition
        if not isinstance(raw_condition, str) or not raw_condition.strip():
            raise _Unsupported("the rule has no condition")
        tree = _parse_condition(_tokenize_condition(raw_condition))
        if _count_nots(tree) + item_negations > 1:
            raise _Unsupported("more than one negation is not supported")
        formula = _substitute(tree, selections)
        # Every pattern decides at string start (``\\A``): nested
        # branches and negations then all evaluate from position 0,
        # so a ``not`` cannot pass by starting its search past the
        # forbidden literal.
        body_sudo = _render(formula, _sudo_atom)
        guard = "(?=[\\s\\S]*type=(?:EXECVE|USER_CMD))"
        body_audit = guard + _render(formula, _audit_atom)
        pattern_sudo = f"(?i)\\A{body_sudo}"
        pattern_audit = f"(?i)\\A{body_audit}"
        if len(pattern_sudo) + len(pattern_audit) > MAX_PATTERN_CHARS:
            raise _Unsupported(
                f"the emitted patterns exceed {MAX_PATTERN_CHARS} characters"
            )
        for label, pattern in (("sudo", pattern_sudo), ("auditd", pattern_audit)):
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise _Unsupported(
                    f"the {label} pattern does not compile: {exc}"
                ) from exc
            if compiled.match("") is not None:
                raise _Unsupported(
                    f"the {label} pattern can match empty (negation-only?)"
                )
        title = str(rule.title or "").strip()
        if not title:
            raise _Unsupported("the rule has no title")
        _check_text(title, "title")
        description_text = str(rule.description or "").strip()
        if description_text:
            _check_text(description_text, "description")
        try:
            uuid_module.UUID(str(rule.id))
        except ValueError:
            raise _Unsupported("the rule id is not a UUID") from None
        mitre = _mitre_ids(rule, attack)
        parents = {
            source: _resolve_parents(source, shipped, parent_ids)
            for source in ("sudo", "auditd")
        }
        parent_levels = {
            pid: shipped[pid].level for chain in parents.values() for pid in chain
        }
        if mode == "shadow":
            # A matching child replaces its parent's alert, so each
            # shadow rule takes the highest replaced level (never a
            # downgrade that would hide an alert), floored below the
            # alert threshold for level-0-only chains.
            levels = {
                source: max(
                    [SHADOW_LEVEL] + [parent_levels[pid] for pid in parents[source]]
                )
                for source in ("sudo", "auditd")
            }
        else:
            levels = {"sudo": ACTIVE_LEVEL, "auditd": ACTIVE_LEVEL}
        level = max(levels.values())
        inner_group = "corvus_shadow" if mode == "shadow" else "corvus_active"
        group_name = f"{GROUP_PREFIX}{rule.id}"
        literals = sorted(set(_formula_literals(formula)))
        literal_hex = sorted({run.encode("utf-8").hex().upper() for run in literals})
        description = f"Corvus {mode} rule {rule.id}: {title}"
        if description_text:
            description += f" -- {description_text}"
        xml = _build_xml(
            group_name=group_name,
            sudo_id=sudo_id,
            audit_id=audit_id,
            parents_sudo=parents["sudo"],
            parents_audit=parents["auditd"],
            level_sudo=levels["sudo"],
            level_audit=levels["auditd"],
            inner_group=inner_group,
            description=description,
            pattern_sudo=pattern_sudo,
            pattern_audit=pattern_audit,
            mitre_ids=mitre,
        )
        parsed = ET.fromstring(xml)
        rules = parsed.findall("rule")
        if len(rules) != 2:
            raise _Unsupported("the output holds no rule per source")
    except _Unsupported as exc:
        return _refuse("translation_unsupported", str(exc))
    except _UnknownParent as exc:
        return _refuse("unknown_parent", str(exc))
    return TranslationReport(
        ok=True,
        code="translated",
        reason=f"one rule per source at levels {levels['sudo']}/{levels['auditd']}",
        xml=xml,
        sigma_rule_id=str(rule.id),
        native_rule_ids=(sudo_id, audit_id),
        mode=mode,
        group=group_name,
        level=level,
        mitre_ids=mitre,
        sources=("sudo", "auditd"),
        detail={
            "pattern_sudo": pattern_sudo,
            "pattern_audit": pattern_audit,
            "parents": {source: list(parents[source]) for source in ("sudo", "auditd")},
            "parent_levels": {
                str(pid): parent_levels[pid] for pid in sorted(parent_levels)
            },
            "levels": dict(levels),
            "literals": literals,
            "literal_hex": literal_hex,
        },
    )
