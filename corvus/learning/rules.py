"""Learned-rule lifecycle over the existing ``rules`` table (0002/0007).

A rule that fails the :mod:`corvus.learning.backtest` verifier cannot
be stored as a candidate: :func:`add_candidate` requires a passing
backtest result for the submitted text. The model's Sigma id is then
ignored: Corvus assigns a fresh uuid4
(:func:`prepare_candidate_text`) and rewrites it into the stored
text, so a model-chosen id can never collide with a shipped or
stored rule and bump the wrong rule's version. The stored copy is
always ``experimental`` (rewritten the same way); deployment
lifecycle lives in the row's ``status`` column (``candidate``,
``shadow``, ``active``, ``rolled_back``, ``archived``), never in the
Sigma text. The backtest level ceiling is enforced again here.
Status moves only through :func:`transition_rule`, which requires a
non-empty approver string and a recorded reason for every move
(``candidate -> shadow -> active``, plus ``rolled_back`` and
``archived``), appended to ``lineage.history``. Storing the same
submission twice yields two rows with distinct Sigma ids (each
version 1); the per-id version counter increments only when the same
Corvus-assigned id is stored again, and the old row is always kept
untouched. ``native_rule_id`` allocates inside 100000-120000 and is
never reused (partial unique index from migration 0007 refuses the
second writer).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import psycopg
import yaml
from psycopg.types.json import Jsonb

__all__ = [
    "NATIVE_ID_MAX",
    "NATIVE_ID_MIN",
    "TRANSITIONS",
    "add_candidate",
    "archive_rule",
    "get_rule",
    "list_rules",
    "prepare_candidate_text",
    "roll_back_rule",
    "transition_rule",
]

#: Native (Wazuh) rule id range for learned rules.
NATIVE_ID_MIN = 100000
NATIVE_ID_MAX = 120000

#: Allowed status moves (every move still needs approver + reason).
TRANSITIONS: dict[str, frozenset[str]] = {
    "candidate": frozenset({"shadow", "archived"}),
    "shadow": frozenset({"active", "rolled_back", "archived"}),
    "active": frozenset({"rolled_back", "archived"}),
    "rolled_back": frozenset({"archived"}),
    "archived": frozenset(),
}

_RULE_COLUMNS = (
    "id, title, sigma_text, native_text, native_rule_id, version, "
    "status, lineage, incident_id, hits, false_positives, created_at, "
    "updated_at, deployed_at"
)


def _row_to_dict(row: Any, columns: list[str]) -> dict[str, Any]:
    """Map a result row to a plain dict (datetimes stay aware)."""
    return dict(zip(columns, row, strict=True))


def _columns() -> list[str]:
    return [name.strip() for name in _RULE_COLUMNS.split(",")]


def _parse_sigma(sigma_text: str) -> Any:
    """Parse exactly one Sigma rule; raise ``ValueError`` otherwise."""
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule

    try:
        collection = SigmaCollection.from_yaml(sigma_text)
    except Exception as exc:
        raise ValueError(f"sigma parse error: {exc}") from None
    plain = [
        rule for rule in collection.rules if not isinstance(rule, SigmaCorrelationRule)
    ]
    if len(plain) != 1 or len(collection.rules) != 1:
        raise ValueError(f"expected exactly 1 rule, found {len(collection.rules)}")
    return plain[0]


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def prepare_candidate_text(sigma_text: str) -> tuple[str, str]:
    """Assign a fresh Corvus Sigma id; return ``(stored_text, sigma_id)``.

    The model's ``id`` is ignored (it may be a fabricated look-alike
    UUID colliding with a shipped or stored rule) and replaced with a
    fresh uuid4, rewritten into the stored text; ``status`` is forced
    to ``experimental`` however the model labelled it. Only those two
    top-level keys change: the rewritten text must describe the same
    detection (compared by parsed structure minus ``id``/``status``),
    otherwise ``ValueError`` is raised and nothing is stored. Raises
    ``ValueError`` for anything that is not exactly one Sigma rule.
    """
    rule = _parse_sigma(sigma_text)
    try:
        doc = yaml.safe_load(sigma_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"sigma YAML does not parse: {exc}") from None
    if not isinstance(doc, Mapping):
        raise ValueError("sigma YAML must be a mapping with one rule")
    before = dict(doc)
    assigned = str(uuid.uuid4())
    stored_doc = dict(before)
    stored_doc["id"] = assigned
    stored_doc["status"] = "experimental"
    try:
        stored_text = yaml.safe_dump(stored_doc, sort_keys=False, allow_unicode=True)
    except yaml.YAMLError as exc:
        raise ValueError(f"sigma YAML does not serialize: {exc}") from None
    rewritten = _parse_sigma(stored_text)
    if str(rewritten.title) != str(rule.title) or str(rewritten.id) != assigned:
        raise ValueError("id/status rewrite changed the rule")
    after = yaml.safe_load(stored_text)
    assert isinstance(after, Mapping)
    stripped_before = {k: v for k, v in before.items() if k not in ("id", "status")}
    stripped_after = {k: v for k, v in after.items() if k not in ("id", "status")}
    if stripped_before != stripped_after:
        raise ValueError("id/status rewrite changed the rule detection")
    return stored_text, assigned


def _allocate_native_id(cur: Any) -> int:
    """Return the next free native id (max + 1 from 100000)."""
    cur.execute(
        "SELECT COALESCE(MAX(native_rule_id), %s) FROM rules",
        (NATIVE_ID_MIN - 1,),
    )
    top = cur.fetchone()[0]  # type: ignore[index]
    candidate = int(top) + 1
    if candidate > NATIVE_ID_MAX:
        raise ValueError("native rule id range 100000-120000 is exhausted")
    return candidate


def add_candidate(
    database_url: str,
    sigma_text: str,
    incident_id: int | None,
    cited_uids: list[str],
    backtest_result: Any,
    producer: str,
    producer_version: str,
    created: datetime | None = None,
    native_rule_id: int | None = None,
    extra_lineage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store a verified candidate rule; return the stored row.

    ``backtest_result`` is the passing verdict for the submitted text
    (a :class:`BacktestResult` or its ``to_dict()`` mapping); any
    other value raises ``ValueError`` and stores nothing. The verdict
    must name the submitted text's own Sigma id, binding it to that
    detection; the stored row then carries a fresh Corvus-assigned
    id and ``experimental`` status text (see
    :func:`prepare_candidate_text`), so the model's id is ignored and
    can never bump another rule's version. The version increments per
    stored Sigma id while older rows are kept. ``native_rule_id`` is
    allocated automatically unless the caller passes one explicitly
    (out-of-range values raise; collisions raise the database's
    unique violation, so a racer never overwrites). ``extra_lineage``
    merges additional keys into the stored lineage (the proposal
    loop records rounds used, model, prompt version and ledger ids
    there); colliding keys raise and store nothing.
    """
    from corvus.learning.backtest import BacktestResult

    if isinstance(backtest_result, BacktestResult):
        verdict = backtest_result.to_dict()
    elif isinstance(backtest_result, dict):
        verdict = backtest_result
    else:
        raise ValueError("backtest_result must be a BacktestResult or its mapping")
    if not verdict.get("accepted"):
        raise ValueError(
            f"a rule that fails the verifier cannot be stored: {verdict.get('codes')}"
        )
    rule = _parse_sigma(sigma_text)
    if verdict.get("rule_id") != str(rule.id):
        raise ValueError("backtest result is for a different rule id")
    stored_text, sigma_id = prepare_candidate_text(sigma_text)
    if not producer.strip() or not producer_version.strip():
        raise ValueError("producer and producer_version are required")
    if any(not isinstance(uid, str) or not uid for uid in cited_uids):
        raise ValueError("cited_uids must be non-empty strings")
    if native_rule_id is not None and not (
        NATIVE_ID_MIN <= native_rule_id <= NATIVE_ID_MAX
    ):
        raise ValueError("native_rule_id must be inside 100000-120000")
    title = rule.title or ""
    moment = created if created is not None else _utcnow()
    if moment.tzinfo is None:
        raise ValueError("created must be timezone-aware")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX((lineage->>'version')::int), 0) FROM rules "
                "WHERE lineage->>'sigma_rule_id' = %s",
                (sigma_id,),
            )
            version = int(cur.fetchone()[0]) + 1  # type: ignore[index]
            allocated = native_rule_id
            if allocated is None:
                allocated = _allocate_native_id(cur)
            lineage = {
                "sigma_rule_id": sigma_id,
                "version": version,
                "producer": producer,
                "producer_version": producer_version,
                "source_incident": incident_id,
                "cited_uids": list(cited_uids),
                "backtest": {
                    "codes": verdict.get("codes"),
                    "target_matched": verdict.get("target_matched"),
                    "target_total": verdict.get("target_total"),
                    "baseline_count": verdict.get("baseline_count"),
                    "group": verdict.get("group"),
                },
                "history": [
                    {
                        "from": None,
                        "to": "candidate",
                        "approver": None,
                        "reason": "stored as candidate",
                        "at": moment.isoformat(),
                    }
                ],
            }
            if extra_lineage:
                for key, value in extra_lineage.items():
                    if key in lineage:
                        raise ValueError(
                            f"extra_lineage key {key!r} collides with stored lineage"
                        )
                    lineage[key] = value
            cur.execute(
                "INSERT INTO rules (title, sigma_text, native_rule_id, version, "
                "status, lineage, incident_id, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, 'candidate', %s, %s, %s, %s) "
                "RETURNING " + _RULE_COLUMNS,
                (
                    title,
                    stored_text,
                    allocated,
                    version,
                    Jsonb(lineage),
                    incident_id,
                    moment,
                    moment,
                ),
            )
            row = cur.fetchone()
        conn.commit()
    assert row is not None
    return _row_to_dict(row, _columns())


def get_rule(database_url: str, rule_id: int) -> dict[str, Any] | None:
    """Return one stored rule row, or None when the id is unknown."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT " + _RULE_COLUMNS + " FROM rules WHERE id = %s", (rule_id,)
            )
            row = cur.fetchone()
    if row is None:
        return None
    return _row_to_dict(row, _columns())


def list_rules(database_url: str, status: str | None = None) -> list[dict[str, Any]]:
    """List stored rules newest first (stable ``id`` tie-breaker)."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            if status is None:
                cur.execute("SELECT " + _RULE_COLUMNS + " FROM rules ORDER BY id DESC")
            else:
                cur.execute(
                    "SELECT " + _RULE_COLUMNS + " FROM rules WHERE status = %s "
                    "ORDER BY id DESC",
                    (status,),
                )
            rows = cur.fetchall()
    assert rows is not None
    return [_row_to_dict(row, _columns()) for row in rows]


def transition_rule(
    database_url: str,
    rule_id: int,
    to_status: str,
    *,
    approver: str,
    reason: str,
) -> dict[str, Any]:
    """Move a rule to a new status; return the updated row.

    Every move requires a non-empty ``approver`` string and a recorded
    ``reason`` (no move to ``shadow`` or ``active`` without an
    approver); anything else raises ``ValueError`` and changes
    nothing. The move appends to ``lineage.history``.
    """
    if not approver.strip():
        raise ValueError("an approver is required for every transition")
    if not reason.strip():
        raise ValueError("a reason is required for every transition")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status, lineage FROM rules WHERE id = %s", (rule_id,))
            current = cur.fetchone()
            if current is None:
                raise ValueError(f"unknown rule id {rule_id}")
            from_status, lineage = current[0], dict(current[1])
            allowed = TRANSITIONS.get(str(from_status), frozenset())
            if to_status not in allowed:
                raise ValueError(
                    f"cannot move a rule from {from_status} to {to_status}"
                )
            history = list(lineage.get("history") or [])
            history.append(
                {
                    "from": from_status,
                    "to": to_status,
                    "approver": approver,
                    "reason": reason,
                    "at": _utcnow().isoformat(),
                }
            )
            lineage["history"] = history
            cur.execute(
                "UPDATE rules SET status = %s, lineage = %s, "
                "deployed_at = CASE WHEN %s IN ('shadow', 'active') "
                "THEN COALESCE(deployed_at, NOW()) ELSE deployed_at END, "
                "updated_at = NOW() WHERE id = %s RETURNING " + _RULE_COLUMNS,
                (to_status, Jsonb(lineage), to_status, rule_id),
            )
            row = cur.fetchone()
        conn.commit()
    assert row is not None
    return _row_to_dict(row, _columns())


def roll_back_rule(
    database_url: str, rule_id: int, *, approver: str, reason: str
) -> dict[str, Any]:
    """Roll a shadow or active rule back; return the updated row."""
    current = get_rule(database_url, rule_id)
    if current is None:
        raise ValueError(f"unknown rule id {rule_id}")
    return transition_rule(
        database_url, rule_id, "rolled_back", approver=approver, reason=reason
    )


def archive_rule(
    database_url: str, rule_id: int, *, approver: str, reason: str
) -> dict[str, Any]:
    """Archive a rule; return the updated row."""
    current = get_rule(database_url, rule_id)
    if current is None:
        raise ValueError(f"unknown rule id {rule_id}")
    return transition_rule(
        database_url, rule_id, "archived", approver=approver, reason=reason
    )
