"""Learned-rule lifecycle over the existing ``rules`` table (0002/0007).

A rule that fails the :mod:`corvus.learning.backtest` verifier cannot
be stored as a candidate: :func:`add_candidate` requires a passing
backtest result for the same Sigma id. The stored copy is always
``experimental``; the backtest level ceiling is enforced again here.
Status moves only through :func:`transition_rule`, which requires a
non-empty approver string and a recorded reason for every move
(``candidate -> shadow -> active``, plus ``rolled_back`` and
``archived``), appended to ``lineage.history``. A new version of the
same Sigma id inserts a fresh row with an incremented version and
keeps the old row untouched. ``native_rule_id`` allocates inside
100000-120000 and is never reused (partial unique index from
migration 0007 refuses the second writer).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

__all__ = [
    "NATIVE_ID_MAX",
    "NATIVE_ID_MIN",
    "TRANSITIONS",
    "add_candidate",
    "archive_rule",
    "get_rule",
    "list_rules",
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
) -> dict[str, Any]:
    """Store a verified candidate rule; return the stored row.

    ``backtest_result`` is the passing verdict for this exact Sigma
    id (a :class:`BacktestResult` or its ``to_dict()`` mapping); any
    other value raises ``ValueError`` and stores nothing. The stored
    status is forced to ``experimental`` and the version increments
    per Sigma id while older rows are kept. ``native_rule_id`` is
    allocated automatically unless the caller passes one explicitly
    (out-of-range values raise; collisions raise the database's
    unique violation, so a racer never overwrites).
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
    sigma_id = str(rule.id)
    if verdict.get("rule_id") != sigma_id:
        raise ValueError("backtest result is for a different rule id")
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
            cur.execute(
                "INSERT INTO rules (title, sigma_text, native_rule_id, version, "
                "status, lineage, incident_id, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, 'candidate', %s, %s, %s, %s) "
                "RETURNING " + _RULE_COLUMNS,
                (
                    title,
                    sigma_text,
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
