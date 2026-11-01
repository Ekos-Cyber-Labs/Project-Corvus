"""Learned-rule lifecycle over the existing ``rules`` table.

The store never trusts a caller-supplied verdict: :func:`add_candidate`
re-runs :mod:`corvus.learning.backtest` itself on the exact submitted
text against the source incident's stored events and the baseline, and
refuses (``ValueError``, nothing stored) unless the fresh result is
``accepted`` with ``codes == ["accepted"]``. A caller verdict may be
passed for information only; it is never the source of the stored
verdict — the fresh one is stored in ``lineage.backtest`` together
with the SHA-256 of the exact evaluated text. Without an incident the
re-run is impossible, so an unknown or missing incident is refused,
never waved through. The model's Sigma id is then ignored: Corvus
assigns a fresh uuid4 (:func:`prepare_candidate_text`) and rewrites
it into the stored text, so a model-chosen id can never collide with
a shipped or stored rule. The stored copy is always ``experimental``
(rewritten the same way); deployment lifecycle lives in the row's
``status`` column (``candidate``, ``shadow``, ``active``,
``rolled_back``, ``archived``), never in the Sigma text. The backtest
level ceiling is enforced again here. A first store is always version
1; a new revision of a stored rule passes ``supersedes=<rule id>``,
which must name the LATEST non-archived revision of that Sigma id
(anything else — an older or an archived revision — is refused),
reuses that Sigma id at version MAX(version) + 1, and records the
superseded id in lineage (the old row is always kept untouched); the
lock, the version computation and the insert happen in one
transaction, and the unique ``(sigma id, version)`` index from
migration 0009 refuses a second writer. Storing without
``supersedes`` always yields a fresh Sigma id at version 1. Status
moves only through :func:`transition_rule`, which requires a
non-empty approver string (stripped before it is checked or recorded;
restricted to :envvar:`CORVUS_RULE_APPROVERS` when that
comma-separated list is set) and a recorded reason for every move
(``candidate -> shadow -> active``, plus ``rolled_back`` and
``archived``), appended to ``lineage.history``. The move reads the
row ``FOR UPDATE`` in the same transaction that writes it, so
concurrent movers serialize and no history entry is lost; callers
that observed a stale state pass ``from_status`` and fail instead of
moving a rule that already left it. ``native_rule_id`` allocates
inside 100000-120000 and is never reused (partial unique index from
migration 0007 refuses the second writer).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
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


def prepare_candidate_text(
    sigma_text: str, sigma_id: str | None = None
) -> tuple[str, str]:
    """Assign the Corvus Sigma id; return ``(stored_text, sigma_id)``.

    The model's ``id`` is ignored (it may be a fabricated look-alike
    UUID colliding with a shipped or stored rule): a fresh uuid4 is
    assigned unless the caller passes ``sigma_id`` (the supersede
    path, reusing a stored rule's id), rewritten into the stored
    text; ``status`` is forced to ``experimental`` however the model
    labelled it. Only those two top-level keys change: the rewritten
    text must describe the same detection (compared by parsed
    structure minus ``id``/``status``), otherwise ``ValueError`` is
    raised and nothing is stored. Raises ``ValueError`` for anything
    that is not exactly one Sigma rule, and for a ``sigma_id`` that
    is not a UUID.
    """
    rule = _parse_sigma(sigma_text)
    try:
        doc = yaml.safe_load(sigma_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"sigma YAML does not parse: {exc}") from None
    if not isinstance(doc, Mapping):
        raise ValueError("sigma YAML must be a mapping with one rule")
    before = dict(doc)
    if sigma_id is None:
        assigned = str(uuid.uuid4())
    else:
        try:
            assigned = str(uuid.UUID(str(sigma_id)))
        except ValueError:
            raise ValueError(f"sigma_id {sigma_id!r} is not a UUID") from None
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
    backtest_result: Any = None,
    producer: str = "",
    producer_version: str = "",
    created: datetime | None = None,
    native_rule_id: int | None = None,
    extra_lineage: dict[str, Any] | None = None,
    supersedes: int | None = None,
    *,
    chain_dir: str | Path = "data/replay-linux-chain1",
    baseline_dir: str | Path = "data/replay-linux-baseline",
) -> dict[str, Any]:
    """Store a verified candidate rule; return the stored row.

    The store never trusts ``backtest_result``: it may be a
    :class:`BacktestResult`, its ``to_dict()`` mapping, or None, and
    is informational only — anything else raises ``ValueError`` and
    stores nothing, but even a well-formed verdict is never the
    source of the stored verdict. Instead the store re-runs
    :func:`corvus.learning.backtest.backtest` itself on the exact
    submitted text against the source incident's stored events and
    the baseline (``chain_dir`` / ``baseline_dir``), and refuses
    unless the fresh result is ``accepted`` with
    ``codes == ["accepted"]``; every cited uid must be inside the
    fresh ``target_matched``. Without an incident the re-run is
    impossible, so a missing or unknown incident id raises
    ``ValueError`` and stores nothing. The fresh verdict — not the
    caller's — is stored in ``lineage.backtest`` with the SHA-256 of
    the exact evaluated text. The stored row then carries a fresh
    Corvus-assigned id and ``experimental`` status text (see
    :func:`prepare_candidate_text`), so the model's id is ignored
    and can never collide with another rule. A first store is
    version 1; ``supersedes=<rule id>`` stores a new revision of
    that rule only when the named row is the LATEST non-archived
    revision of its Sigma id (an unknown id, a stale revision, or an
    archived revision raises), reusing that Sigma id at version
    MAX(version) + 1 for the Sigma id and recording the superseded
    id in lineage (the old row is kept untouched). The parent lock,
    the latest-revision check, the version computation and the
    insert run in one transaction, so two concurrent supersedes of
    the same parent serialize and exactly one wins; the unique
    ``(sigma id, version)`` index refuses any residual double
    writer. ``native_rule_id`` is allocated automatically unless the
    caller passes one explicitly (out-of-range values raise;
    collisions raise the database's unique violation, so a racer
    never overwrites). ``extra_lineage`` merges additional keys into
    the stored lineage (the proposal loop records rounds used,
    model, prompt version and ledger ids there); colliding keys
    raise and store nothing.
    """
    from corvus.learning.backtest import BacktestResult, backtest

    if backtest_result is not None and not isinstance(
        backtest_result, (BacktestResult, dict)
    ):
        raise ValueError(
            "backtest_result must be a BacktestResult, its mapping, or None"
        )
    if not producer.strip() or not producer_version.strip():
        raise ValueError("producer and producer_version are required")
    if any(not isinstance(uid, str) or not uid for uid in cited_uids):
        raise ValueError("cited_uids must be non-empty strings")
    if native_rule_id is not None and not (
        NATIVE_ID_MIN <= native_rule_id <= NATIVE_ID_MAX
    ):
        raise ValueError("native_rule_id must be inside 100000-120000")
    if incident_id is None:
        raise ValueError(
            "an incident id is required: the store re-runs the backtest "
            "against the incident's stored events and cannot verify a rule "
            "without one"
        )
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_uids FROM incidents WHERE id = %s", (incident_id,)
            )
            found = cur.fetchone()
    if found is None:
        raise ValueError(f"unknown incident id {incident_id}")
    raw_uids = found[0] or []
    incident_uids = [uid for uid in raw_uids if isinstance(uid, str) and uid]
    fresh = backtest(
        sigma_text,
        {"event_uids": incident_uids},
        baseline_dir=baseline_dir,
        chain_dir=chain_dir,
    )
    if fresh.accepted is not True or list(fresh.codes) != ["accepted"]:
        raise ValueError(
            "the store's backtest refused this text "
            f"(codes={fresh.codes}); nothing was stored"
        )
    matched = list(fresh.target_matched)
    missing = [uid for uid in cited_uids if uid not in set(matched)]
    if missing:
        raise ValueError(f"{len(missing)} cited uids are not in the backtest match")
    rule = _parse_sigma(sigma_text)
    text_hash = hashlib.sha256(sigma_text.encode("utf-8")).hexdigest()
    title = rule.title or ""
    moment = created if created is not None else _utcnow()
    if moment.tzinfo is None:
        raise ValueError("created must be timezone-aware")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            if supersedes is None:
                reuse_id: str | None = None
                version = 1
            else:
                cur.execute(
                    "SELECT lineage FROM rules WHERE id = %s FOR UPDATE",
                    (supersedes,),
                )
                parent = cur.fetchone()
                if parent is None:
                    raise ValueError(f"unknown superseded rule id {supersedes}")
                reuse_id = str((parent[0] or {}).get("sigma_rule_id") or "")
                if not reuse_id:
                    raise ValueError(f"superseded rule {supersedes} has no sigma id")
                cur.execute(
                    "SELECT id FROM rules "
                    "WHERE lineage->>'sigma_rule_id' = %s AND status <> 'archived' "
                    "ORDER BY version DESC LIMIT 1 FOR UPDATE",
                    (reuse_id,),
                )
                latest = cur.fetchone()
                if latest is None or int(latest[0]) != supersedes:
                    raise ValueError(
                        f"rule {supersedes} is not the latest non-archived "
                        "revision of its Sigma id; supersede that revision instead"
                    )
                cur.execute(
                    "SELECT MAX(version) FROM rules "
                    "WHERE lineage->>'sigma_rule_id' = %s",
                    (reuse_id,),
                )
                top = cur.fetchone()
                assert top is not None
                version = int(top[0]) + 1
            stored_text, sigma_id = prepare_candidate_text(
                sigma_text, sigma_id=reuse_id
            )
            allocated = native_rule_id
            if allocated is None:
                allocated = _allocate_native_id(cur)
            lineage = {
                "sigma_rule_id": sigma_id,
                "version": version,
                "supersedes": supersedes,
                "producer": producer,
                "producer_version": producer_version,
                "source_incident": incident_id,
                "cited_uids": list(cited_uids),
                "backtest": {
                    "codes": list(fresh.codes),
                    "target_matched": matched,
                    "target_total": fresh.target_total,
                    "baseline_count": fresh.baseline_count,
                    "group": fresh.group,
                    "sigma_sha256": text_hash,
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


#: Approver allow-list (comma-separated); when set, only listed
#: approvers may move a rule. Read at call time so tests and
#: operators can change it without a restart.
APPROVERS_ENV_VAR = "CORVUS_RULE_APPROVERS"


def _allowed_approvers() -> set[str] | None:
    """Return the approver allow-list, or None when unset.

    ``CORVUS_RULE_APPROVERS`` holds comma-separated names; blank
    entries are dropped, and an empty value means no restriction
    (any non-empty approver string is recorded).
    """
    raw = os.environ.get(APPROVERS_ENV_VAR, "")
    names = {part.strip() for part in raw.split(",")}
    names.discard("")
    return names or None


def transition_rule(
    database_url: str,
    rule_id: int,
    to_status: str,
    *,
    approver: str,
    reason: str,
    from_status: str | None = None,
) -> dict[str, Any]:
    """Move a rule to a new status; return the updated row.

    Every move requires a non-empty ``approver`` string and a recorded
    ``reason`` (no move to ``shadow`` or ``active`` without an
    approver); the approver is stripped first, so the recorded value
    is exactly the string the allow-list check compares. When
    :envvar:`CORVUS_RULE_APPROVERS` is set, the approver must also be
    listed there. Anything else raises ``ValueError`` and changes
    nothing. ``from_status``, when given, is the state the caller
    observed: the move fails when the row has already left it, so a
    concurrent mover is told it lost instead of silently chaining
    onto the winner's state. The move appends to ``lineage.history``.
    The row is read ``FOR UPDATE`` in the same transaction that
    writes it, so concurrent movers serialize and no history entry
    is ever lost.
    """
    clean_approver = approver.strip()
    if not clean_approver:
        raise ValueError("an approver is required for every transition")
    if not reason.strip():
        raise ValueError("a reason is required for every transition")
    allowed_names = _allowed_approvers()
    if allowed_names is not None and clean_approver not in allowed_names:
        raise ValueError(f"approver {clean_approver!r} is not in {APPROVERS_ENV_VAR}")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, lineage FROM rules WHERE id = %s FOR UPDATE",
                (rule_id,),
            )
            current = cur.fetchone()
            if current is None:
                raise ValueError(f"unknown rule id {rule_id}")
            locked_status, lineage = str(current[0]), dict(current[1])
            if from_status is not None and locked_status != str(from_status):
                raise ValueError(
                    f"rule {rule_id} is {locked_status}, "
                    f"expected {from_status} (concurrent modification)"
                )
            from_status, lineage = locked_status, lineage
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
                    "approver": clean_approver,
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
        database_url,
        rule_id,
        "rolled_back",
        approver=approver,
        reason=reason,
        from_status=current["status"],
    )


def archive_rule(
    database_url: str, rule_id: int, *, approver: str, reason: str
) -> dict[str, Any]:
    """Archive a rule; return the updated row."""
    current = get_rule(database_url, rule_id)
    if current is None:
        raise ValueError(f"unknown rule id {rule_id}")
    return transition_rule(
        database_url,
        rule_id,
        "archived",
        approver=approver,
        reason=reason,
        from_status=current["status"],
    )
