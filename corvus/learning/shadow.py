"""Shadow evaluation for learned rules (no model calls, no side effects).

A rule in ``shadow`` status is evaluated with the same engine and
mapping as the shipped rules (:func:`corvus.detect.rules.load_rules`
plus :func:`corvus.detect.engine.evaluate`), and every match becomes
a finding marked shadow (rule database id, version and Sigma id in
``unmapped``). Shadow evaluation never writes to the findings store,
never creates a notification (no notification path exists yet), and
never touches incidents or severity: the mark keeps shadow findings
out of correlation by construction, since they are returned to the
caller and never persisted.

Hits update the rule's ``hits`` counter; an operator verdict written
through :func:`record_shadow_verdict` lands in ``dispositions`` and
updates the counters (``fp`` bumps ``false_positives``, ``tp``
confirms a hit). The kill switch
(:attr:`corvus.settings.Settings.learned_rules_enabled`,
``LEARNED_RULES_ENABLED=0``) disables all learned-rule evaluation at
once: :func:`evaluate_shadow` then returns zero findings without
compiling anything.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg

from corvus.detect.rules import ALL_STATUSES, CompiledRule, load_rules

__all__ = [
    "ShadowFinding",
    "ShadowReport",
    "compile_shadow_rules",
    "evaluate_shadow",
    "learned_rules_enabled",
    "record_shadow_verdict",
    "shadow_rules",
]


@dataclass(frozen=True)
class ShadowFinding:
    """One shadow match: the finding plus its learned-rule provenance."""

    rule_db_id: int
    version: int
    sigma_rule_id: str
    event_uid: str
    finding: Any


@dataclass
class ShadowReport:
    """The outcome of one shadow evaluation run (counts only)."""

    enabled: bool
    rules_evaluated: int
    findings: list[ShadowFinding] = field(default_factory=list)
    hits_by_rule: dict[int, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def total_hits(self) -> int:
        """Return the matches across all shadow rules."""
        return sum(self.hits_by_rule.values())


def learned_rules_enabled() -> bool:
    """Return the kill-switch state (True means learned rules may run).

    Reads ``LEARNED_RULES_ENABLED`` directly (``0``/``false``/``no``/
    ``off`` disable; unset means enabled) instead of constructing the
    full :class:`corvus.settings.Settings`, so the switch never
    depends on unrelated settings being present. The same flag lives
    on Settings for the operator-facing configuration surface.
    """
    import os

    raw = os.environ.get("LEARNED_RULES_ENABLED", "").strip().lower()
    if raw == "" or raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"LEARNED_RULES_ENABLED must be a boolean, got {raw!r}")


def shadow_rules(database_url: str) -> list[dict[str, Any]]:
    """Return every stored rule in ``shadow`` status, oldest first."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, sigma_text, native_rule_id, version,"
                " lineage FROM rules WHERE status = 'shadow' ORDER BY id ASC"
            )
            rows = cur.fetchall()
    assert rows is not None
    return [
        {
            "id": int(row[0]),
            "title": str(row[1] or ""),
            "sigma_text": str(row[2]),
            "native_rule_id": row[3],
            "version": int(row[4]),
            "lineage": dict(row[5] or {}),
        }
        for row in rows
    ]


def compile_shadow_rules(
    rows: Sequence[dict[str, Any]],
) -> tuple[list[tuple[CompiledRule, dict[str, Any]]], dict[str, int]]:
    """Compile stored shadow rules through the shipped-rule loader.

    Each ``sigma_text`` is written to a temporary file and loaded
    with :func:`corvus.detect.rules.load_rules` (all statuses: the
    stored copy is ``experimental`` by design), so a shadow rule is
    judged by exactly the same routing, field and construct checks
    as a shipped rule. Returns the (compiled rule, stored row) pairs
    plus skip counts by reason. A Sigma id shared by several stored
    rows maps to the oldest shadow row.
    """
    pairs: list[tuple[CompiledRule, dict[str, Any]]] = []
    skipped: dict[str, int] = {}
    if not rows:
        return pairs, skipped
    with tempfile.TemporaryDirectory(prefix="shadow-rules") as tmp:
        paths = []
        for row in rows:
            path = Path(tmp) / f"rule-{int(row['id'])}-v{int(row['version'])}.yml"
            path.write_text(str(row["sigma_text"]), encoding="utf-8")
            paths.append((path, row))
        compiled, stats = load_rules(tmp, statuses=ALL_STATUSES)
        by_sigma: dict[str, dict[str, Any]] = {}
        for _path, row in paths:
            by_sigma.setdefault(str(row["lineage"].get("sigma_rule_id") or ""), row)
        for item in compiled:
            stored = by_sigma.get(item.rule_id)
            if stored is None:
                skipped["unmatched"] = skipped.get("unmatched", 0) + 1
                continue
            pairs.append((item, stored))
        for reason, count in stats.skipped.items():
            skipped[reason] = skipped.get(reason, 0) + int(count)
    pairs.sort(key=lambda pair: int(pair[1]["id"]))
    return pairs, skipped


def _mark_shadow(finding: Any, row: dict[str, Any], sigma_rule_id: str) -> None:
    """Stamp one finding as shadow with its learned-rule provenance."""
    unmapped = finding.unmapped
    if not isinstance(unmapped, dict):
        finding.unmapped = {}
        unmapped = finding.unmapped
    unmapped["corvus_shadow"] = True
    unmapped["corvus_shadow_rule_id"] = int(row["id"])
    unmapped["corvus_shadow_version"] = int(row["version"])
    unmapped["corvus_shadow_sigma_id"] = sigma_rule_id


def evaluate_shadow(
    replay_dir: str | Path,
    database_url: str,
    *,
    attack: Any | None = None,
    attack_path: str | Path = "data/attack/enterprise.json",
) -> ShadowReport:
    """Evaluate every shadow rule over a replay store; return the report.

    The kill switch comes first: when
    :func:`learned_rules_enabled` is False the report is disabled
    with zero findings and nothing is compiled. Otherwise each
    shadow rule runs through the shipped-rule loader and the
    detection engine, matches become shadow-marked findings
    (returned, never persisted to the findings store), and the
    rule's ``hits`` counter grows by this run's matches. No
    notification is created and no incident severity changes: this
    function never writes findings, incidents or dispositions.
    """
    from corvus.attack import load_dictionary
    from corvus.detect.engine import evaluate
    from corvus.detect.findings import build_finding

    if not learned_rules_enabled():
        return ShadowReport(enabled=False, rules_evaluated=0)
    rows = shadow_rules(database_url)
    pairs, skipped = compile_shadow_rules(rows)
    if not pairs:
        return ShadowReport(enabled=True, rules_evaluated=0, skipped=skipped)
    import json as json_module

    with open(attack_path, encoding="utf-8") as handle:
        attack_version = str(
            json_module.loads(handle.read()).get("attack_version", "v20.0")
        ).removeprefix("v")
    dictionary = attack if attack is not None else load_dictionary(attack_path)
    compiled = [item for item, _row in pairs]
    matches, infos, _stats = evaluate(replay_dir, compiled)
    report = ShadowReport(enabled=True, rules_evaluated=len(compiled), skipped=skipped)
    for item, row in pairs:
        uids = sorted(matches.get(item.rule_id, set()))
        for uid in uids:
            info = infos.get(uid)
            if info is None:
                continue
            finding = build_finding(item, info, dictionary, attack_version)
            _mark_shadow(finding, row, item.rule_id)
            report.findings.append(
                ShadowFinding(
                    rule_db_id=int(row["id"]),
                    version=int(row["version"]),
                    sigma_rule_id=item.rule_id,
                    event_uid=uid,
                    finding=finding,
                )
            )
        report.hits_by_rule[int(row["id"])] = len(uids)
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            for rule_db_id, hits in report.hits_by_rule.items():
                cur.execute(
                    "UPDATE rules SET hits = hits + %s, updated_at = NOW()"
                    " WHERE id = %s",
                    (hits, rule_db_id),
                )
        conn.commit()
    return report


def record_shadow_verdict(
    database_url: str,
    rule_db_id: int,
    verdict: str,
    analyst: str,
    note: str = "",
) -> dict[str, Any]:
    """Record an operator verdict on a shadow rule; return the counts.

    The verdict (``tp`` or ``fp``) lands in ``dispositions`` with the
    analyst name; ``fp`` bumps the rule's ``false_positives`` counter
    and ``tp`` confirms a hit on ``hits``. Anything else raises
    ``ValueError`` and changes nothing.
    """
    if verdict not in ("tp", "fp"):
        raise ValueError(f"shadow verdict must be 'tp' or 'fp', got {verdict!r}")
    if not analyst.strip():
        raise ValueError("an analyst name is required for a shadow verdict")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM rules WHERE id = %s", (rule_db_id,))
            if cur.fetchone() is None:
                raise ValueError(f"unknown rule id {rule_db_id}")
            cur.execute(
                "INSERT INTO dispositions (rule_id, verdict, analyst, note)"
                " VALUES (%s, %s, %s, %s)",
                (rule_db_id, verdict, analyst, note),
            )
            if verdict == "fp":
                cur.execute(
                    "UPDATE rules SET false_positives = false_positives + 1,"
                    " updated_at = NOW() WHERE id = %s"
                    " RETURNING hits, false_positives",
                    (rule_db_id,),
                )
            else:
                cur.execute(
                    "UPDATE rules SET hits = hits + 1, updated_at = NOW()"
                    " WHERE id = %s RETURNING hits, false_positives",
                    (rule_db_id,),
                )
            row = cur.fetchone()
            assert row is not None
        conn.commit()
    return {"hits": int(row[0]), "false_positives": int(row[1])}
