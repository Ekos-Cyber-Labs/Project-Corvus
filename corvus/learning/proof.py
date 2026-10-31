"""The learning proof: a stored rule fires on unseen-variant data.

``run_proof`` stores the deterministic stand-in for a model output
(the previous prompt's golden control rule, no API involved),
approves it to shadow, evaluates the shadow rule over the control
store (the variant run: same techniques, neutral values) and
reports that it fires there — while the same detection run adds
ZERO rows to ``llm_attempts`` and ``spend``. The negative control
runs the same evaluation with the rule rolled back and reports that
it does not fire. Every figure carries its n and window.
"""

from __future__ import annotations

import glob
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pyarrow.parquet as pq

__all__ = ["ProofReport", "chain_store_stats", "run_proof"]

#: The deterministic stand-in for the model output (committed fixture).
GOLDEN_RULE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "tests"
    / "fixtures"
    / "rules"
    / "linux_golden_rule.yml"
)

#: Target uids the golden control is known to match in the chain store.
GOLDEN_UIDS = [
    "lnx-d7bea80358fc93ab",
    "lnx-f749ba60b31e41e4",
    "lnx-22e99900825434c9",
]


@dataclass
class ProofReport:
    """Counts and windows for the learning proof (no event content)."""

    rule_db_id: int
    sigma_rule_id: str
    chain_n: int
    chain_window: tuple[str, str]
    control_n: int
    control_window: tuple[str, str]
    control_hits: int
    control_hit_uids: list[str] = field(default_factory=list)
    attempts_before: int = 0
    attempts_after: int = 0
    spend_before: int = 0
    spend_after: int = 0
    rolled_back_hits: int = 0
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable proof report."""
        return {
            "rule_db_id": self.rule_db_id,
            "sigma_rule_id": self.sigma_rule_id,
            "chain_n": self.chain_n,
            "chain_window": list(self.chain_window),
            "control_n": self.control_n,
            "control_window": list(self.control_window),
            "control_hits": self.control_hits,
            "control_hit_uids": list(self.control_hit_uids),
            "attempts_before": self.attempts_before,
            "attempts_after": self.attempts_after,
            "spend_before": self.spend_before,
            "spend_after": self.spend_after,
            "rolled_back_hits": self.rolled_back_hits,
            "passed": self.passed,
        }


def chain_store_stats(replay_dir: str | Path) -> tuple[int, tuple[str, str]]:
    """Return ``(event count, (first, last) ISO window)`` for a store."""
    times: list[int] = []
    pattern = str(Path(replay_dir) / "events" / "*.parquet")
    for path in sorted(glob.glob(pattern)):
        times.extend(pq.read_table(path, columns=["time"]).column("time").to_pylist())
    if not times:
        raise ValueError(f"no events under {replay_dir}")
    iso = [
        datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat()
        for ms in (min(times), max(times))
    ]
    return len(times), (iso[0], iso[1])


def _audit_counts(database_url: str) -> tuple[int, int]:
    """Return ``(llm_attempts rows, spend rows)`` right now."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM llm_attempts")
            attempts = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM spend")
            spend = cur.fetchone()
    assert attempts is not None and spend is not None
    return int(attempts[0]), int(spend[0])


def run_proof(
    database_url: str,
    *,
    chain_dir: str | Path = "data/replay-linux-chain1",
    control_dir: str | Path = "data/replay-linux-chain1-off",
    baseline_dir: str | Path = "data/replay-linux-baseline",
) -> ProofReport:
    """Run the learning proof end to end; raise when any check fails.

    Stores the golden stand-in as candidate, approves it to shadow,
    evaluates shadow rules over the control store (must fire),
    asserts the detection added zero ``llm_attempts`` / ``spend``
    rows, rolls the rule back and asserts the same evaluation no
    longer fires. The stored rule is left ``rolled_back`` with its
    lineage intact. Every step raises with a plain message instead
    of returning a half-proof.
    """
    from corvus.learning.backtest import backtest
    from corvus.learning.rules import add_candidate, roll_back_rule, transition_rule
    from corvus.learning.shadow import evaluate_shadow

    sigma_text = GOLDEN_RULE_PATH.read_text(encoding="utf-8")
    verdict = backtest(
        sigma_text,
        {"event_uids": list(GOLDEN_UIDS)},
        baseline_dir=baseline_dir,
        chain_dir=chain_dir,
    )
    if not verdict.accepted:
        raise ValueError(f"golden stand-in rejected: {verdict.codes}")
    matched = sorted(verdict.target_matched)
    if not matched:
        raise ValueError("golden stand-in matched no target event")
    stored = add_candidate(
        database_url,
        sigma_text,
        None,
        matched,
        verdict,
        "learning-proof",
        "v1",
    )
    rule_db_id = int(stored["id"])
    sigma_rule_id = str(stored["lineage"]["sigma_rule_id"])
    transition_rule(
        database_url,
        rule_db_id,
        "shadow",
        approver="learning-proof",
        reason="proof control run",
    )
    chain_n, chain_window = chain_store_stats(chain_dir)
    control_n, control_window = chain_store_stats(control_dir)
    attempts_before, spend_before = _audit_counts(database_url)
    fired = evaluate_shadow(control_dir, database_url)
    attempts_after, spend_after = _audit_counts(database_url)
    if attempts_after != attempts_before:
        raise ValueError("shadow detection wrote llm_attempts rows")
    if spend_after != spend_before:
        raise ValueError("shadow detection wrote spend rows")
    control_hits = fired.hits_by_rule.get(rule_db_id, 0)
    hit_uids = sorted(
        finding.event_uid
        for finding in fired.findings
        if finding.rule_db_id == rule_db_id
    )
    if control_hits == 0:
        raise ValueError("learned rule did not fire on the control store")
    roll_back_rule(
        database_url,
        rule_db_id,
        approver="learning-proof",
        reason="proof negative control",
    )
    quiet = evaluate_shadow(control_dir, database_url)
    rolled_back_hits = quiet.hits_by_rule.get(rule_db_id, 0)
    if rolled_back_hits != 0:
        raise ValueError("rolled-back rule still fires")
    return ProofReport(
        rule_db_id=rule_db_id,
        sigma_rule_id=sigma_rule_id,
        chain_n=chain_n,
        chain_window=chain_window,
        control_n=control_n,
        control_window=control_window,
        control_hits=control_hits,
        control_hit_uids=hit_uids,
        attempts_before=attempts_before,
        attempts_after=attempts_after,
        spend_before=spend_before,
        spend_after=spend_after,
        rolled_back_hits=rolled_back_hits,
        passed=True,
    )
