"""Differential proof: indexed correlation matches the old full scan.

Compares :func:`corvus.correlate.correlate_findings` byte for byte
against a test-local brute-force oracle (the pre-index algorithm: one
finding at a time scanned against every cluster, factor 4 re-walking
the whole events map per cluster) over the 6074 real findings of
``data/replay`` plus 20 random shuffles. Skips with a clear marker
when ``data/`` is absent, like the other real-data tests. No timing
assertion lives here (timing-dependent tests are banned); wall times
are measured out of band and reported in the change notes.
"""

from __future__ import annotations

import json
import random
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

REPLAY_DIR = Path("data/replay")
ATTACK_PATH = Path("data/attack/enterprise.json")


def _dump(incidents: list[dict[str, Any]]) -> str:
    return json.dumps(incidents, sort_keys=True, default=str)


def _oracle(
    findings: list[Any],
    events: dict[str, Any],
    attack: Any,
    session_gap: timedelta,
    max_span: timedelta,
    threshold: int,
) -> list[dict[str, Any]]:
    """Brute-force reference: the pre-index correlation algorithm."""
    from corvus.correlate.correlate import (
        SCORE_BREADTH_STEP,
        _Cluster,
        _cross_host_ok,
        _signals_for,
        _success_detail,
    )
    from corvus.correlate.severity import severity_floor

    gap_ms = int(session_gap.total_seconds() * 1000)
    span_ms = int(max_span.total_seconds() * 1000)
    ordered = sorted(
        (_signals_for(finding, events, attack) for finding in findings),
        key=lambda signals: (signals.time, signals.uid),
    )
    clusters: list[_Cluster] = []
    for signals in ordered:
        candidates = [
            cluster
            for cluster in clusters
            if cluster.keys & signals.join_keys
            and signals.time - cluster.last_seen <= gap_ms
            and signals.time - cluster.first_seen <= span_ms
            and _cross_host_ok(signals, cluster)
        ]
        if not candidates:
            cluster = _Cluster(key=f"corr-{signals.uid}")
            cluster.first_seen = signals.time
            cluster.add(signals)
            clusters.append(cluster)
        elif len(candidates) == 1:
            candidates[0].add(signals)
        else:
            keeper = min(candidates, key=lambda item: (item.first_seen, item.key))
            others = [item for item in candidates if item is not keeper]
            for other in others:
                for member in sorted(
                    other.members, key=lambda item: (item.time, item.uid)
                ):
                    keeper.add(member)
                clusters.remove(other)
            keeper.add(signals)
    incidents: list[dict[str, Any]] = []
    for cluster in clusters:
        tactics = sorted(
            {short for member in cluster.members for short in member.tactics}
        )
        primaries = sorted(
            {
                member.primary_tactic
                for member in cluster.members
                if member.primary_tactic is not None
            }
        )
        techniques = sorted(
            {tech for member in cluster.members for tech in member.techniques}
        )
        detail = _success_detail(
            cluster, events, threshold, cluster.first_seen - gap_ms
        )
        max_severity = max(member.severity_id for member in cluster.members)
        floor, factors = severity_floor(
            tactics, primaries, list(attack.tactic_order), max_severity, detail["fired"]
        )
        factor_4 = factors["factor_4_success_vs_attempt"]
        factors["factor_4_success_vs_attempt"] = {**factor_4, **detail}
        breadth = len(primaries)
        score = round(float(floor) + SCORE_BREADTH_STEP * max(breadth - 1, 0), 2)
        earliest = min(cluster.members, key=lambda member: (member.time, member.uid))
        most_advanced = factors["factor_1_attack_stage"]["most_advanced_tactic"]
        if most_advanced is not None:
            display = attack.tactic_names.get(str(most_advanced), str(most_advanced))
        else:
            display = "Unclassified"
        primary = sorted(earliest.hosts)[0] if earliest.hosts else "unknown host"
        count = len(cluster.members)
        incidents.append(
            {
                "correlation_key": cluster.key,
                "title": (
                    f"{display} on {primary} "
                    f"({count} finding{'s' if count != 1 else ''})"
                ),
                "entity_keys": {
                    "hosts": sorted(cluster.hosts),
                    "users": sorted(cluster.users),
                    "service_users": sorted(cluster.service_users),
                    "ips": sorted(cluster.device_ips | cluster.remote_ips),
                    "processes": sorted(cluster.proc_keys),
                },
                "techniques": techniques,
                "event_uids": sorted(
                    {member.uid for member in cluster.members}
                    | (cluster.referenced_uids & set(events))
                ),
                "first_seen": cluster.first_seen,
                "last_seen": cluster.last_seen,
                "deterministic_score": score,
                "severity_floor": floor,
                "severity_id": floor,
                "severity_factors": factors,
            }
        )
    return sorted(
        incidents, key=lambda item: (item["first_seen"], item["correlation_key"])
    )


def _load_real() -> tuple[list[Any], dict[str, Any], Any] | None:
    if not REPLAY_DIR.is_dir() or not ATTACK_PATH.is_file():
        return None
    from corvus.adapters.replay.adapter import ReplayAdapter
    from corvus.attack import load_dictionary
    from corvus.correlate.replay import (
        load_replay_events,
        load_replay_findings,
        referenced_event_uids,
    )

    dictionary = load_dictionary(ATTACK_PATH)
    findings = load_replay_findings(REPLAY_DIR)
    if not findings:
        return None
    gap_ms = int(timedelta(minutes=30).total_seconds() * 1000)
    start = min(finding.time for finding in findings) - gap_ms
    end = max(finding.time for finding in findings)
    adapter = ReplayAdapter(REPLAY_DIR)
    events = load_replay_events(
        REPLAY_DIR, adapter, referenced_event_uids(findings), start, end
    )
    return findings, events, dictionary


def test_index_matches_scan_on_real_replay_store() -> None:
    """Byte-identical incidents (keys, floors, factors, uids) on 6074 findings."""
    from corvus.correlate import correlate_findings

    loaded = _load_real()
    if loaded is None:
        pytest.skip("data/replay or data/attack/enterprise.json absent")
    findings, events, attack = loaded
    assert len(findings) == 6074, (
        f"expected the full replay census, got {len(findings)}"
    )
    assert len({f.metadata.uid for f in findings}) == len(findings)
    session_gap = timedelta(minutes=30)
    max_span = timedelta(hours=24)
    threshold = 5
    expected = _oracle(findings, events, attack, session_gap, max_span, threshold)
    actual = correlate_findings(
        findings,
        events,
        attack,
        session_gap=session_gap,
        max_span=max_span,
        auth_failure_threshold=threshold,
    )
    for incident in actual:
        assert incident.pop("learned_rules") == []
    assert _dump(actual) == _dump(expected)


def test_index_matches_scan_on_twenty_shuffles() -> None:
    """Twenty random arrival orders give the same byte-identical result."""
    from corvus.correlate import correlate_findings

    loaded = _load_real()
    if loaded is None:
        pytest.skip("data/replay or data/attack/enterprise.json absent")
    findings, events, attack = loaded
    session_gap = timedelta(minutes=30)
    max_span = timedelta(hours=24)
    threshold = 5
    reference = _dump(
        correlate_findings(
            findings,
            events,
            attack,
            session_gap=session_gap,
            max_span=max_span,
            auth_failure_threshold=threshold,
        )
    )
    for seed in range(20):
        shuffled = list(findings)
        random.Random(seed).shuffle(shuffled)
        assert (
            _dump(
                correlate_findings(
                    shuffled,
                    events,
                    attack,
                    session_gap=session_gap,
                    max_span=max_span,
                    auth_failure_threshold=threshold,
                )
            )
            == reference
        ), f"shuffle seed {seed} diverged"
