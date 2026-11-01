"""One live poll cycle: indexer alerts -> findings/incidents (no model calls).

A cycle streams new alerts through :class:`WazuhAdapter.stream_alerts`
(checkpoint resume, overlap dedupe), attributes learned-rule findings
(:mod:`corvus.live.attribution`), appends new events and findings to
the live replay-format store (:mod:`corvus.live.store`, idempotent by
uid), correlates the whole store deterministically, upserts incidents
(learned-rule references included), and optionally pulls archive
context for each new incident. Every poll writes one
``wazuh_poll_cycles`` row with the counts, so the proof of
learned-rule findings never depends on log scraping.

Correlation windows come from the ``CORRELATION_*`` environment
variables with the :mod:`corvus.correlate` defaults as fallback, so
the poll never requires unrelated model settings to run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg

from corvus.adapters.replay.adapter import ReplayAdapter
from corvus.adapters.siem import Cursor
from corvus.adapters.wazuh.adapter import WazuhAdapter
from corvus.attack import load_dictionary
from corvus.correlate import Incident, correlate_findings
from corvus.correlate.correlate import (
    DEFAULT_AUTH_FAILURE_THRESHOLD,
    DEFAULT_MAX_SPAN,
    DEFAULT_SESSION_GAP,
)
from corvus.correlate.replay import (
    load_replay_events,
    load_replay_findings,
    referenced_event_uids,
)
from corvus.live.attribution import attribution_for_finding, learned_refs_for_uids
from corvus.live.store import append_live_records
from corvus.normalize.ocsf import DetectionFinding
from corvus.state.checkpoints import load_checkpoint
from corvus.state.incidents import stored_correlation_keys, upsert_incidents
from corvus.state.migrate import migrate

__all__ = [
    "PollCycleReport",
    "load_stored_rules",
    "resolve_windows",
    "run_poll_cycle",
]


@dataclass
class PollCycleReport:
    """Counts for one poll cycle (printed by the CLI, stored in the ledger)."""

    alerts_seen: int = 0
    events_written: int = 0
    findings_written: int = 0
    learned_findings: int = 0
    shadow_findings: int = 0
    unknown_learned: int = 0
    incidents_upserted: int = 0
    archives_added: int = 0
    archives_empty: bool = False
    incidents_total: int = 0
    learned_refs: list[dict[str, Any]] = field(default_factory=list)


def resolve_windows() -> tuple[timedelta, timedelta, int]:
    """Return (session gap, max span, auth threshold) from env or defaults."""

    def _int(name: str, default: int) -> int:
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            return default
        try:
            return int(raw.strip())
        except ValueError:
            raise ValueError(f"{name} must be an integer, got {raw!r}") from None

    gap_minutes = _int(
        "CORRELATION_SESSION_GAP_MINUTES",
        int(DEFAULT_SESSION_GAP.total_seconds() // 60),
    )
    span_hours = _int(
        "CORRELATION_MAX_SPAN_HOURS", int(DEFAULT_MAX_SPAN.total_seconds() // 3600)
    )
    threshold = _int(
        "CORRELATION_AUTH_FAILURE_THRESHOLD", DEFAULT_AUTH_FAILURE_THRESHOLD
    )
    if gap_minutes <= 0 or span_hours <= 0 or threshold < 0:
        raise ValueError("correlation windows must be positive (threshold >= 0)")
    return timedelta(minutes=gap_minutes), timedelta(hours=span_hours), threshold


def load_stored_rules(
    database_url: str,
) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Return stored rules keyed by native id and by Sigma id."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, native_rule_id, version, status, lineage FROM rules"
            )
            rows = cur.fetchall()
    assert rows is not None
    by_native: dict[int, dict[str, Any]] = {}
    by_sigma: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = {
            "id": int(row[0]),
            "native_rule_id": row[1],
            "version": int(row[2]),
            "status": str(row[3]),
            "lineage": dict(row[4] or {}),
        }
        if isinstance(record["native_rule_id"], int):
            by_native.setdefault(record["native_rule_id"], record)
        sigma_id = record["lineage"].get("sigma_rule_id")
        if isinstance(sigma_id, str) and sigma_id:
            by_sigma.setdefault(sigma_id, record)
    return by_native, by_sigma


def _record_cycle_start(database_url: str) -> int:
    """Insert the open cycle row; return its id (used as the store stem)."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO wazuh_poll_cycles (started_at) VALUES (NOW()) RETURNING id"
            )
            row = cur.fetchone()
        conn.commit()
    assert row is not None
    return int(row[0])


def _record_cycle_end(
    database_url: str, cycle_id: int, report: PollCycleReport
) -> None:
    """Close the cycle row with the final counts."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE wazuh_poll_cycles SET completed_at = NOW(),"
                " alerts_seen = %s, events_written = %s,"
                " findings_written = %s, learned_findings = %s,"
                " shadow_findings = %s, unknown_learned = %s,"
                " incidents_upserted = %s, archives_added = %s"
                " WHERE id = %s",
                (
                    report.alerts_seen,
                    report.events_written,
                    report.findings_written,
                    report.learned_findings,
                    report.shadow_findings,
                    report.unknown_learned,
                    report.incidents_upserted,
                    report.archives_added,
                    cycle_id,
                ),
            )
        conn.commit()


def run_poll_cycle(
    *,
    adapter: WazuhAdapter,
    database_url: str,
    store_dir: str | Path,
    attack_path: str | Path = "data/attack/enterprise.json",
    page_size: int = 500,
    max_docs: int = 5000,
    since_ms: int | None = None,
    with_archives: bool = False,
    archives_limit: int = 200,
) -> PollCycleReport:
    """Run one bounded poll cycle; return the counts.

    ``since_ms`` seeds the cursor only when no checkpoint is stored
    (a stored checkpoint always wins, so restarts resume). Archive
    context is fetched for new incidents only. No model is called:
    findings come from each alert's own rule block.
    """
    if page_size < 1 or page_size > 1000:
        raise ValueError(f"page_size must be 1..1000, got {page_size}")
    if max_docs < 1:
        raise ValueError(f"max_docs must be >= 1, got {max_docs}")
    if archives_limit < 1 or archives_limit > 200:
        raise ValueError(f"archives_limit must be 1..200, got {archives_limit}")
    migrate(database_url)
    session_gap, max_span, auth_threshold = resolve_windows()
    by_native, by_sigma = load_stored_rules(database_url)
    cycle_id = _record_cycle_start(database_url)
    report = PollCycleReport()

    cursor: Cursor | None = None
    if since_ms is not None and not load_checkpoint(database_url, "wazuh", "alerts"):
        cursor = Cursor(last_time=since_ms)
    new_findings: list[DetectionFinding] = []
    new_events: list[Any] = []
    provenance: dict[str, tuple[str, str]] = {}
    docs = 0
    while docs < max_docs:
        page, cursor = adapter.stream_alerts(
            since=cursor, page_size=min(page_size, max_docs - docs)
        )
        if not page:
            break
        provenance.update(adapter.last_provenance)
        for record in page:
            docs += 1
            if record.class_uid == 2004:
                assert isinstance(record, DetectionFinding)
                stamp = attribution_for_finding(record, by_native, by_sigma)
                report.alerts_seen += 1
                if stamp.get("resolved") and not stamp.get("unknown_learned_rule"):
                    report.learned_findings += 1
                if stamp.get("shadow"):
                    report.shadow_findings += 1
                if stamp.get("unknown_learned_rule"):
                    report.unknown_learned += 1
                new_findings.append(record)
            else:
                new_events.append(record)
            if docs >= max_docs:
                break
    if not new_findings and docs == 0:
        if with_archives:
            report.archives_empty = True
        _record_cycle_end(database_url, cycle_id, report)
        return report

    events = new_events
    finding_rows = [
        (
            finding,
            str(finding.finding_info.analytic.uid)
            if finding.finding_info and finding.finding_info.analytic
            else "",
            str(finding.severity_id),
            provenance.get(finding.metadata.uid or "", ("wazuh-alerts", ""))[0],
            provenance.get(finding.metadata.uid or "", ("wazuh-alerts", ""))[1],
        )
        for finding in new_findings
    ]
    event_rows = [
        (
            event,
            provenance.get(event.metadata.uid or "", ("wazuh-alerts", ""))[0],
            provenance.get(event.metadata.uid or "", ("wazuh-alerts", ""))[1],
        )
        for event in events
    ]
    wrote = append_live_records(
        store_dir, event_rows, finding_rows, stem=f"live-{cycle_id}"
    )
    report.events_written = wrote["events"]
    report.findings_written = wrote["findings"]

    dictionary = load_dictionary(attack_path)
    replay = ReplayAdapter(store_dir)
    findings = load_replay_findings(store_dir)
    findings_by_uid = {finding.metadata.uid or "": finding for finding in findings}
    gap_ms = int(session_gap.total_seconds() * 1000)
    if findings:
        start = min(finding.time for finding in findings) - gap_ms
        end = max(finding.time for finding in findings)
        events_by_uid = load_replay_events(
            store_dir, replay, referenced_event_uids(findings), start, end
        )
    else:
        events_by_uid = {}
    incidents = correlate_findings(
        findings,
        events_by_uid,
        dictionary,
        session_gap=session_gap,
        max_span=max_span,
        auth_failure_threshold=auth_threshold,
    )
    for incident in incidents:
        incident["learned_rules"] = learned_refs_for_uids(
            [str(uid) for uid in incident.get("event_uids") or []], findings_by_uid
        )
    known_keys = stored_correlation_keys(database_url)
    fresh = [
        incident
        for incident in incidents
        if incident["correlation_key"] not in known_keys
    ]
    upsert_incidents(database_url, incidents)
    report.incidents_total = len(incidents)
    report.incidents_upserted = len(fresh)
    for incident in fresh:
        refs = incident.get("learned_rules") or []
        report.learned_refs.extend(refs)

    if with_archives and fresh:
        report.archives_added = _fetch_archive_context(
            adapter,
            store_dir,
            fresh,
            gap_ms,
            archives_limit,
        )
        report.archives_empty = report.archives_added == 0
    elif with_archives:
        report.archives_empty = True
    _record_cycle_end(database_url, cycle_id, report)
    return report


def _fetch_archive_context(
    adapter: WazuhAdapter,
    store_dir: str | Path,
    incidents: list[Incident],
    gap_ms: int,
    archives_limit: int,
) -> int:
    """Fetch surrounding archive events for new incidents; return added."""
    from corvus.adapters.siem import Entity

    added = 0
    for incident in incidents:
        entity_keys = incident.get("entity_keys") or {}
        hosts = entity_keys.get("hosts") or []
        if not hosts:
            continue
        try:
            entity = Entity(host=str(hosts[0]))
        except ValueError:
            continue
        start = int(incident["first_seen"]) - gap_ms
        end = int(incident["last_seen"]) + gap_ms
        try:
            context = adapter.query_events(
                entity, start=start, end=end, limit=archives_limit
            )
        except Exception:
            continue
        rows = [
            (
                event,
                adapter.last_archive_provenance.get(
                    event.metadata.uid or "", ("wazuh-archives", "")
                )[0],
                adapter.last_archive_provenance.get(
                    event.metadata.uid or "", ("wazuh-archives", "")
                )[1],
            )
            for event in context
        ]
        wrote = append_live_records(
            store_dir, rows, [], stem=f"live-arch-{incident['correlation_key'][:16]}"
        )
        added += wrote["events"]
    return added
