"""Correlate replay findings into deterministic incidents.

Loads every Detection Finding from the replay store, the referenced
OCSF events they point at, plus every Authentication event overlapping
the findings' time range (padded by the session gap): detection rules
rarely match each failed logon, so factor 4 only sees the failures it
is given. The session gap, max span and failure threshold come from
:func:`corvus.settings.get_settings`, so environment overrides apply
(the module defaults in :mod:`corvus.correlate` only mirror the
Settings field defaults). Output is the plain incident dicts
:func:`corvus.correlate.correlate_findings` returns; persisting them
is the caller's job (see :mod:`corvus.state.incidents`).
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pyarrow.parquet as pq
from pydantic import TypeAdapter

from corvus.adapters.replay.schema import events_dir, findings_dir
from corvus.adapters.siem import MAX_QUERY_LIMIT
from corvus.normalize.ocsf import DetectionFinding, OcsfEvent

if TYPE_CHECKING:
    from corvus.adapters.replay.adapter import ReplayAdapter
    from corvus.attack.dictionary import AttackDictionary
    from corvus.correlate.correlate import Incident
    from corvus.settings import Settings

__all__ = [
    "correlate_replay_store",
    "load_replay_events",
    "load_replay_findings",
    "referenced_event_uids",
]

#: Rehydrates one stored ``finding_json`` back into a finding.
_FINDING_ADAPTER = TypeAdapter(DetectionFinding)

#: Rehydrates one stored ``event_json`` back into the OCSF union.
_EVENT_ADAPTER = TypeAdapter(OcsfEvent)

#: OCSF class for Authentication (the factor-4 context scan).
_AUTH_CLASS_UID = 3002


def load_replay_findings(replay_dir: str | Path) -> list[DetectionFinding]:
    """Load every Detection Finding stored under ``findings/``."""
    directory = findings_dir(replay_dir)
    findings: list[DetectionFinding] = []
    if not Path(directory).is_dir():
        return findings
    for path in sorted(Path(directory).glob("*.parquet")):
        for record in pq.read_table(path).to_pylist():
            findings.append(_FINDING_ADAPTER.validate_json(record["finding_json"]))
    return findings


def referenced_event_uids(findings: list[DetectionFinding]) -> set[str]:
    """Collect the event uids findings reference (lineage + relations)."""
    uids: set[str] = set()
    for finding in findings:
        if finding.finding_info and finding.finding_info.related_events:
            for related in finding.finding_info.related_events:
                if related.uid:
                    uids.add(related.uid)
        for evidence in finding.evidences or []:
            if evidence.uid:
                uids.add(evidence.uid)
    return uids


def _load_referenced_events(
    replay_dir: str | Path, uids: set[str]
) -> dict[str, OcsfEvent]:
    """Load stored events by uid (the public query contract has no uid filter).

    Streams the ``events/`` tables file by file and keeps only the
    referenced rows, so the whole store is never held in memory.
    """
    wanted = set(uids)
    events: dict[str, OcsfEvent] = {}
    directory = events_dir(replay_dir)
    if not Path(directory).is_dir() or not wanted:
        return events
    for path in sorted(Path(directory).glob("*.parquet")):
        table = pq.read_table(path, columns=["uid", "event_json"])
        for record in table.to_pylist():
            uid = str(record["uid"])
            if uid in wanted and uid not in events:
                events[uid] = _EVENT_ADAPTER.validate_json(record["event_json"])
        if len(events) == len(wanted):
            break
    return events


def _load_auth_events(
    adapter: ReplayAdapter, start: int, end: int
) -> dict[str, OcsfEvent]:
    """Page every Authentication event in ``[start, end]`` via the adapter.

    Uses the public ``SiemAdapter.query_events`` contract (``limit`` <=
    200), advancing the window past each full page. Assumes fewer than
    one page of stored events shares a single millisecond timestamp;
    the census checks this against the current store.
    """
    events: dict[str, OcsfEvent] = {}
    cursor = start
    while cursor <= end:
        page = adapter.query_events(
            start=cursor, end=end, classes=[_AUTH_CLASS_UID], limit=MAX_QUERY_LIMIT
        )
        for event in page:
            uid = event.metadata.uid or ""
            if uid and uid not in events:
                events[uid] = event
        if len(page) < MAX_QUERY_LIMIT:
            break
        last = page[-1].time
        cursor = last + 1 if last <= cursor else last
    return events


def load_replay_events(
    replay_dir: str | Path,
    adapter: ReplayAdapter,
    uids: set[str],
    start: int,
    end: int,
) -> dict[str, OcsfEvent]:
    """Load referenced events plus Authentication events in ``[start, end]``."""
    events = _load_referenced_events(replay_dir, uids)
    for uid, event in _load_auth_events(adapter, start, end).items():
        events.setdefault(uid, event)
    return events


def correlate_replay_store(
    replay_dir: str | Path = "data/replay",
    attack_path: str | Path = "data/attack/enterprise.json",
    settings: Settings | None = None,
    attack: AttackDictionary | None = None,
) -> list[Incident]:
    """Correlate every replay finding into candidate incidents.

    The Authentication context window is the findings' time range
    padded below by the session gap, so factor 4 sees failures just
    before the first finding of each incident.
    """
    from corvus.attack import load_dictionary
    from corvus.correlate import correlate_findings
    from corvus.settings import get_settings

    resolved = settings if settings is not None else get_settings()
    session_gap = timedelta(minutes=resolved.correlation_session_gap_minutes)
    max_span = timedelta(hours=resolved.correlation_max_span_hours)
    threshold = resolved.correlation_auth_failure_threshold
    dictionary = attack if attack is not None else load_dictionary(attack_path)
    findings = load_replay_findings(replay_dir)
    if not findings:
        return []
    gap_ms = int(session_gap.total_seconds() * 1000)
    start = min(finding.time for finding in findings) - gap_ms
    end = max(finding.time for finding in findings)
    from corvus.adapters.replay.adapter import ReplayAdapter

    adapter = ReplayAdapter(replay_dir)
    events = load_replay_events(
        replay_dir, adapter, referenced_event_uids(findings), start, end
    )
    return correlate_findings(
        findings,
        events,
        dictionary,
        session_gap=session_gap,
        max_span=max_span,
        auth_failure_threshold=threshold,
    )
