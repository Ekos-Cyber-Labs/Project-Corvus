"""Glimmer triage worker over the durable work queue.

One ``"triage"`` job per incident without a triage analysis. Each job
runs: claim (by the loop) -> load evidence (events plus findings) ->
injection-signal scan over the full records (persisted, review flag
reconciled, signals handed to the call) -> project to bounded
evidence and select under the input cap -> heartbeat in a background
thread while the model runs ->
:func:`corvus.llm.call.call_model` with the
:class:`corvus.llm.schemas.CondensedIncident` schema -> store one row
in ``incident_analyses`` (stage ``"triage"``) -> complete. A
context-overflow 400 shrinks the evidence budget once for the next
try via the selection callback.

Lease discipline: a cluster can take 1-1.5 minutes while the queue
lease defaults to 60 s, so the heartbeat fires every ``lease / 3``.
A lost heartbeat (``False`` or an error) means another worker may own
the job: this worker stops and writes nothing. Delivery is
at-least-once, so the analysis upsert is idempotent on
``(incident_id, stage)`` and a redelivered job leaves exactly one row.

Outcome mapping (never silently benign):

- ``resolved`` -> analysis ``resolved``; incident ``ai_status``
  ``done``.
- ``indeterminate`` / ``ai_failed`` / ``quarantined`` -> stored with
  that status; incident ``ai_status`` ``failed`` and
  ``review_required`` (stays open and visible, escalated).
- ``pending_ai`` (spend cap refused) -> no analysis row; the job
  fails back onto the queue with backoff.
- no evidence at all -> analysis ``unprocessed``; escalated like
  above.
- unexpected exception -> the job fails back onto the queue; nothing
  is stored.

Concurrency is a thread pool sized by the serving backend's
configured concurrency (default 16). SIGTERM/SIGINT stop new claims;
in-flight jobs finish before the loop returns.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from corvus.llm.call import CallContext, call_model
from corvus.llm.prompts.triage import (
    EvidenceSelection,
    build_system_message,
    build_triage_messages,
    estimate_tokens,
    group_findings,
    measure_framing_tokens,
    project_event,
    resolve_reasoning_strength,
    select_evidence,
)
from corvus.llm.schemas import CondensedIncident
from corvus.state.queue import Job, WorkQueue, heartbeat_interval_for

__all__ = [
    "TRIAGE_JOB_KIND",
    "TriageIncident",
    "enqueue_triage_jobs",
    "load_replay_events_by_uid",
    "process_incident_triage",
    "process_job",
    "run_loop",
]

_log = logging.getLogger(__name__)

#: Work-queue kind this worker claims.
TRIAGE_JOB_KIND = "triage"

#: Dedupe-key version: bump to deliberately re-triage an incident
#: (keys stay taken after done/dead, so a re-run needs a new key).
DEDUPE_VERSION = "v1"


@dataclass(frozen=True)
class TriageIncident:
    """The incident row a triage job condenses."""

    id: int
    correlation_key: str
    title: str
    severity_floor: int
    techniques: tuple[str, ...]
    event_uids: tuple[str, ...]


def _dedupe_key(incident_id: int) -> str:
    return f"triage:incident:{incident_id}:{DEDUPE_VERSION}"


def _resolve_lease(lease_seconds: float | None, backend: Any) -> float:
    """Return the queue lease for one claim.

    An explicit override wins; otherwise the lease follows the
    purpose's read timeout, so a legitimate slow prefill on the
    single on-prem GPU is never cut by lease sizing. The heartbeat
    (one third of the lease) keeps extending it while the model
    runs.
    """
    if lease_seconds is not None:
        return lease_seconds
    return float(backend.read_timeout_seconds)


def read_incident(database_url: str, incident_id: int) -> TriageIncident | None:
    """Return the incident row for ``incident_id``, or None."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, correlation_key, title, severity_floor,"
                " techniques, event_uids FROM incidents WHERE id = %s",
                (incident_id,),
            )
            row = cur.fetchone()
    if row is None:
        return None
    techniques = row[4] or []
    event_uids = row[5] or []
    return TriageIncident(
        id=int(row[0]),
        correlation_key=str(row[1]),
        title=str(row[2] or ""),
        severity_floor=int(row[3]),
        techniques=tuple(str(item) for item in techniques),
        event_uids=tuple(str(item) for item in event_uids),
    )


def enqueue_triage_jobs(
    database_url: str,
    *,
    limit: int | None = None,
    incident_ids: Sequence[int] | None = None,
    min_floor: int | None = None,
) -> list[int]:
    """Enqueue one ``triage`` job per incident lacking a triage analysis.

    With ``incident_ids`` only those incidents are considered (each
    must be an int; an empty list enqueues nothing), so an
    incident-scoped runner never creates jobs for other incidents.
    With ``min_floor`` only incidents at or above that severity floor
    are considered (1-6; anything else raises). Both filters compose:
    the eval harness passes the selected ids plus the floor so a
    re-run never enqueues incidents outside the selection.
    Returns the job ids (existing dedupe keys return their original
    job id, so re-running enqueue never duplicates work).
    """
    queue = WorkQueue(database_url)
    query = (
        "SELECT i.id FROM incidents i"
        " LEFT JOIN incident_analyses a ON a.incident_id = i.id"
        " AND a.stage = 'triage'"
        " WHERE a.incident_id IS NULL"
    )
    params: list[Any] = []
    if min_floor is not None:
        if isinstance(min_floor, bool) or not isinstance(min_floor, int):
            raise ValueError(f"min_floor must be an int, got {min_floor!r}")
        if not 1 <= min_floor <= 6:
            raise ValueError(f"min_floor must be 1..6, got {min_floor!r}")
        query += " AND i.severity_floor >= %s"
        params.append(min_floor)
    if incident_ids is not None:
        wanted: list[int] = []
        for incident_id in incident_ids:
            if isinstance(incident_id, bool) or not isinstance(incident_id, int):
                raise ValueError(f"incident_ids must hold ints, got {incident_id!r}")
            wanted.append(incident_id)
        if not wanted:
            return []
        query += " AND i.id = ANY(%s)"
        params.append(wanted)
    query += " ORDER BY i.id ASC"
    if limit is not None:
        query += " LIMIT %s"
        params.append(limit)
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, tuple(params))
            missing = [int(row[0]) for row in cur.fetchall()]
    job_ids: list[int] = []
    for incident_id in missing:
        job_ids.append(
            queue.enqueue(
                TRIAGE_JOB_KIND,
                {"incident_id": incident_id},
                dedupe_key=_dedupe_key(incident_id),
            )
        )
    return job_ids


def _load_uid_table(
    directory: Path,
    wanted: set[str],
    found: dict[str, dict[str, Any]],
    *,
    payload_column: str,
    flat_columns: Sequence[str],
) -> None:
    """Row-group pushdown load of one uid-keyed Parquet table.

    Per row group only the ``uid`` column is read first; the wide
    payload column (plus the listed flat columns) is read only for
    row groups holding a still-wanted row. Adds new uids to
    ``found``; when several files hold the same uid, the
    alphabetically first file wins. Each row becomes a small mapping
    with the uid, epoch-millisecond time, class uid, the flat
    columns, and the parsed stored record under ``data``.
    """
    import pyarrow.parquet as pq

    columns = ["uid", "time", "class_uid", *flat_columns, payload_column]
    for path in sorted(directory.glob("*.parquet")):
        if len(found) == len(wanted):
            break
        parquet_file = pq.ParquetFile(path)
        try:
            for group in range(parquet_file.metadata.num_row_groups):
                if len(found) == len(wanted):
                    break
                uid_table = parquet_file.read_row_group(group, columns=["uid"])
                group_uids = {
                    str(value) for value in uid_table.column("uid").to_pylist()
                }
                if not (group_uids & (wanted - set(found))):
                    continue
                table = parquet_file.read_row_group(group, columns=columns)
                for record in table.to_pylist():
                    uid = str(record["uid"])
                    if uid in wanted and uid not in found:
                        row: dict[str, Any] = {
                            "event_uid": uid,
                            "time": int(record["time"]),
                            "class_uid": int(record["class_uid"]),
                            "data": json.loads(str(record[payload_column])),
                        }
                        for column in flat_columns:
                            row[column] = record.get(column)
                        found[uid] = row
        finally:
            parquet_file.close()


def load_replay_events_by_uid(
    replay_dir: str | Path, uids: Sequence[str]
) -> list[dict[str, Any]]:
    """Load incident evidence from the replay Parquet store by uid.

    Reads both the ``events/`` table (uid, time, class, host, user,
    IP columns plus the full OCSF record) and the ``findings/``
    table (uid, time, class 2004, rule id, level, host plus the full
    finding record), each with the row-group pushdown of
    :func:`_load_uid_table`. The incident's ``event_uids`` hold both
    event and finding uids, so without the findings table the
    detections would never reach the model. When several files hold
    the same uid, the alphabetically first file wins.
    """
    from corvus.adapters.replay.schema import events_dir, findings_dir

    wanted = set(uids)
    if not wanted:
        return []
    found: dict[str, dict[str, Any]] = {}
    events_directory = Path(events_dir(replay_dir))
    if events_directory.is_dir():
        _load_uid_table(
            events_directory,
            wanted,
            found,
            payload_column="event_json",
            flat_columns=("host", "user", "ip", "src_ip", "dst_ip"),
        )
    findings_directory = Path(findings_dir(replay_dir))
    if findings_directory.is_dir():
        _load_uid_table(
            findings_directory,
            wanted,
            found,
            payload_column="finding_json",
            flat_columns=("rule_id", "level", "host"),
        )
    return [found[uid] for uid in wanted if uid in found]


def _resolve_valid_techniques(
    incident_techniques: Sequence[str],
) -> set[str] | None:
    """Prefer the ATT&CK dictionary; fall back to incident techniques.

    The dictionary file may be absent where only the database is
    available (tests); then the incident's own technique list scopes
    the check instead of failing the call before it starts.
    """
    try:
        from corvus.attack import load_dictionary

        load_dictionary()
    except OSError, ValueError:
        return {str(item) for item in incident_techniques}
    return None


class _Heartbeat:
    """Background lease heartbeat for one running job.

    Fires every ``interval_seconds`` (``lease / 3`` per the queue
    contract). :attr:`alive` turns False on the first failed or
    erroring heartbeat; the worker must then stop and write nothing.
    """

    def __init__(
        self,
        database_url: str,
        job_id: int,
        worker_id: str,
        lease_seconds: float,
        interval_seconds: float,
    ) -> None:
        self._database_url = database_url
        self._job_id = job_id
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def alive(self) -> bool:
        """False once a heartbeat failed: the lease is lost."""
        return not self._lost.is_set()

    def start(self) -> None:
        """Start the daemon heartbeat thread."""
        thread = threading.Thread(
            target=self._run, name=f"triage-heartbeat-{self._job_id}", daemon=True
        )
        self._thread = thread
        thread.start()

    def _run(self) -> None:
        queue = WorkQueue(self._database_url)
        while not self._stop.wait(self._interval):
            try:
                owned = queue.heartbeat(
                    self._job_id, self._worker_id, self._lease_seconds
                )
            except Exception as exc:
                # Lease state is unknown: treat as lost (the worker
                # stops and writes nothing), but say so. Job id and
                # exception type only — never message text.
                _log.warning(
                    "triage heartbeat for job %s failed: %s",
                    self._job_id,
                    type(exc).__name__,
                )
                owned = False
            if not owned:
                self._lost.set()
                return

    def stop(self) -> None:
        """Stop the thread (no-op when it already exited)."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(1.0, self._interval))


def _has_resolved_analysis(database_url: str, incident_id: int, stage: str) -> bool:
    """True when ``(incident, stage)`` already stores a ``resolved`` row."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM incident_analyses"
                " WHERE incident_id = %s AND stage = %s AND status = 'resolved'",
                (incident_id, stage),
            )
            return cur.fetchone() is not None


def _store_analysis(
    database_url: str,
    incident: TriageIncident,
    stage: str,
    status: str,
    payload: Mapping[str, Any],
    language: str | None,
    model: str | None,
) -> None:
    """Upsert the ``(incident, stage)`` analysis row (idempotent).

    The upsert never downgrades a stored ``resolved`` row: the
    conflicting update applies only while the stored status is not
    ``resolved``, so a slow redelivery that ends non-resolved cannot
    overwrite a success that landed first. Incident flags follow the
    status actually stored, read back in the same transaction.
    """
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incident_analyses (incident_id, stage, status,"
                " payload, language, model, deterministic_floor)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (incident_id, stage) DO UPDATE SET"
                " status = EXCLUDED.status, payload = EXCLUDED.payload,"
                " language = EXCLUDED.language, model = EXCLUDED.model,"
                " deterministic_floor = EXCLUDED.deterministic_floor,"
                " created_at = NOW()"
                " WHERE incident_analyses.status <> 'resolved'",
                (
                    incident.id,
                    stage,
                    status,
                    Jsonb(dict(payload)),
                    language,
                    model,
                    incident.severity_floor,
                ),
            )
            cur.execute(
                "SELECT status FROM incident_analyses"
                " WHERE incident_id = %s AND stage = %s",
                (incident.id, stage),
            )
            row = cur.fetchone()
            stored = str(row[0]) if row is not None else status
            if stored == "resolved":
                cur.execute(
                    "UPDATE incidents SET ai_status = 'done',"
                    " updated_at = NOW() WHERE id = %s",
                    (incident.id,),
                )
            else:
                cur.execute(
                    "UPDATE incidents SET ai_status = 'failed',"
                    " review_required = TRUE, updated_at = NOW()"
                    " WHERE id = %s",
                    (incident.id,),
                )
        conn.commit()


def _fail_job(database_url: str, job_id: int, worker_id: str, error: str) -> None:
    WorkQueue(database_url).fail(job_id, worker_id, error)


def process_job(
    job: Job,
    *,
    database_url: str,
    worker_id: str,
    lease_seconds: float | None = None,
    heartbeat_interval: float | None = None,
    backend_override: Any = None,
    prices: Mapping[str, Any] | None = None,
    evidence_loader: (Callable[[TriageIncident], list[dict[str, Any]]] | None) = None,
    replay_dir: str | Path = "data/replay",
    reasoning_strength: str | None = None,
    purpose: str = TRIAGE_JOB_KIND,
    call_id: str | None = None,
) -> str:
    """Run one triage job to completion; return the outcome status.

    The model is reached only through :func:`corvus.llm.call.call_model`
    (this module never drives transport itself). Returns ``resolved``,
    ``indeterminate``, ``ai_failed``, ``quarantined``, ``pending_ai``,
    ``unprocessed`` (stored, job done), ``failed`` (job failed back
    onto the queue, nothing stored) or ``lease_lost`` (heartbeat died
    mid-call: nothing stored, nothing completed, the lease reclaim
    re-runs the job).

    The backend resolves first so the lease can follow the purpose's
    read timeout (a legitimate slow prefill must not be cut); then
    the heartbeat starts and stops in a ``finally``. Any unexpected
    exception after the claim fails the job back onto the queue
    (error text carries the stage and the exception type, never
    secrets or message text) and returns ``failed``, so no job is
    left orphaned ``locked``. A redelivery for an already-``resolved``
    ``(incident, stage)`` row completes without any model call.
    """
    queue = WorkQueue(database_url)
    raw_id = job.payload.get("incident_id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int):
        _fail_job(database_url, job.id, worker_id, "triage payload lacks incident_id")
        return "failed"
    incident = read_incident(database_url, raw_id)
    if incident is None:
        _fail_job(database_url, job.id, worker_id, "triage incident not found")
        return "failed"
    if _has_resolved_analysis(database_url, incident.id, purpose):
        # Redelivery after success: no model call, no spend, the
        # single existing row stands.
        queue.complete(job.id, worker_id)
        return "resolved"
    try:
        if backend_override is not None:
            backend = backend_override
        else:
            from corvus.llm.config import get_backend

            backend = get_backend(purpose)
    except Exception as exc:
        _fail_job(
            database_url,
            job.id,
            worker_id,
            f"triage backend failed: {type(exc).__name__}",
        )
        return "failed"
    lease = _resolve_lease(lease_seconds, backend)
    if heartbeat_interval is None:
        # Honor the actually granted lease, never just ``lease``: this
        # job may have been claimed elsewhere with less (a fire exactly
        # at expiry already loses the lease).
        heartbeat_interval = heartbeat_interval_for(job, lease)
    heartbeat = _Heartbeat(
        database_url,
        job.id,
        worker_id,
        lease,
        heartbeat_interval,
    )
    heartbeat.start()
    stage = "start"
    try:
        stage = "backend"
        strength = resolve_reasoning_strength(reasoning_strength)

        stage = "evidence"
        loader = evidence_loader
        if loader is None:

            def loader(found: TriageIncident) -> list[dict[str, Any]]:
                return load_replay_events_by_uid(replay_dir, list(found.event_uids))

        full_items = [event for event in loader(incident) if isinstance(event, Mapping)]
        full_findings = [
            event for event in full_items if event.get("class_uid") == 2004
        ]
        full_events = [event for event in full_items if event.get("class_uid") != 2004]
        # Injection scan at evidence-load time (the documented worker
        # moment) runs over the FULL stored records — never the
        # truncated projections below — so a payload hidden past a
        # truncation cut is still flagged and persisted. The same
        # signals plus the normalized field texts go to the call so
        # validator 5 can quarantine an output that echoes injected
        # payload text. The triage schema carries no verdict or severity,
        # so the verbatim-echo check is the live one on this path.
        stage = "scan"
        from corvus.guardrails.injection import scan_events, scan_incident

        scan_map: dict[str, Any] = {}
        for event in full_items:
            uid = event.get("event_uid")
            if not isinstance(uid, str) or not uid:
                continue
            data = event.get("data")
            scan_map[uid] = data if isinstance(data, Mapping) else event
        scan_incident(database_url, incident.id, scan_map)
        injection_signals, payload_texts = scan_events(scan_map)
        stage = "selection"
        # The model sees bounded projections, not full OCSF records:
        # one group line per (rule_id, host) for findings, one
        # projected line per event.
        groups = group_findings(full_findings)
        event_projs = [project_event(item) for item in full_events]
        findings_total = sum(group.count for group in groups)
        input_cap = backend.max_input_tokens
        system_text = build_system_message(strength)
        incident_meta = {
            "correlation_key": incident.correlation_key,
            "title": incident.title,
            "severity_floor": incident.severity_floor,
            "technique_count": len(incident.techniques),
        }
        # The measured system prefix is the floor of the reservation;
        # framing only adds to it.
        reserved = estimate_tokens(system_text)
        provisional = select_evidence(
            groups,
            event_projs,
            max_input_tokens=input_cap,
            reserved_tokens=reserved,
        )
        reserved = estimate_tokens(system_text) + measure_framing_tokens(
            incident_meta,
            provisional,
            input_cap,
            findings_total=findings_total,
            groups_total=len(groups),
        )
        selection = select_evidence(
            groups,
            event_projs,
            max_input_tokens=input_cap,
            reserved_tokens=reserved,
        )

        def _shown_count(sel: EvidenceSelection) -> int:
            return sum(group.count for group in sel.findings.included)

        if (
            findings_total + selection.events.total == 0
            or not selection.findings.included
            and not selection.events.included
        ):
            _store_analysis(
                database_url,
                incident,
                purpose,
                "unprocessed",
                {
                    "note": "no evidence available under the input-token cap",
                    "total_findings": findings_total,
                    "included_findings": 0,
                    "omitted_findings": findings_total,
                    "groups_total": len(groups),
                    "groups_included": 0,
                    "total_events": selection.events.total,
                    "included_events": 0,
                    "omitted_events": selection.events.omitted,
                },
                "en",
                None,
            )
            queue.complete(job.id, worker_id)
            return "unprocessed"

        stage = "model-call"

        def _build_raw_payload(sel: EvidenceSelection) -> dict[str, Any]:
            return {
                "incident": {
                    **incident_meta,
                    "findings_count": findings_total,
                    "groups_count": len(groups),
                    "event_count": sel.events.total,
                },
                "included_findings": [group.line() for group in sel.findings.included],
                "total_findings": findings_total,
                "groups_total": len(groups),
                "included_events": [dict(item) for item in sel.events.included],
                "omitted_events": sel.events.omitted,
                "total_events": sel.events.total,
                "input_token_cap": input_cap,
            }

        evidence_budget = input_cap - reserved
        active: dict[str, Any] = {
            "selection": selection,
            "payload": _build_raw_payload(selection),
        }

        def _reselect(factor: float) -> Any | None:
            """Shrink the evidence budget once after a context overflow.

            Re-runs the deterministic selection on the same ranked
            pools with a scaled budget. Returns None when the
            selection would not change, so the caller retries
            identically-sized input only via the generic path.
            """
            shrunk = select_evidence(
                groups,
                event_projs,
                max_input_tokens=reserved + int(evidence_budget * factor),
                reserved_tokens=reserved,
            )
            old_keys = [
                (group.rule_id, group.host) for group in selection.findings.included
            ] + [str(item.get("uid")) for item in selection.events.included]
            new_keys = [
                (group.rule_id, group.host) for group in shrunk.findings.included
            ] + [str(item.get("uid")) for item in shrunk.events.included]
            if new_keys == old_keys:
                return None
            active["selection"] = shrunk
            active["payload"] = _build_raw_payload(shrunk)
            return active["payload"]

        raw_payload = active["payload"]
        context = CallContext(
            event_uids=list(incident.event_uids),
            deterministic_floor=incident.severity_floor,
            language="en",
            valid_techniques=_resolve_valid_techniques(incident.techniques),
            injection_signals=injection_signals,
            payload_texts=payload_texts,
            payload=raw_payload,
            deterministic_value={"note": "AI analysis failed"},
            incident_id=incident.id,
            database_url=database_url,
        )

        def _builder(prepared: Any) -> list[dict[str, str]]:
            return build_triage_messages(prepared, reasoning_strength=strength)

        outcome = call_model(
            purpose,
            _builder,
            CondensedIncident,
            context,
            database_url=database_url,
            prices=prices,  # type: ignore[arg-type]
            backend_override=backend,
            reasoning_strength=strength,
            call_id=call_id,
            reselect_payload=_reselect,
        )
        if not heartbeat.alive:
            return "lease_lost"
        # Final ownership check before any write: the lease may have
        # expired while the model ran (no heartbeat fired). A False here
        # means another worker may own the job, so write nothing; the
        # lease reclaim re-runs it. A True also extends the lease across
        # the store + complete writes below.
        if not queue.heartbeat(job.id, worker_id, lease):
            return "lease_lost"

        if outcome.status == "pending_ai":
            _fail_job(database_url, job.id, worker_id, "spend cap refused triage call")
            return "pending_ai"
        selection = active["selection"]
        if outcome.status == "resolved":
            condensed = outcome.value
            assert condensed is not None
            payload: dict[str, Any] = {
                "condensed": condensed.model_dump(),
                "included_findings": _shown_count(selection),
                "omitted_findings": findings_total - _shown_count(selection),
                "total_findings": findings_total,
                "groups_total": len(groups),
                "groups_included": len(selection.findings.included),
                "included_events": len(selection.events.included),
                "omitted_events": selection.events.omitted,
                "total_events": selection.events.total,
                "model": outcome.model,
            }
            _store_analysis(
                database_url,
                incident,
                purpose,
                "resolved",
                payload,
                "en",
                outcome.model,
            )
            queue.complete(job.id, worker_id)
            return "resolved"
        payload = {
            "note": f"triage ended {outcome.status}",
            "errors": list(outcome.errors),
            "error_codes": list(outcome.error_codes),
            "included_findings": _shown_count(selection),
            "omitted_findings": findings_total - _shown_count(selection),
            "total_findings": findings_total,
            "groups_total": len(groups),
            "groups_included": len(selection.findings.included),
            "included_events": len(selection.events.included),
            "omitted_events": selection.events.omitted,
            "total_events": selection.events.total,
            "model": outcome.model,
        }
        _store_analysis(
            database_url,
            incident,
            purpose,
            outcome.status,
            payload,
            "en",
            outcome.model,
        )
        queue.complete(job.id, worker_id)
        return outcome.status
    except Exception as exc:
        _fail_job(
            database_url,
            job.id,
            worker_id,
            f"triage {stage} failed: {type(exc).__name__}",
        )
        return "failed"
    finally:
        heartbeat.stop()


def process_incident_triage(
    database_url: str,
    incident_id: int,
    *,
    lease_seconds: float | None = None,
    replay_dir: str | Path = "data/replay",
    reasoning_strength: str | None = None,
    prices: Mapping[str, Any] | None = None,
    evidence_loader: (Callable[[TriageIncident], list[dict[str, Any]]] | None) = None,
    purpose: str = TRIAGE_JOB_KIND,
    worker_id: str | None = None,
    backend_override: Any = None,
) -> str:
    """Triage exactly one incident; return the outcome status.

    Enqueues a triage job only for ``incident_id`` (nothing is
    created for other incidents), claims exactly that job, and runs
    it through :func:`process_job`. Returns ``resolved`` at once when
    the incident already has a resolved triage, ``busy`` when its job
    is not claimable (another worker holds it), and the
    :func:`process_job` status otherwise. Raises :class:`ValueError`
    for a non-int incident id; backend misconfiguration propagates
    (no attempts are burned before the backend resolves).
    """
    if isinstance(incident_id, bool) or not isinstance(incident_id, int):
        raise ValueError(f"incident_id must be an int, got {incident_id!r}")
    if _has_resolved_analysis(database_url, incident_id, purpose):
        return "resolved"
    job_ids = enqueue_triage_jobs(database_url, incident_ids=[incident_id])
    if not job_ids:
        return "failed"
    if backend_override is not None:
        backend = backend_override
    else:
        from corvus.llm.config import get_backend

        backend = get_backend(purpose)
    lease = _resolve_lease(lease_seconds, backend)
    queue = WorkQueue(database_url)
    queue.reclaim_expired_leases()
    active_worker = worker_id or f"triage-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    job = queue.claim_job(job_ids[0], active_worker, lease_seconds=lease)
    if job is None:
        return "busy"
    return process_job(
        job,
        database_url=database_url,
        worker_id=active_worker,
        lease_seconds=lease_seconds,
        backend_override=backend,
        prices=prices,
        evidence_loader=evidence_loader,
        replay_dir=replay_dir,
        reasoning_strength=reasoning_strength,
        purpose=purpose,
    )


def _install_sigterm_handler(stop: threading.Event) -> dict[int, Any]:
    """Set SIGTERM/SIGINT to mark ``stop``; return the old handlers."""

    def _handle(signum: int, _frame: Any) -> None:
        stop.set()

    old: dict[int, Any] = {
        sig: signal.signal(sig, _handle) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    return old


def run_loop(
    database_url: str,
    *,
    purpose: str = TRIAGE_JOB_KIND,
    limit: int | None = None,
    concurrency: int | None = None,
    lease_seconds: float | None = None,
    replay_dir: str | Path = "data/replay",
    reasoning_strength: str | None = None,
    stop_event: threading.Event | None = None,
    install_handlers: bool = True,
    prices: Mapping[str, Any] | None = None,
    evidence_loader: (Callable[[TriageIncident], list[dict[str, Any]]] | None) = None,
) -> dict[str, int]:
    """Claim and run triage jobs until empty, limited, or stopped.

    Reclaims expired leases once at startup so a previous stopped run
    resumes instead of restarting. Returns outcome counts by status.
    SIGTERM/SIGINT (when ``install_handlers``) stop new claims while
    in-flight jobs finish. An unset ``lease_seconds`` follows the
    purpose's read timeout (see :func:`_resolve_lease`).

    Claims happen inside the worker threads — one claim per free
    slot — so a claimed job is always running now and never burns
    its lease waiting in a pool queue. ``limit`` caps the total
    number of claims. After a stop, unclaimed jobs stay ``pending``.
    """
    from corvus.llm.config import get_backend

    backend = get_backend(purpose)
    workers = concurrency if concurrency is not None else backend.concurrency
    if workers < 1:
        raise ValueError(f"concurrency must be at least 1, got {workers!r}")
    lease = _resolve_lease(lease_seconds, backend)
    stop = stop_event if stop_event is not None else threading.Event()
    if install_handlers:
        _install_sigterm_handler(stop)
    worker_id = f"triage-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    queue = WorkQueue(database_url)
    reclaimed = queue.reclaim_expired_leases()
    counts: Counter[str] = Counter({"reclaimed": reclaimed})
    lock = threading.Lock()
    claimed = 0

    def _run_claimed() -> None:
        """Claim one job per free slot and run it, until stopped."""
        nonlocal claimed
        while True:
            if stop.is_set():
                return
            with lock:
                if limit is not None and claimed >= limit:
                    return
                claimed += 1
            job = queue.claim(worker_id, kinds=[purpose], lease_seconds=lease)
            if job is None:
                return
            try:
                status = process_job(
                    job,
                    database_url=database_url,
                    worker_id=worker_id,
                    lease_seconds=lease,
                    prices=prices,
                    evidence_loader=evidence_loader,
                    replay_dir=replay_dir,
                    reasoning_strength=reasoning_strength,
                    purpose=purpose,
                )
            except Exception:
                status = "failed"
            with lock:
                counts[status] += 1

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="triage") as pool:
        futures = [pool.submit(_run_claimed) for _ in range(workers)]
        for future in futures:
            future.result()
    return dict(counts)
