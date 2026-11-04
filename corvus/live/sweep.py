"""Automatic sweep: poll Wazuh, select incidents, run existing analysis.

Every N seconds (default 300) one cycle runs:

1. the existing poll cycle (:func:`corvus.live.poll.run_poll_cycle`;
   no logic copied, its ``wazuh_poll_cycles`` row stays the counts
   ledger and is linked from the sweep row);
2. selection of the incidents this cycle created or grew whose
   ``ai_status`` is still ``pending``;
3. a pure per-incident policy decision (:func:`decide`);
4. concurrent analysis of the chosen incidents through the exact code
   path ``corvus analyze`` uses (triage worker, then the Spark agent
   loop) on a ``ThreadPoolExecutor`` with ``triage_workers`` threads,
   one failure never stopping the cycle;
5. the sweep row plus one decision row per candidate.

Nothing is deleted. Incidents the policy skips stay ``pending`` and
can still be analyzed by hand. Model spend still honours
``SPEND_CAP_USD`` through the existing reservation path.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from corvus.live.poll import run_poll_cycle

__all__ = [
    "FLOOR_NAMES",
    "LEVEL_TO_FLOOR",
    "SWEEP_ADVISORY_LOCK",
    "SweepPolicy",
    "decide",
    "effective_policy",
    "sweep_once",
    "try_acquire_sweep_lock",
]

#: Advisory lock so two sweeps never overlap (session-scoped, held
#: for the whole process lifetime; a different constant from the
#: migration runner and the spend ledger locks).
SWEEP_ADVISORY_LOCK = 20261103

#: UI level name -> deterministic severity floor (1 Informational, 2
#: Low, 3 Medium, 4 High, 5 Critical, 6 Fatal; the UI folds 5+6 into
#: "critical" and 1 into "informational", hence the mapping below).
LEVEL_TO_FLOOR = {"low": 2, "medium": 3, "high": 4, "critical": 5}
FLOOR_NAMES = {2: "low", 3: "medium", 4: "high", 5: "critical"}

DEFAULT_INTERVAL_SECONDS = 300.0
DEFAULT_MIN_FLOOR = "high"
DEFAULT_MAX_ANALYSES = 5
DEFAULT_TRIAGE_WORKERS = 4
MIN_TRIAGE_WORKERS = 1
MAX_TRIAGE_WORKERS = 16

#: Seconds of grace for in-flight tasks after a stop request before
#: the cycle records and returns; running threads are never killed.
STOP_GRACE_SECONDS = 600.0

#: Fallback per-task spend reservation (USD) when no backend resolves
#: (tests with fake runners monkeypatch :func:`_task_reservation_usd`).
DEFAULT_TASK_RESERVATION_USD = 0.05


@dataclass(frozen=True)
class SweepPolicy:
    """Effective per-cycle policy (already resolved flag > env > default)."""

    min_floor: int = 4
    max_analyses: int = 5
    always_analyze_injection: bool = True
    spend_cap_usd: float = 100.0
    lang: str = "en"
    interval_seconds: float = 300.0
    triage_workers: int = 4

    def as_dict(self) -> dict[str, Any]:
        """JSON-serializable form stored on the sweep row."""
        return asdict(self)


def _env(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def _parse_bool(raw: str, name: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be a boolean (true/false), got {raw!r}")


def effective_policy(
    *,
    min_floor: str | None = None,
    max_analyses: int | None = None,
    always_analyze_injection: bool | None = None,
    spend_cap_usd: float | None = None,
    lang: str | None = None,
    interval_seconds: float | None = None,
    triage_workers: int | None = None,
) -> SweepPolicy:
    """Resolve flag > env > default (``SWEEP_*`` env, ``SPEND_CAP_USD`` cap).

    Raises :class:`ValueError` with a clear message for any invalid
    value (unknown level, interval < 30, max analyses outside 0..50,
    bad lang, negative cap, workers outside 1..16).
    """

    level_raw = (
        min_floor
        if min_floor is not None
        else (_env("SWEEP_MIN_FLOOR") or DEFAULT_MIN_FLOOR)
    )
    level_key = level_raw.strip().lower()
    if level_key not in LEVEL_TO_FLOOR:
        raise ValueError(
            f"min_floor must be one of low, medium, high, critical, got {level_raw!r}"
        )

    if max_analyses is not None:
        max_n = max_analyses
    else:
        raw_max = _env("SWEEP_MAX_ANALYSES")
        if raw_max is None:
            max_n = DEFAULT_MAX_ANALYSES
        else:
            try:
                max_n = int(raw_max)
            except ValueError:
                raise ValueError(
                    f"SWEEP_MAX_ANALYSES must be an integer 0..50, got {raw_max!r}"
                ) from None
    if isinstance(max_n, bool) or not isinstance(max_n, int):
        raise ValueError(f"max_analyses must be an integer 0..50, got {max_n!r}")
    if max_n < 0 or max_n > 50:
        raise ValueError(f"max_analyses must be 0..50, got {max_n!r}")

    if always_analyze_injection is not None:
        always_injection = always_analyze_injection
    else:
        raw_always = _env("SWEEP_ALWAYS_INJECTION")
        always_injection = (
            _parse_bool(raw_always, "SWEEP_ALWAYS_INJECTION")
            if raw_always is not None
            else True
        )

    if spend_cap_usd is not None:
        cap = spend_cap_usd
    else:
        from corvus.llm.spend import get_spend_cap

        try:
            cap = get_spend_cap()
        except ValueError as exc:
            raise ValueError(str(exc)) from None
    if (
        not isinstance(cap, (int, float))
        or cap != cap
        or cap in (float("inf"), float("-inf"))
        or cap < 0
    ):
        raise ValueError(f"spend_cap_usd must be a finite number >= 0, got {cap!r}")

    lang_raw = lang if lang is not None else (_env("SWEEP_LANG") or "en")
    if lang_raw not in ("en", "es"):
        raise ValueError(f"lang must be 'en' or 'es', got {lang_raw!r}")

    if interval_seconds is not None:
        interval = interval_seconds
    else:
        raw_interval = _env("SWEEP_INTERVAL_SECONDS")
        if raw_interval is None:
            interval = DEFAULT_INTERVAL_SECONDS
        else:
            try:
                interval = float(raw_interval)
            except ValueError:
                raise ValueError(
                    "SWEEP_INTERVAL_SECONDS must be a number >= 30,"
                    f" got {raw_interval!r}"
                ) from None
    if (
        not isinstance(interval, (int, float))
        or interval != interval
        or interval in (float("inf"), float("-inf"))
        or interval < 30
    ):
        raise ValueError(f"interval must be >= 30 seconds, got {interval!r}")

    if triage_workers is not None:
        workers = triage_workers
    else:
        raw_workers = _env("SWEEP_TRIAGE_WORKERS")
        if raw_workers is None:
            workers = DEFAULT_TRIAGE_WORKERS
        else:
            try:
                workers = int(raw_workers)
            except ValueError:
                raise ValueError(
                    "SWEEP_TRIAGE_WORKERS must be an integer 1..16,"
                    f" got {raw_workers!r}"
                ) from None
    if isinstance(workers, bool) or not isinstance(workers, int):
        raise ValueError(f"triage_workers must be an integer 1..16, got {workers!r}")
    if workers < MIN_TRIAGE_WORKERS or workers > MAX_TRIAGE_WORKERS:
        raise ValueError(f"triage_workers must be 1..16, got {workers!r}")

    return SweepPolicy(
        min_floor=LEVEL_TO_FLOOR[level_key],
        max_analyses=max_n,
        always_analyze_injection=always_injection,
        spend_cap_usd=float(cap),
        lang=lang_raw,
        interval_seconds=float(interval),
        triage_workers=workers,
    )


@dataclass(frozen=True)
class Candidate:
    """One pending incident the cycle created or grew."""

    incident_id: int
    severity_floor: int
    event_count: int
    has_injection: bool


def decide(
    incident: Candidate,
    policy: SweepPolicy,
    spent_usd: float,
    analyses_so_far: int,
) -> tuple[str, str]:
    """Pure policy decision: ``(decision, reason_code)``.

    Decision is ``analyze``, ``skipped_policy`` or ``skipped_budget``.
    The budget check runs first: once recorded spend reaches the cap,
    every remaining candidate is ``skipped_budget``. Otherwise an
    incident qualifies when its deterministic floor reaches
    ``min_floor``, or when it carries an injection signal and
    ``always_analyze_injection`` is on; the caller ranks candidates
    (floor descending, event count descending) and counts analyses,
    so reaching ``max_analyses`` yields ``skipped_policy``.
    """
    if spent_usd >= policy.spend_cap_usd:
        return "skipped_budget", "over_spend_cap"
    qualifies = incident.severity_floor >= policy.min_floor or (
        incident.has_injection and policy.always_analyze_injection
    )
    if not qualifies:
        return "skipped_policy", "below_min_floor"
    if analyses_so_far >= policy.max_analyses:
        return "skipped_policy", "max_analyses_reached"
    return "analyze", "selected"


def _snapshot_incidents(database_url: str) -> dict[int, int]:
    """Return {incident id: event uid count} for the incidents table."""
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, COALESCE(jsonb_array_length(event_uids), 0) FROM incidents"
            )
            rows = cur.fetchall() or []
    return {int(r[0]): int(r[1] or 0) for r in rows}


def _pending_candidates(database_url: str, before: dict[int, int]) -> list[Candidate]:
    """Pending incidents this cycle created (new id) or grew (more uids)."""
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT i.id, i.severity_floor,"
                " COALESCE(jsonb_array_length(i.event_uids), 0),"
                " EXISTS(SELECT 1 FROM incident_signals s"
                " WHERE s.incident_id = i.id AND s.kind = 'injection')"
                " FROM incidents i WHERE i.ai_status = 'pending'"
            )
            rows = cur.fetchall() or []
    out: list[Candidate] = []
    for row in rows:
        incident_id = int(row[0])
        count = int(row[2] or 0)
        previous = before.get(incident_id)
        if previous is None or count > previous:
            out.append(
                Candidate(
                    incident_id=incident_id,
                    severity_floor=int(row[1]),
                    event_count=count,
                    has_injection=bool(row[3]),
                )
            )
    out.sort(key=lambda c: (-c.severity_floor, -c.event_count, c.incident_id))
    return out


def _already_analyzed(database_url: str, incident_id: int) -> bool:
    """True when a resolved analysis row already exists (never re-run)."""
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM incident_analyses WHERE incident_id = %s"
                " AND stage = 'analysis' AND status = 'resolved'",
                (incident_id,),
            )
            return cur.fetchone() is not None


def _record_sweep_start(database_url: str, policy: SweepPolicy) -> int:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sweep_runs (started_at, status, policy, interval_seconds)"
                " VALUES (NOW(), 'running', %s, %s) RETURNING id",
                (
                    Jsonb(policy.as_dict()),
                    policy.interval_seconds,
                ),
            )
            row = cur.fetchone()
        conn.commit()
    assert row is not None
    return int(row[0])


def _latest_poll_cycle_id(database_url: str) -> int | None:
    with psycopg.connect(database_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM wazuh_poll_cycles ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
    return int(row[0]) if row else None


def _record_decisions(
    database_url: str, sweep_run_id: int, decisions: list[tuple[int, str, str]]
) -> None:
    if not decisions:
        return
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO sweep_decisions"
                " (sweep_run_id, incident_id, decision, reason_code)"
                " VALUES (%s, %s, %s, %s)"
                " ON CONFLICT (sweep_run_id, incident_id) DO NOTHING",
                [(sweep_run_id, i, d, r) for i, d, r in decisions],
            )
        conn.commit()


def _mark_abandoned_runs(database_url: str, exclude_id: int) -> int:
    """Fail older rows still ``running`` whose lease long expired.

    The sweep holds a Postgres advisory lock, so when this process
    starts no other sweep is alive: any other row still in status
    ``running`` whose ``started_at`` is older than three times its
    own stored interval is an orphan from a crashed run. Mark those
    ``failed`` with ``error_code='abandoned'`` and return the count.
    """
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sweep_runs SET finished_at = NOW(), status = 'failed',"
                " error_code = 'abandoned' WHERE id != %s AND status = 'running'"
                " AND started_at < NOW() -"
                " (COALESCE(interval_seconds, 300) * INTERVAL '1 second' * 3)",
                (exclude_id,),
            )
            count = cur.rowcount or 0
        conn.commit()
    return int(count)


def _record_sweep_end(
    database_url: str,
    sweep_run_id: int,
    status: str,
    error_code: str,
    analyzed: int,
    failed: int,
    skipped_policy: int,
    skipped_budget: int,
) -> None:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            poll_id = None
            try:
                latest_poll = (
                    "SELECT id FROM wazuh_poll_cycles ORDER BY id DESC LIMIT 1"
                )
                cur.execute(latest_poll)
                row = cur.fetchone()
                poll_id = int(row[0]) if row else None
            except Exception:
                poll_id = None
            cur.execute(
                "UPDATE sweep_runs SET finished_at = NOW(), status = %s,"
                " error_code = %s, poll_cycle_id = %s, analyzed = %s,"
                " failed_analyses = %s, skipped_policy = %s,"
                " skipped_budget = %s WHERE id = %s",
                (
                    status,
                    error_code,
                    poll_id,
                    analyzed,
                    failed,
                    skipped_policy,
                    skipped_budget,
                    sweep_run_id,
                ),
            )
        conn.commit()


def _task_reservation_usd() -> float:
    """Worst-case USD of one sweep task (triage attempt plus analysis).

    Sums the single-attempt worst case of the serving triage and
    analysis backends under the price book, so the per-task hold
    covers the most one task can spend. Falls back to
    ``DEFAULT_TASK_RESERVATION_USD`` when no backend resolves (fake
    runners in tests); tests needing an exact bound monkeypatch this
    function. Only the returned amount is used, never model text.
    """
    try:
        from corvus.llm.config import get_backend
        from corvus.llm.price_book import cost_usd, load_price_book

        prices = load_price_book()
        total = 0.0
        for purpose in ("triage", "analysis"):
            backend = get_backend(purpose)
            total += cost_usd(
                prices,
                backend.model,
                backend.max_input_tokens,
                0,
                backend.max_output_tokens,
            )
        if total > 0.0:
            return float(total)
    except Exception:
        pass
    return DEFAULT_TASK_RESERVATION_USD


def _analyze_one(
    database_url: str,
    incident_id: int,
    lang: str,
    replay_dir: str | Path,
    adapter_factory: Callable[[], Any] | None = None,
    triage_runner: Callable[..., str] | None = None,
    analysis_runner: Callable[..., Any] | None = None,
) -> str:
    """Run one incident through the ``corvus analyze`` path; return outcome.

    Returns the analysis outcome status (``resolved`` and friends),
    ``busy`` when another worker holds the incident's job (the caller
    records it skipped, never analyzed twice), or a
    ``backend_unavailable:<Class>`` / ``failed:<Class>`` marker. Never
    raises for per-incident failures: the sweep records and continues.
    Only the exception class name is recorded, never the message.
    """
    from corvus.llm.agent import TriageMissingError

    try:
        if triage_runner is not None:
            triage_status = triage_runner(
                database_url, incident_id, replay_dir=replay_dir
            )
        else:
            from corvus.llm.triage_worker import process_incident_triage

            triage_status = process_incident_triage(
                database_url, incident_id, replay_dir=replay_dir
            )
    except Exception as exc:
        return f"failed:{type(exc).__name__}"
    if triage_status == "busy":
        return "busy"
    try:
        if analysis_runner is not None:
            outcome = analysis_runner(
                incident_id, lang=lang, database_url=database_url, replay_dir=replay_dir
            )
            return str(getattr(outcome, "status", outcome))
        from corvus.adapters.replay import ReplayAdapter
        from corvus.llm.agent import run_analysis
        from corvus.llm.config import get_backend

        backend = get_backend("analysis")
        outcome = run_analysis(
            incident_id,
            lang=lang,
            database_url=database_url,
            adapter=ReplayAdapter(replay_dir),
            replay_dir=replay_dir,
            backend=backend,
        )
        return str(outcome.status)
    except TriageMissingError as exc:
        return f"failed:{type(exc).__name__}"
    except Exception as exc:
        return f"failed:{type(exc).__name__}"


def _can_submit(
    pending: deque[Candidate],
    inflight: dict[Future[tuple[str, str, str]], Candidate],
    workers: int,
    stop_event: threading.Event,
) -> bool:
    """True when another task may be submitted this turn."""
    return bool(pending) and len(inflight) < workers and not stop_event.is_set()


def _install_cycle_stop_handlers(stop: threading.Event) -> dict[int, Any]:
    """Point SIGINT/SIGTERM at ``stop``; return the previous handlers."""

    def _handle(signum: int, _frame: object) -> None:
        stop.set()

    return {sig: signal.signal(sig, _handle) for sig in (signal.SIGINT, signal.SIGTERM)}


def _run_guarded_task(
    database_url: str,
    candidate: Candidate,
    policy: SweepPolicy,
    replay_dir: str | Path,
    reservation_usd: float,
    triage_runner: Callable[..., str] | None,
    analysis_runner: Callable[..., Any] | None,
) -> tuple[str, str, str]:
    """Run one selected incident; return ``(decision, reason, bucket)``.

    The bucket is ``analyzed``, ``failed``, ``skipped_budget`` or
    ``skipped_policy``. Never raises: every failure path returns
    ``failed`` with the exception class only. Each task opens its own
    database connections (nothing shared is mutated), re-checks the
    recorded spend plus a spend reservation right before any model
    call, and re-checks that the incident is still unanalyzed.
    """
    from corvus.llm.spend import (
        BudgetExceededError,
        release_reservation,
        reserve,
        spent_usd,
    )

    try:
        try:
            spent = spent_usd(database_url)
        except Exception:
            spent = 0.0
        if spent >= policy.spend_cap_usd:
            return ("skipped_budget", "over_spend_cap", "skipped_budget")
        if _already_analyzed(database_url, candidate.incident_id):
            return ("skipped_policy", "already_analyzed", "skipped_policy")
        try:
            reservation = reserve(
                reservation_usd,
                database_url=database_url,
                cap_usd=policy.spend_cap_usd,
                ttl_seconds=STOP_GRACE_SECONDS + 300.0,
            )
        except BudgetExceededError:
            return ("skipped_budget", "over_spend_cap", "skipped_budget")
        try:
            result = _analyze_one(
                database_url,
                candidate.incident_id,
                policy.lang,
                replay_dir,
                triage_runner=triage_runner,
                analysis_runner=analysis_runner,
            )
        finally:
            try:
                release_reservation(reservation.id, database_url)
            except Exception:
                pass
        if result == "resolved":
            return ("analyze", "selected", "analyzed")
        if result == "busy":
            return ("skipped_policy", "already_running", "skipped_policy")
        return ("analyze", "selected", "failed")
    except Exception:
        return ("analyze", "selected", "failed")


def sweep_once(
    *,
    database_url: str,
    store_dir: str | Path,
    replay_dir: str | Path | None = None,
    policy: SweepPolicy,
    adapter_factory: Callable[[], Any] | None = None,
    triage_runner: Callable[..., str] | None = None,
    analysis_runner: Callable[..., Any] | None = None,
    attack_path: str | Path = "data/attack/enterprise.json",
    page_size: int = 500,
    max_docs: int = 5000,
    since_ms: int | None = None,
    with_archives: bool = False,
    archives_limit: int = 200,
    now_ms: int | None = None,
    stop_event: threading.Event | None = None,
    stop_grace_seconds: float = STOP_GRACE_SECONDS,
) -> dict[str, Any]:
    """Run one sweep cycle; return the recorded counts.

    ``replay_dir`` defaults to ``store_dir`` when not given, so the
    analysis reads the same store the poll writes; an explicit
    ``replay_dir`` wins. ``analyzed`` counts only analyses that ended
    ``resolved``; ``failed_analyses`` counts the rest; attempts
    (``analyzed + failed_analyses``) drive ``max_analyses``.

    The cycle is (a) poll, (b) deterministic selection, (c) the
    selected incidents through a ``ThreadPoolExecutor`` with
    ``policy.triage_workers`` threads (``1`` runs them one at a time,
    exactly like the old sequential loop), (d) collection as tasks
    finish, (e) decisions and counters recorded at the end. Decisions
    and submission order stay deterministic (floor descending, event
    count descending); only completion order varies.

    Raises the poll exception after recording a failed sweep row, so
    the loop can log one redacted line and continue. Per-incident
    analysis failures are recorded, never raised. Any other exception
    after the start record also ends the row as ``failed`` with the
    exception class name, so no exit path leaves it ``running``.
    SIGINT/SIGTERM (or ``stop_event``) stop submitting new tasks,
    let running ones finish within ``stop_grace_seconds``, and end
    the row ``ok`` (``error_code`` ``"stopped"``) when nothing else
    failed. The advisory lock stays held by the calling thread.
    """
    cycle_started = time.monotonic()
    if stop_event is None:
        stop_event = threading.Event()
        old_handlers: dict[int, Any] | None = None
        if threading.current_thread() is threading.main_thread():
            old_handlers = _install_cycle_stop_handlers(stop_event)
    else:
        old_handlers = None
    try:
        return _sweep_once_inner(
            database_url=database_url,
            store_dir=store_dir,
            replay_dir=replay_dir,
            policy=policy,
            adapter_factory=adapter_factory,
            triage_runner=triage_runner,
            analysis_runner=analysis_runner,
            attack_path=attack_path,
            page_size=page_size,
            max_docs=max_docs,
            since_ms=since_ms,
            with_archives=with_archives,
            archives_limit=archives_limit,
            now_ms=now_ms,
            stop_event=stop_event,
            stop_grace_seconds=stop_grace_seconds,
            cycle_started=cycle_started,
        )
    finally:
        if old_handlers is not None:
            for sig, handler in old_handlers.items():
                try:
                    signal.signal(sig, handler)
                except Exception:
                    pass


def _sweep_once_inner(
    *,
    database_url: str,
    store_dir: str | Path,
    replay_dir: str | Path | None,
    policy: SweepPolicy,
    adapter_factory: Callable[[], Any] | None,
    triage_runner: Callable[..., str] | None,
    analysis_runner: Callable[..., Any] | None,
    attack_path: str | Path,
    page_size: int,
    max_docs: int,
    since_ms: int | None,
    with_archives: bool,
    archives_limit: int,
    now_ms: int | None,
    stop_event: threading.Event,
    stop_grace_seconds: float,
    cycle_started: float,
) -> dict[str, Any]:
    """Poll, select, run the task pool, and record (see :func:`sweep_once`)."""
    from corvus.llm.spend import spent_usd

    sweep_run_id = _record_sweep_start(database_url, policy)
    try:
        _mark_abandoned_runs(database_url, sweep_run_id)
    except Exception:
        pass
    effective_replay: str | Path = replay_dir if replay_dir is not None else store_dir
    adapter: Any = None
    analyzed = failed = skipped_policy = skipped_budget = attempts = 0
    candidates: list[Candidate] = []
    stopped_early = False
    try:
        before = _snapshot_incidents(database_url)
        adapter = (
            adapter_factory()
            if adapter_factory is not None
            else _default_adapter(database_url)
        )
        run_poll_cycle(
            adapter=adapter,
            database_url=database_url,
            store_dir=store_dir,
            attack_path=attack_path,
            page_size=page_size,
            max_docs=max_docs,
            since_ms=since_ms,
            with_archives=with_archives,
            archives_limit=archives_limit,
            now_ms=now_ms,
        )
        candidates = _pending_candidates(database_url, before)
        decisions: list[tuple[int, str, str]] = []
        to_run: list[Candidate] = []
        for candidate in candidates:
            if _already_analyzed(database_url, candidate.incident_id):
                decisions.append(
                    (candidate.incident_id, "skipped_policy", "already_analyzed")
                )
                skipped_policy += 1
                continue
            try:
                spent = spent_usd(database_url)
            except Exception:
                spent = 0.0
            decision, reason = decide(candidate, policy, spent, attempts)
            decisions.append((candidate.incident_id, decision, reason))
            if decision != "analyze":
                if decision == "skipped_budget":
                    skipped_budget += 1
                else:
                    skipped_policy += 1
                continue
            attempts += 1
            to_run.append(candidate)
        reservation_usd = _task_reservation_usd()
        outcomes: dict[int, tuple[str, str, str]] = {}
        workers = max(1, policy.triage_workers)
        if to_run:
            executor = ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="sweep-task"
            )
            try:
                pending: deque[Candidate] = deque(to_run)
                inflight: dict[Future[tuple[str, str, str]], Candidate] = {}
                stop_deadline: float | None = None
                while pending or inflight:
                    while _can_submit(pending, inflight, workers, stop_event):
                        cand = pending.popleft()
                        fut = executor.submit(
                            _run_guarded_task,
                            database_url,
                            cand,
                            policy,
                            effective_replay,
                            reservation_usd,
                            triage_runner,
                            analysis_runner,
                        )
                        inflight[fut] = cand
                    if stop_event.is_set() and stop_deadline is None:
                        stop_deadline = time.monotonic() + stop_grace_seconds
                        stopped_early = True
                    if not inflight:
                        break
                    if stop_deadline is not None:
                        remaining = stop_deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        done, _ = wait(
                            set(inflight),
                            timeout=min(0.2, remaining),
                            return_when=FIRST_COMPLETED,
                        )
                    else:
                        done, _ = wait(
                            set(inflight),
                            timeout=0.2,
                            return_when=FIRST_COMPLETED,
                        )
                    for fut in done:
                        cand = inflight.pop(fut)
                        try:
                            outcomes[cand.incident_id] = fut.result()
                        except Exception:
                            outcomes[cand.incident_id] = (
                                "analyze",
                                "selected",
                                "failed",
                            )
                dec_idx = {d[0]: i for i, d in enumerate(decisions)}
                for cand in pending:
                    decisions[dec_idx[cand.incident_id]] = (
                        cand.incident_id,
                        "skipped_policy",
                        "cycle_stopped",
                    )
                    skipped_policy += 1
                for _fut, cand in inflight.items():
                    if cand.incident_id not in outcomes:
                        outcomes[cand.incident_id] = (
                            "analyze",
                            "selected",
                            "failed",
                        )
            finally:
                if stop_deadline is not None and inflight_remaining(executor):
                    executor.shutdown(wait=False, cancel_futures=False)
                else:
                    executor.shutdown(wait=True)
        for cand in to_run:
            outcome = outcomes.get(cand.incident_id)
            if outcome is None:
                continue
            bucket = outcome[2]
            idx = next(i for i, d in enumerate(decisions) if d[0] == cand.incident_id)
            decisions[idx] = (cand.incident_id, outcome[0], outcome[1])
            if bucket == "analyzed":
                analyzed += 1
            elif bucket == "failed":
                failed += 1
            elif bucket == "skipped_budget":
                skipped_budget += 1
            else:
                skipped_policy += 1
        _record_decisions(database_url, sweep_run_id, decisions)
        _record_sweep_end(
            database_url,
            sweep_run_id,
            "ok",
            "stopped" if stopped_early else "",
            analyzed,
            failed,
            skipped_policy,
            skipped_budget,
        )
    except Exception as exc:
        try:
            _record_sweep_end(
                database_url,
                sweep_run_id,
                "failed",
                type(exc).__name__,
                analyzed,
                failed,
                skipped_policy,
                skipped_budget,
            )
        except Exception:
            pass
        raise
    finally:
        if adapter_factory is None and adapter is not None:
            try:
                client = getattr(adapter, "_client", None)
                close = getattr(client, "close", None)
                if callable(close):
                    close()
            except Exception:
                pass
    poll_id = _latest_poll_cycle_id(database_url)
    return {
        "sweep_run_id": sweep_run_id,
        "poll_cycle_id": poll_id,
        "candidates": len(candidates),
        "analyzed": analyzed,
        "failed_analyses": failed,
        "skipped_policy": skipped_policy,
        "skipped_budget": skipped_budget,
        "elapsed_seconds": time.monotonic() - cycle_started,
        "triage_workers": max(1, policy.triage_workers),
        "stopped_early": stopped_early,
    }


def inflight_remaining(executor: ThreadPoolExecutor) -> bool:
    """True when the executor may still have threads doing work."""
    try:
        work_queue = getattr(executor, "_work_queue", None)
        threads: set[Any] = getattr(executor, "_threads", set())
        alive = any(t.is_alive() for t in set(threads))
        return bool(alive or (work_queue is not None and work_queue.qsize() > 0))
    except Exception:
        return True


def _default_adapter(database_url: str) -> Any:
    """Build the read-only Wazuh indexer adapter from the environment."""
    import httpx2

    from corvus.adapters.wazuh.adapter import WazuhAdapter
    from corvus.adapters.wazuh.client import ReadOnlyIndexerClient

    missing = [
        name
        for name in (
            "WAZUH_INDEXER_URL",
            "WAZUH_INDEXER_USER",
            "WAZUH_INDEXER_PASSWORD",
        )
        if not os.environ.get(name)
    ]
    if missing:
        raise ValueError("sweep needs from the environment: " + ", ".join(missing))
    client = ReadOnlyIndexerClient(
        os.environ["WAZUH_INDEXER_URL"],
        os.environ["WAZUH_INDEXER_USER"],
        os.environ["WAZUH_INDEXER_PASSWORD"],
        ca_path=os.environ.get("WAZUH_INDEXER_CA") or None,
        timeout=httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
    )
    return WazuhAdapter(client, database_url=database_url)


def try_acquire_sweep_lock(database_url: str) -> Any | None:
    """Hold the sweep advisory lock; return the connection or None.

    Returns None when another sweep already holds the lock (the
    caller exits cleanly). The caller owns the returned connection:
    closing it releases the lock.
    """
    conn = psycopg.connect(database_url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (SWEEP_ADVISORY_LOCK,))
            row = cur.fetchone()
        if row is None or not row[0]:
            conn.close()
            return None
        return conn
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise


def run_sweep_loop(
    *,
    database_url: str,
    store_dir: str | Path,
    replay_dir: str | Path | None = None,
    policy: SweepPolicy,
    once: bool = False,
    attack_path: str | Path = "data/attack/enterprise.json",
    page_size: int = 500,
    max_docs: int = 5000,
    since_ms: int | None = None,
    with_archives: bool = False,
    archives_limit: int = 200,
    stop_flag: list[bool] | None = None,
    on_cycle: Callable[[dict[str, Any]], None] | None = None,
    adapter_factory: Callable[[], Any] | None = None,
) -> int:
    """Loop ``sweep_once`` every interval; return a process exit code.

    The loop never sleeps less than the interval minus the cycle
    duration (no drift pile-up, no busy loop). SIGINT/SIGTERM stop
    cleanly after the current step. A Wazuh outage records a failed
    sweep row, logs one redacted line, and the loop continues.
    """
    from corvus.guardrails.egress import redact

    stop = stop_flag if stop_flag is not None else [False]
    cycle_events: list[threading.Event] = []

    def _request_stop(signum: int, frame: object) -> None:
        stop[0] = True
        for event in list(cycle_events):
            event.set()

    old_int = signal.signal(signal.SIGINT, _request_stop)
    old_term = signal.signal(signal.SIGTERM, _request_stop)
    try:
        while True:
            started = time.monotonic()
            cycle_stop = threading.Event()
            cycle_events.append(cycle_stop)
            try:
                summary = sweep_once(
                    database_url=database_url,
                    store_dir=store_dir,
                    replay_dir=replay_dir,
                    policy=policy,
                    adapter_factory=adapter_factory,
                    attack_path=attack_path,
                    page_size=page_size,
                    max_docs=max_docs,
                    since_ms=since_ms,
                    with_archives=with_archives,
                    archives_limit=archives_limit,
                    stop_event=cycle_stop,
                )
            except ValueError:
                raise
            except Exception as exc:
                print(f"sweep cycle failed ({redact(type(exc).__name__)}); continuing")
                if once or stop[0]:
                    return 1
                _interruptible_sleep(policy.interval_seconds, stop)
                continue
            finally:
                try:
                    cycle_events.remove(cycle_stop)
                except ValueError:
                    pass
            attempted = int(summary["analyzed"]) + int(summary["failed_analyses"])
            print(
                f"sweep cycle: candidates={summary['candidates']}"
                f" attempted={attempted}"
                f" analyzed={summary['analyzed']}"
                f" failed={summary['failed_analyses']}"
                f" skipped_policy={summary['skipped_policy']}"
                f" skipped_budget={summary['skipped_budget']}"
                f" elapsed={float(summary.get('elapsed_seconds', 0.0)):.1f}s"
                f" workers={policy.triage_workers}"
            )
            if on_cycle is not None:
                on_cycle(summary)
            if once or stop[0] or bool(summary.get("stopped_early")):
                return 0
            elapsed = time.monotonic() - started
            _interruptible_sleep(max(0.0, policy.interval_seconds - elapsed), stop)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


def _interruptible_sleep(seconds: float, stop: list[bool]) -> None:
    """Sleep up to ``seconds`` in short slices; stop early when asked."""
    deadline = time.monotonic() + max(0.0, seconds)
    while not stop[0] and time.monotonic() < deadline:
        time.sleep(min(0.2, deadline - time.monotonic()))
