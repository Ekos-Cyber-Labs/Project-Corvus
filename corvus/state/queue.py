"""Durable Postgres work queue over the ``work_queue`` table (0002).

Delivery is at-least-once. ``claim`` hands a job to one worker under a
lease; if that worker crashes, the lease expires, the job is reclaimed,
and another worker runs it again. Handlers MUST therefore be
idempotent: running a handler twice for the same job (crash after the
side effect, before ``complete``) must be safe. Use the job ``id`` or
the enqueue ``dedupe_key`` as the handler's own idempotency key where a
downstream write needs one.

Every operation is one short transaction that opens its own
connection, commits, and closes. A transaction is never held open
while a job runs: claim, run the handler outside any transaction,
then call ``complete`` or ``fail``.

Ownership: ``complete``, ``fail`` and ``heartbeat`` only act while
the row is still ``locked`` by the calling worker and its lease has
not expired. A worker whose lease was reclaimed (and possibly
re-claimed by another worker) gets ``False`` / ``None`` and cannot
overwrite the new owner's result. Long handlers (Glimmer triage
takes longer than the default lease) must call ``heartbeat`` at
least every ``lease / 3``; a ``False`` heartbeat means the worker
must stop and not write any results. All timestamps are
timezone-aware UTC; the application sets ``updated_at`` on every
write (there are no triggers).

No migration 0003 is needed: 0002 already provides every column,
status check, the nullable unique ``dedupe_key``, and the claim/lease
partial indexes this module uses.
"""

import random
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DEFAULT_LEASE_SECONDS = 60.0
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY_SECONDS = 1.0
DEFAULT_MAX_DELAY_SECONDS = 300.0

_COLUMNS = (
    "id, kind, payload, dedupe_key, status, attempts, available_at, "
    "locked_by, locked_at, lease_expires_at, last_error, created_at, updated_at"
)


class JobStatus(StrEnum):
    """Lifecycle of a ``work_queue`` row."""

    PENDING = "pending"
    LOCKED = "locked"
    DONE = "done"
    FAILED = "failed"
    DEAD = "dead"


@dataclass(frozen=True)
class Job:
    """One ``work_queue`` row as claimed by a worker."""

    id: int
    kind: str
    payload: dict[str, Any]
    dedupe_key: str | None
    status: JobStatus
    attempts: int
    available_at: datetime
    locked_by: str | None
    locked_at: datetime | None
    lease_expires_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


def _utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _now(now: datetime | None) -> datetime:
    return datetime.now(UTC) if now is None else _utc(now, "now")


def _required_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _lease_delta(lease_seconds: float, lease_duration: timedelta | None) -> timedelta:
    delta = (
        lease_duration
        if lease_duration is not None
        else timedelta(seconds=lease_seconds)
    )
    if delta <= timedelta(0):
        raise ValueError("lease must be positive")
    return delta


def _lease_value(lease: float | timedelta) -> timedelta:
    """Accept a heartbeat lease as seconds or as a ``timedelta``."""
    delta = lease if isinstance(lease, timedelta) else timedelta(seconds=float(lease))
    if delta <= timedelta(0):
        raise ValueError("lease must be positive")
    return delta


def _job_from_row(row: Mapping[str, Any]) -> Job:
    payload = row["payload"]
    return Job(
        id=int(row["id"]),
        kind=str(row["kind"]),
        payload=dict(payload) if isinstance(payload, Mapping) else {},
        dedupe_key=None if row["dedupe_key"] is None else str(row["dedupe_key"]),
        status=JobStatus(str(row["status"])),
        attempts=int(row["attempts"]),
        available_at=row["available_at"],
        locked_by=row["locked_by"],
        locked_at=row["locked_at"],
        lease_expires_at=row["lease_expires_at"],
        last_error=row["last_error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class WorkQueue:
    """Short-transaction queue operations against one database URL."""

    def __init__(self, database_url: str) -> None:
        self._database_url = _required_text(database_url, "database_url")

    def enqueue(
        self,
        kind: str,
        payload: Mapping[str, Any] | None = None,
        *,
        dedupe_key: str | None = None,
        available_at: datetime | None = None,
        now: datetime | None = None,
    ) -> int:
        """Insert a pending job and return its id.

        With ``dedupe_key``, ``INSERT ... ON CONFLICT (dedupe_key) DO
        NOTHING`` plus a lookup of the existing row means enqueueing
        the same work twice returns the same id and creates one row.
        Without a key, every call creates a new job (NULLs never
        collide in the unique index).

        A ``dedupe_key`` stays taken for the life of the row, even
        after the job is ``done`` or ``dead``: re-enqueueing with the
        same key always returns that finished job's id, never a fresh
        job. To re-run the same work on purpose, use a new key, for
        example by including a version or revision in it.
        """
        kind = _required_text(kind, "kind")
        if dedupe_key is not None:
            dedupe_key = _required_text(dedupe_key, "dedupe_key")
        current = _now(now)
        available = (
            current if available_at is None else _utc(available_at, "available_at")
        )
        body: dict[str, Any] = {} if payload is None else dict(payload)
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO work_queue "
                    "(kind, payload, dedupe_key, status, available_at, "
                    "created_at, updated_at) "
                    "VALUES (%s, %s, %s, 'pending', %s, %s, %s) "
                    "ON CONFLICT (dedupe_key) DO NOTHING RETURNING id",
                    (kind, Jsonb(body), dedupe_key, available, current, current),
                )
                row = cur.fetchone()
                if row is not None:
                    return int(row["id"])
                if dedupe_key is None:  # pragma: no cover - insert always returns
                    raise RuntimeError("enqueue returned no job id")
                cur.execute(
                    "SELECT id FROM work_queue WHERE dedupe_key = %s",
                    (dedupe_key,),
                )
                existing = cur.fetchone()
                if existing is None:  # pragma: no cover - conflict implies a row
                    raise RuntimeError("dedupe conflict without an existing job")
                return int(existing["id"])

    def claim(
        self,
        worker_id: str,
        *,
        kinds: Collection[str] | None = None,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        lease_duration: timedelta | None = None,
        now: datetime | None = None,
    ) -> Job | None:
        """Claim the next due job for ``worker_id``, or return None.

        Claimable rows are ``pending``/``failed`` with
        ``available_at <= now``. Expired ``locked`` rows are not
        claimable until :meth:`reclaim_expired_leases` returns them to
        ``pending``. The pick is ordered by ``available_at`` then
        ``id`` and locked with ``SELECT ... FOR UPDATE SKIP LOCKED``
        in one UPDATE, so two concurrent workers never claim the same
        job. Sets ``locked_by``, ``locked_at`` and
        ``lease_expires_at``.
        """
        worker_id = _required_text(worker_id, "worker_id")
        current = _now(now)
        lease_expires = current + _lease_delta(lease_seconds, lease_duration)
        wanted: list[str] = []
        if kinds is not None:
            wanted.extend(_required_text(item, "kind") for item in kinds)
        kind_filter = ""
        # Placeholder order: locked_by, locked_at, lease_expires_at,
        # updated_at, available_at due check, kinds.
        params: list[Any] = [
            worker_id,
            current,
            lease_expires,
            current,
            current,
        ]
        if wanted:
            placeholders = ", ".join(["%s"] * len(wanted))
            kind_filter = f" AND kind IN ({placeholders})"
            params.extend(wanted)
        query = (
            f"UPDATE work_queue SET status = 'locked', locked_by = %s, "
            f"locked_at = %s, lease_expires_at = %s, updated_at = %s "
            f"WHERE id = ("
            f"SELECT id FROM work_queue "
            f"WHERE status IN ('pending', 'failed') AND available_at <= %s"
            f"{kind_filter} "
            f"ORDER BY available_at ASC, id ASC "
            f"FOR UPDATE SKIP LOCKED LIMIT 1) "
            f"RETURNING {_COLUMNS}"
        )
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                return None if row is None else _job_from_row(row)

    def claim_job(
        self,
        job_id: int,
        worker_id: str,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        lease_duration: timedelta | None = None,
        now: datetime | None = None,
    ) -> Job | None:
        """Claim one specific job row for ``worker_id``, or return None.

        Same atomic lease as :meth:`claim`, but scoped to ``job_id``:
        the row moves to ``locked`` only when it is ``pending`` or
        ``failed`` and due (``available_at <= now``). Anything else
        (done, dead, locked by another worker, not yet due, unknown
        id) returns None without touching the row, so an
        incident-scoped runner never picks up another incident's job.
        """
        if isinstance(job_id, bool) or not isinstance(job_id, int):
            raise ValueError("job_id must be an int")
        worker_id = _required_text(worker_id, "worker_id")
        current = _now(now)
        lease_expires = current + _lease_delta(lease_seconds, lease_duration)
        query = (
            "UPDATE work_queue SET status = 'locked', locked_by = %s, "
            "locked_at = %s, lease_expires_at = %s, updated_at = %s "
            f"WHERE id = %s AND status IN ('pending', 'failed') "
            "AND available_at <= %s "
            f"RETURNING {_COLUMNS}"
        )
        params: list[Any] = [
            worker_id,
            current,
            lease_expires,
            current,
            job_id,
            current,
        ]
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                return None if row is None else _job_from_row(row)

    def heartbeat(
        self,
        job_id: int,
        worker_id: str,
        lease: float | timedelta = DEFAULT_LEASE_SECONDS,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Extend the lease of a job the caller still owns; False otherwise.

        Sets ``lease_expires_at = now + lease`` (``lease`` is seconds
        or a ``timedelta``) only while the row is still ``locked`` by
        ``worker_id`` and its lease has not expired — the same
        ownership rule as ``complete``. Long handlers must heartbeat
        at least every ``lease / 3`` so a reclaim cannot fire between
        heartbeats. A ``False`` return means ownership is lost: the
        worker must stop and not write any results, because another
        worker may already own (or soon re-run) the job.
        """
        if job_id <= 0:
            raise ValueError("job_id must be positive")
        worker_id = _required_text(worker_id, "worker_id")
        current = _now(now)
        lease_expires = current + _lease_value(lease)
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE work_queue SET lease_expires_at = %s, updated_at = %s "
                    "WHERE id = %s AND status = 'locked' AND locked_by = %s "
                    "AND lease_expires_at IS NOT NULL AND lease_expires_at > %s "
                    "RETURNING id",
                    (lease_expires, current, job_id, worker_id, current),
                )
                return cur.fetchone() is not None

    def complete(
        self, job_id: int, worker_id: str, *, now: datetime | None = None
    ) -> bool:
        """Mark a job ``done``; False when the caller no longer owns it.

        Acts only on a row still ``locked`` by ``worker_id`` with an
        unexpired lease, so a stale worker whose lease was reclaimed
        cannot overwrite the new owner's result.
        """
        if job_id <= 0:
            raise ValueError("job_id must be positive")
        worker_id = _required_text(worker_id, "worker_id")
        current = _now(now)
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE work_queue SET status = 'done', locked_by = NULL, "
                    "locked_at = NULL, lease_expires_at = NULL, updated_at = %s "
                    "WHERE id = %s AND status = 'locked' AND locked_by = %s "
                    "AND lease_expires_at IS NOT NULL AND lease_expires_at > %s "
                    "RETURNING id",
                    (current, job_id, worker_id, current),
                )
                return cur.fetchone() is not None

    def fail(
        self,
        job_id: int,
        worker_id: str,
        error: str,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS,
        max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS,
        jitter_seconds: float | None = None,
        now: datetime | None = None,
    ) -> Job | None:
        """Record a failure; None when the caller no longer owns the job.

        Increments ``attempts`` and stores ``last_error``. Below
        ``max_attempts`` the job becomes ``failed`` with
        ``available_at = now + delay`` where
        ``delay = min(max_delay_seconds, base * 2 ** (attempts - 1))``
        plus uniform jitter in ``[0, jitter_seconds]`` (default: up to
        the exponential delay itself). At ``max_attempts`` it becomes
        ``dead`` and is never claimable again. Locks are cleared.
        """
        if job_id <= 0:
            raise ValueError("job_id must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if base_delay_seconds < 0 or max_delay_seconds < 0:
            raise ValueError("backoff delays must not be negative")
        if jitter_seconds is not None and jitter_seconds < 0:
            raise ValueError("jitter_seconds must not be negative")
        worker_id = _required_text(worker_id, "worker_id")
        error = _required_text(error, "error")
        current = _now(now)
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_COLUMNS} FROM work_queue WHERE id = %s FOR UPDATE",
                    (job_id,),
                )
                row = cur.fetchone()
                if (
                    row is None
                    or row["status"] != JobStatus.LOCKED
                    or row["locked_by"] != worker_id
                    or row["lease_expires_at"] is None
                    or row["lease_expires_at"] <= current
                ):
                    return None
                attempts = int(row["attempts"]) + 1
                if attempts >= max_attempts:
                    status = JobStatus.DEAD
                    available = row["available_at"]
                else:
                    status = JobStatus.FAILED
                    exponential = min(
                        max_delay_seconds,
                        base_delay_seconds * (2 ** (attempts - 1)),
                    )
                    jitter_cap = (
                        exponential if jitter_seconds is None else jitter_seconds
                    )
                    delay = exponential + random.uniform(0, jitter_cap)
                    available = current + timedelta(seconds=delay)
                cur.execute(
                    "UPDATE work_queue SET status = %s, attempts = %s, "
                    "available_at = %s, locked_by = NULL, locked_at = NULL, "
                    "lease_expires_at = NULL, last_error = %s, updated_at = %s "
                    f"WHERE id = %s RETURNING {_COLUMNS}",
                    (
                        status.value,
                        attempts,
                        available,
                        error,
                        current,
                        job_id,
                    ),
                )
                updated = cur.fetchone()
                return None if updated is None else _job_from_row(updated)

    def reclaim_expired_leases(
        self,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        now: datetime | None = None,
    ) -> int:
        """Reclaim expired-lease ``locked`` rows; count the rows touched.

        A reclaim counts as an attempt: ``attempts`` is incremented
        and ``last_error`` is set to ``"lease expired"``, so a poison
        job that crashes or hangs its worker every time is not
        reclaimed forever. When the incremented ``attempts`` reaches
        ``max_attempts`` the job becomes ``dead``; otherwise it
        returns to ``pending`` with locks cleared. The original
        ``available_at`` is kept — it is already due — so reclaiming
        to ``pending`` preserves claim order.
        """
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        current = _now(now)
        with psycopg.connect(self._database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE work_queue SET "
                    "status = CASE WHEN attempts + 1 >= %s "
                    "THEN 'dead' ELSE 'pending' END, "
                    "attempts = attempts + 1, last_error = 'lease expired', "
                    "locked_by = NULL, locked_at = NULL, "
                    "lease_expires_at = NULL, updated_at = %s "
                    "WHERE status = 'locked' AND lease_expires_at IS NOT NULL "
                    "AND lease_expires_at <= %s RETURNING id",
                    (max_attempts, current, current),
                )
                return len(cur.fetchall())


def heartbeat_interval_for(job: Job, lease_seconds: float) -> float:
    """Heartbeat interval honoring the actually granted lease.

    Never assume the claim granted ``lease_seconds``: the interval
    derives from ``min(lease_seconds, remaining time on the claimed
    row) / 3``, so the first fire always lands strictly inside the
    grant (``heartbeat`` requires ``lease_expires_at > now`` and a
    fire exactly at expiry already loses the lease). Falls back to
    ``lease_seconds / 3`` when the row exposes no expiry, and fires
    ~immediately when the grant already lapsed so the run ends busy
    fast instead of working under a dead lease.
    """
    remaining: float | None = None
    expires_at = getattr(job, "lease_expires_at", None)
    if isinstance(expires_at, datetime):
        try:
            remaining = (expires_at - _now(None)).total_seconds()
        except TypeError:
            remaining = None
    base = lease_seconds if remaining is None else min(lease_seconds, remaining)
    if base <= 0:
        return 0.05
    return base / 3.0


def enqueue(
    database_url: str,
    kind: str,
    payload: Mapping[str, Any] | None = None,
    *,
    dedupe_key: str | None = None,
    available_at: datetime | None = None,
    now: datetime | None = None,
) -> int:
    """Module-level wrapper for :meth:`WorkQueue.enqueue`."""
    return WorkQueue(database_url).enqueue(
        kind, payload, dedupe_key=dedupe_key, available_at=available_at, now=now
    )


def claim(
    database_url: str,
    worker_id: str,
    *,
    kinds: Collection[str] | None = None,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    lease_duration: timedelta | None = None,
    now: datetime | None = None,
) -> Job | None:
    """Module-level wrapper for :meth:`WorkQueue.claim`."""
    return WorkQueue(database_url).claim(
        worker_id,
        kinds=kinds,
        lease_seconds=lease_seconds,
        lease_duration=lease_duration,
        now=now,
    )


def claim_job(
    database_url: str,
    job_id: int,
    worker_id: str,
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    lease_duration: timedelta | None = None,
    now: datetime | None = None,
) -> Job | None:
    """Module-level wrapper for :meth:`WorkQueue.claim_job`."""
    return WorkQueue(database_url).claim_job(
        job_id,
        worker_id,
        lease_seconds=lease_seconds,
        lease_duration=lease_duration,
        now=now,
    )


def heartbeat(
    database_url: str,
    job_id: int,
    worker_id: str,
    lease: float | timedelta = DEFAULT_LEASE_SECONDS,
    *,
    now: datetime | None = None,
) -> bool:
    """Module-level wrapper for :meth:`WorkQueue.heartbeat`."""
    return WorkQueue(database_url).heartbeat(job_id, worker_id, lease, now=now)


def complete(
    database_url: str, job_id: int, worker_id: str, *, now: datetime | None = None
) -> bool:
    """Module-level wrapper for :meth:`WorkQueue.complete`."""
    return WorkQueue(database_url).complete(job_id, worker_id, now=now)


def fail(
    database_url: str,
    job_id: int,
    worker_id: str,
    error: str,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS,
    max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS,
    jitter_seconds: float | None = None,
    now: datetime | None = None,
) -> Job | None:
    """Module-level wrapper for :meth:`WorkQueue.fail`."""
    return WorkQueue(database_url).fail(
        job_id,
        worker_id,
        error,
        max_attempts=max_attempts,
        base_delay_seconds=base_delay_seconds,
        max_delay_seconds=max_delay_seconds,
        jitter_seconds=jitter_seconds,
        now=now,
    )


def reclaim_expired_leases(
    database_url: str,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    now: datetime | None = None,
) -> int:
    """Module-level wrapper for :meth:`WorkQueue.reclaim_expired_leases`."""
    return WorkQueue(database_url).reclaim_expired_leases(
        max_attempts=max_attempts, now=now
    )


__all__ = [
    "DEFAULT_BASE_DELAY_SECONDS",
    "DEFAULT_LEASE_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_DELAY_SECONDS",
    "Job",
    "JobStatus",
    "WorkQueue",
    "claim",
    "claim_job",
    "complete",
    "enqueue",
    "fail",
    "heartbeat",
    "heartbeat_interval_for",
    "reclaim_expired_leases",
]
