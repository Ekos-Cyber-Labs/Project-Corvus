"""Work queue integration tests (always run; never skip)."""

import threading
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from corvus.state.migrate import migrate
from corvus.state.queue import JobStatus, WorkQueue
from tests.conftest import _create_database, _drop_database, _test_database_urls

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def queue_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield WorkQueue(test_url), test_url
    finally:
        _drop_database(admin_url, name)


def _row(test_url: str, job_id: int) -> dict:
    with psycopg.connect(test_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM work_queue WHERE id = %s", (job_id,))
            row = cur.fetchone()
    assert row is not None
    return row


def _count(test_url: str, where: str = "") -> int:
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM work_queue {where}")
            result = cur.fetchone()
    assert result is not None
    return int(result[0])


@pytest.mark.integration
def test_enqueue_same_dedupe_key_returns_same_id_one_row(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    first = queue.enqueue("triage", {"incident": 1}, dedupe_key="job-1", now=T0)
    second = queue.enqueue("triage", {"incident": 1}, dedupe_key="job-1", now=T0)
    assert second == first
    assert _count(test_url) == 1
    row = _row(test_url, first)
    assert row["status"] == "pending"
    assert row["payload"] == {"incident": 1}
    assert row["created_at"] == T0
    assert row["updated_at"] == T0

    # No dedupe key: each enqueue is a distinct job.
    other_a = queue.enqueue("triage", now=T0)
    other_b = queue.enqueue("triage", now=T0)
    assert other_a != other_b
    assert _count(test_url) == 3

    # The key stays taken after the job is done: same id, still one row
    # for that key, and a deliberate re-run needs a new key.
    claimed = queue.claim("worker-1", now=T0, lease_seconds=60)
    assert claimed is not None
    assert claimed.id == first
    assert queue.complete(first, "worker-1", now=T0) is True
    assert queue.enqueue("triage", {"incident": 1}, dedupe_key="job-1", now=T0) == first
    assert _count(test_url) == 3
    assert _row(test_url, first)["status"] == "done"
    rerun = queue.enqueue("triage", {"incident": 1}, dedupe_key="job-1-v2", now=T0)
    assert rerun != first
    assert _count(test_url) == 4


@pytest.mark.integration
def test_claim_orders_by_available_at_then_id_and_skips_future(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, _test_url = queue_db
    queue.enqueue(
        "triage", {"n": "future"}, available_at=T0 + timedelta(hours=1), now=T0
    )
    later = queue.enqueue(
        "triage", {"n": "later"}, available_at=T0 + timedelta(minutes=5), now=T0
    )
    earlier = queue.enqueue("triage", {"n": "earlier"}, available_at=T0, now=T0)
    other_kind = queue.enqueue("rules", {"n": "rules"}, available_at=T0, now=T0)

    first = queue.claim("worker-1", kinds=["triage"], now=T0, lease_seconds=60)
    assert first is not None
    assert first.id == earlier
    assert first.status == JobStatus.LOCKED
    assert first.locked_by == "worker-1"
    assert first.locked_at == T0
    assert first.lease_expires_at == T0 + timedelta(seconds=60)
    assert first.payload == {"n": "earlier"}

    # The only other due triage job is not available yet; rules is another kind.
    assert queue.claim("worker-1", kinds=["triage"], now=T0) is None
    due_later = queue.claim(
        "worker-1", kinds=["triage"], now=T0 + timedelta(minutes=5), lease_seconds=60
    )
    assert due_later is not None
    assert due_later.id == later
    rules = queue.claim("worker-2", kinds=["rules"], now=T0)
    assert rules is not None
    assert rules.id == other_kind


@pytest.mark.integration
def test_concurrent_workers_never_claim_same_job(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_ids = [queue.enqueue("triage", {"n": n}) for n in range(200)]
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    completed: list[int] = []
    errors: list[BaseException] = []

    def run_worker(worker_id: str) -> None:
        try:
            barrier.wait(timeout=30)
            while True:
                job = queue.claim(worker_id, lease_seconds=120)
                if job is None:
                    return
                assert queue.complete(job.id, worker_id)
                with lock:
                    completed.append(job.id)
        except BaseException as exc:  # surfaced by the assertion below
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(target=run_worker, args=(f"worker-{n}",)) for n in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    counts = Counter(completed)
    assert sorted(completed) == sorted(job_ids)
    assert len(completed) == 200
    assert all(counts[job_id] == 1 for job_id in job_ids)
    assert _count(test_url, "WHERE status = 'done'") == 200


@pytest.mark.integration
def test_crashed_worker_reclaimed_and_stale_complete_rejected(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_id = queue.enqueue("triage", {"n": 1}, now=T0)
    claimed = queue.claim("worker-a", now=T0, lease_seconds=30)
    assert claimed is not None
    assert claimed.id == job_id

    # Lease still valid: nothing to reclaim, and no other worker can claim.
    assert queue.reclaim_expired_leases(now=T0 + timedelta(seconds=29)) == 0
    # Lease expired (worker-a crashed): reclaim makes the job pending again.
    assert queue.reclaim_expired_leases(now=T0 + timedelta(seconds=31)) == 1
    row = _row(test_url, job_id)
    assert row["status"] == "pending"
    assert row["attempts"] == 1
    assert row["last_error"] == "lease expired"
    assert row["locked_by"] is None
    assert row["locked_at"] is None
    assert row["lease_expires_at"] is None
    assert row["updated_at"] == T0 + timedelta(seconds=31)

    reclaimed = queue.claim(
        "worker-b", now=T0 + timedelta(seconds=31), lease_seconds=300
    )
    assert reclaimed is not None
    assert reclaimed.id == job_id

    # The stale worker cannot overwrite the new owner's result.
    assert queue.complete(job_id, "worker-a", now=T0 + timedelta(seconds=32)) is False
    assert (
        queue.fail(job_id, "worker-a", "late failure", now=T0 + timedelta(seconds=32))
        is None
    )
    row = _row(test_url, job_id)
    assert row["status"] == "locked"
    assert row["locked_by"] == "worker-b"

    assert queue.complete(job_id, "worker-b", now=T0 + timedelta(seconds=33)) is True
    row = _row(test_url, job_id)
    assert row["status"] == "done"
    assert row["locked_by"] is None


@pytest.mark.integration
def test_failed_jobs_back_off_and_end_dead_after_max_attempts(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_id = queue.enqueue("triage", {"n": 1}, now=T0)
    claimed = queue.claim("worker-1", now=T0, lease_seconds=300)
    assert claimed is not None

    first = queue.fail(
        job_id,
        "worker-1",
        "boom-1",
        max_attempts=3,
        base_delay_seconds=10,
        jitter_seconds=0,
        now=T0,
    )
    assert first is not None
    assert first.status == JobStatus.FAILED
    assert first.attempts == 1
    assert first.last_error == "boom-1"
    assert first.available_at == T0 + timedelta(seconds=10)
    assert first.locked_by is None

    # Not claimable before the backoff elapses; claimable at that instant.
    assert queue.claim("worker-1", now=T0 + timedelta(seconds=9)) is None
    second_claim = queue.claim(
        "worker-1", now=T0 + timedelta(seconds=10), lease_seconds=300
    )
    assert second_claim is not None
    second = queue.fail(
        job_id,
        "worker-1",
        "boom-2",
        max_attempts=3,
        base_delay_seconds=10,
        jitter_seconds=0,
        now=T0 + timedelta(seconds=10),
    )
    assert second is not None
    assert second.status == JobStatus.FAILED
    assert second.attempts == 2
    # Exponential: second failure waits 20s, not 10s.
    assert second.available_at == T0 + timedelta(seconds=30)

    third_claim = queue.claim(
        "worker-1", now=T0 + timedelta(seconds=30), lease_seconds=300
    )
    assert third_claim is not None
    third = queue.fail(
        job_id,
        "worker-1",
        "boom-3",
        max_attempts=3,
        base_delay_seconds=10,
        jitter_seconds=0,
        now=T0 + timedelta(seconds=30),
    )
    assert third is not None
    assert third.status == JobStatus.DEAD
    assert third.attempts == 3
    assert third.last_error == "boom-3"

    # Dead jobs are never claimable or reclaimable.
    assert queue.claim("worker-1", now=T0 + timedelta(days=1)) is None
    assert queue.reclaim_expired_leases(now=T0 + timedelta(days=1)) == 0
    row = _row(test_url, job_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 3
    assert row["last_error"] == "boom-3"


@pytest.mark.integration
def test_heartbeat_by_owner_keeps_job_from_reclaim_past_original_lease(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_id = queue.enqueue("triage", {"n": 1}, now=T0)
    claimed = queue.claim("worker-1", now=T0, lease_seconds=30)
    assert claimed is not None
    assert claimed.lease_expires_at == T0 + timedelta(seconds=30)

    # Owner heartbeats before expiry: lease now runs to T0+50s.
    assert (
        queue.heartbeat(
            job_id, "worker-1", timedelta(seconds=30), now=T0 + timedelta(seconds=20)
        )
        is True
    )
    row = _row(test_url, job_id)
    assert row["lease_expires_at"] == T0 + timedelta(seconds=50)
    assert row["updated_at"] == T0 + timedelta(seconds=20)

    # Past the original lease (T0+30s) the job is not reclaimed...
    assert queue.reclaim_expired_leases(now=T0 + timedelta(seconds=31)) == 0
    assert queue.reclaim_expired_leases(now=T0 + timedelta(seconds=49)) == 0
    # ...the owner can still complete, and only then is it done.
    assert queue.complete(job_id, "worker-1", now=T0 + timedelta(seconds=49)) is True
    assert _row(test_url, job_id)["status"] == "done"


@pytest.mark.integration
def test_heartbeat_by_stale_worker_returns_false(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_id = queue.enqueue("triage", {"n": 1}, now=T0)
    claimed = queue.claim("worker-a", now=T0, lease_seconds=30)
    assert claimed is not None

    # A different worker never owns the lock.
    assert (
        queue.heartbeat(
            job_id, "worker-b", timedelta(seconds=30), now=T0 + timedelta(seconds=10)
        )
        is False
    )
    # The owner's lease already expired: too late to heartbeat.
    assert (
        queue.heartbeat(
            job_id, "worker-a", timedelta(seconds=30), now=T0 + timedelta(seconds=31)
        )
        is False
    )
    # After reclaim and re-claim by worker-b, worker-a is stale.
    assert queue.reclaim_expired_leases(now=T0 + timedelta(seconds=31)) == 1
    reclaimed = queue.claim(
        "worker-b", now=T0 + timedelta(seconds=31), lease_seconds=300
    )
    assert reclaimed is not None
    assert (
        queue.heartbeat(
            job_id, "worker-a", timedelta(seconds=30), now=T0 + timedelta(seconds=32)
        )
        is False
    )
    row = _row(test_url, job_id)
    assert row["locked_by"] == "worker-b"
    assert row["lease_expires_at"] == T0 + timedelta(seconds=331)
    # The new owner's heartbeat still works.
    assert (
        queue.heartbeat(
            job_id, "worker-b", timedelta(seconds=30), now=T0 + timedelta(seconds=32)
        )
        is True
    )


@pytest.mark.integration
def test_job_reclaimed_max_attempts_times_ends_dead(
    queue_db: tuple[WorkQueue, str],
) -> None:
    queue, test_url = queue_db
    job_id = queue.enqueue("triage", {"n": 1}, now=T0)

    # Each cycle: a worker claims, hangs past its lease, reclaim counts it.
    for cycle in range(3):
        start = T0 + timedelta(minutes=cycle * 2)
        claimed = queue.claim("worker-1", now=start, lease_seconds=30)
        assert claimed is not None
        assert claimed.id == job_id
        assert (
            queue.reclaim_expired_leases(
                max_attempts=3, now=start + timedelta(seconds=31)
            )
            == 1
        )
        row = _row(test_url, job_id)
        assert row["attempts"] == cycle + 1
        assert row["last_error"] == "lease expired"
        assert row["locked_by"] is None
        if cycle < 2:
            assert row["status"] == "pending"
        else:
            assert row["status"] == "dead"

    # Dead after the third reclaim: never claimable again.
    assert queue.claim("worker-1", now=T0 + timedelta(days=1)) is None
    row = _row(test_url, job_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 3
    assert row["last_error"] == "lease expired"
