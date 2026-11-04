"""Concurrent sweep tests: workers, ordering, budget, stop, thread safety.

Fakes only (no network, no model calls) except the Postgres
pseudonym test, which uses real concurrent transactions against the
throwaway database. Every Postgres test uses the throwaway-database
helpers (wrong port or database prefix fails, never skips).
"""

from __future__ import annotations

import os
import signal
import threading
import time
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

import corvus.live.sweep as sweep_mod
from corvus.live.sweep import SweepPolicy, effective_policy, sweep_once
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def sweep_db(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name in (
        "SWEEP_INTERVAL_SECONDS",
        "SWEEP_MIN_FLOOR",
        "SWEEP_MAX_ANALYSES",
        "SWEEP_ALWAYS_INJECTION",
        "SWEEP_TRIAGE_WORKERS",
        "SWEEP_LANG",
        "SPEND_CAP_USD",
    ):
        monkeypatch.delenv(name, raising=False)
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _policy(**over: Any) -> SweepPolicy:
    base: dict[str, Any] = {
        "min_floor": 2,
        "max_analyses": 10,
        "always_analyze_injection": True,
        "spend_cap_usd": 100.0,
        "lang": "en",
        "interval_seconds": 300.0,
        "triage_workers": 4,
    }
    base.update(over)
    return SweepPolicy(**base)


def _insert_incident(
    database_url: str,
    key: str,
    floor: int,
    uids: list[str],
) -> int:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, ai_status, techniques, event_uids, first_seen)"
                " VALUES (%s, %s, %s, %s, 'pending', %s, %s, NOW()) RETURNING id",
                (key, f"Incident {key}", floor, floor, Jsonb([]), Jsonb(uids)),
            )
            incident_id = int(cur.fetchone()[0])  # type: ignore[index]
        conn.commit()
    return incident_id


def _fake_poll(
    monkeypatch: pytest.MonkeyPatch,
    plan: list[dict[str, Any]],
) -> None:
    """Replace the poll cycle with a fake that inserts the plan."""

    def _fake(**kwargs: Any) -> Any:
        from corvus.live.poll import (
            PollCycleReport,
            _record_cycle_end,
            _record_cycle_start,
        )

        database_url = kwargs["database_url"]
        cycle_id = _record_cycle_start(database_url)
        report = PollCycleReport(alerts_seen=len(plan), incidents_upserted=len(plan))
        for item in plan:
            _insert_incident(database_url, item["key"], item["floor"], item["uids"])
        _record_cycle_end(database_url, cycle_id, report)
        return report

    monkeypatch.setattr(sweep_mod, "run_poll_cycle", _fake)


class _Outcome:
    status = "resolved"


def _sweep_row(database_url: str) -> Any:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, error_code, analyzed, failed_analyses,"
                " skipped_policy, skipped_budget, policy FROM sweep_runs"
                " ORDER BY id DESC LIMIT 1"
            )
            return cur.fetchone()


def _decisions(database_url: str, run_id: int) -> list[tuple[int, str, str]]:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT incident_id, decision, reason_code FROM sweep_decisions"
                " WHERE sweep_run_id = %s ORDER BY incident_id",
                (run_id,),
            )
            return [(int(r[0]), str(r[1]), str(r[2])) for r in cur.fetchall()]


def test_workers_overlap_with_barrier(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With 4 workers and 4 incidents, all 4 tasks run at the same time."""
    _fake_poll(
        monkeypatch,
        [{"key": f"w{i}", "floor": 5, "uids": [f"u{i}"]} for i in range(4)],
    )
    barrier = threading.Barrier(4, timeout=30.0)
    active = 0
    peak = 0
    lock = threading.Lock()

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            barrier.wait()
        finally:
            with lock:
                active -= 1
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(triage_workers=4),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 4
    assert peak == 4
    assert summary["triage_workers"] == 4


def test_workers_one_never_overlaps(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """workers=1 runs one task at a time in deterministic submit order."""
    _fake_poll(
        monkeypatch,
        [
            {"key": "w-low", "floor": 3, "uids": ["u1"]},
            {"key": "w-mid", "floor": 4, "uids": ["u2", "u3"]},
            {"key": "w-high", "floor": 5, "uids": ["u4"]},
        ],
    )
    active = 0
    peak = 0
    lock = threading.Lock()
    started: list[int] = []

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            started.append(incident_id)
        try:
            time.sleep(0.05)
        finally:
            with lock:
                active -= 1
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(triage_workers=1),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 3
    assert peak == 1
    with psycopg.connect(sweep_db) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, severity_floor FROM incidents ORDER BY id")
            _rows = list(cur.fetchall())
    by_floor = {int(r[1]): int(r[0]) for r in _rows}
    assert started == [by_floor[5], by_floor[4], by_floor[3]]


def test_failure_isolation_and_counters_add_up(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One task's exception never cancels the others; counters add up."""
    _fake_poll(
        monkeypatch,
        [
            {"key": "f-ok1", "floor": 5, "uids": ["u1"]},
            {"key": "f-boom", "floor": 5, "uids": ["u2"]},
            {"key": "f-busy", "floor": 5, "uids": ["u3"]},
            {"key": "f-low", "floor": 2, "uids": ["u4"]},
        ],
    )

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        with psycopg.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT correlation_key FROM incidents WHERE id = %s",
                    (incident_id,),
                )
                key = str(cur.fetchone()[0])  # type: ignore[index]
        if key == "f-busy":
            return "busy"
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        with psycopg.connect(kwargs["database_url"]) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT correlation_key FROM incidents WHERE id = %s",
                    (incident_id,),
                )
                key = str(cur.fetchone()[0])  # type: ignore[index]
        if key == "f-boom":
            raise RuntimeError("sweep-test-failure-marker")
        return _Outcome()

    policy = _policy(min_floor=4, triage_workers=3)
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=policy,
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 1
    assert summary["failed_analyses"] == 1
    assert summary["skipped_policy"] == 2
    assert summary["skipped_budget"] == 0
    total = (
        summary["analyzed"]
        + summary["failed_analyses"]
        + summary["skipped_policy"]
        + summary["skipped_budget"]
    )
    assert total == summary["candidates"] == 4
    row = _sweep_row(sweep_db)
    assert row[0] == "ok" and row[2] == 1 and row[3] == 1 and row[4] == 2
    rows = _decisions(sweep_db, int(summary["sweep_run_id"]))
    assert len(rows) == 4
    by_reason = {r[2] for r in rows}
    assert by_reason == {"selected", "already_running", "below_min_floor"}
    with psycopg.connect(sweep_db) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incident_analyses")
            assert int(cur.fetchone()[0]) == 0  # type: ignore[index]
    # Only the exception class is recorded anywhere; the message is not.
    with psycopg.connect(sweep_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM sweep_decisions WHERE reason_code LIKE"
                " '%sweep-test-failure-marker%'"
                " OR decision LIKE '%sweep-test-failure-marker%'",
            )
            assert int(cur.fetchone()[0]) == 0  # type: ignore[index]


def test_budget_cap_with_spending_fakes(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent tasks cannot overshoot the cap by more than one hold.

    Cap 25 USD, six tasks each spending 10 USD through the real ledger,
    one 10 USD hold per task: exactly two tasks spend (20 USD) and the
    other four are recorded ``skipped_budget`` without model calls, so
    the final spend stays within cap plus one reservation.
    """
    from corvus.llm.price_book import ModelPrice
    from corvus.llm.spend import record_spend, spent_usd

    prices = {
        "fake-sweep": ModelPrice(
            model="fake-sweep",
            input_per_mtok=0.0,
            cached_input_per_mtok=0.0,
            output_per_mtok=10000.0,
            source="test",
            date="2026-11-04",
        )
    }
    monkeypatch.setattr(sweep_mod, "_task_reservation_usd", lambda: 10.0)
    _fake_poll(
        monkeypatch,
        [{"key": f"b{i}", "floor": 5, "uids": [f"u{i}"]} for i in range(6)],
    )
    model_calls = 0
    lock = threading.Lock()

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        nonlocal model_calls
        with lock:
            model_calls += 1
        record_spend(
            "fake-sweep",
            0,
            0,
            1000,
            incident_id,
            database_url=database_url,
            prices=prices,
        )
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(min_floor=4, max_analyses=6, spend_cap_usd=25.0),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 2
    assert summary["skipped_budget"] == 4
    assert summary["failed_analyses"] == 0
    total = (
        summary["analyzed"]
        + summary["failed_analyses"]
        + summary["skipped_policy"]
        + summary["skipped_budget"]
    )
    assert total == summary["candidates"] == 6
    assert model_calls == 2
    final_spend = spent_usd(sweep_db)
    assert final_spend == 20.0
    assert final_spend <= 25.0 + 10.0


def test_worker_recheck_exact_cap(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A task starting exactly at the cap is skipped without a model call.

    Cap 10 USD, two tasks each spending 10 USD, zero sweep hold: the
    first task spends to exactly the cap, so the second task's
    re-check (``>=``) must refuse it. With ``>`` (or no re-check) the
    zero hold would still be admitted by ``reserve`` and the second
    task would call the model, so this test kills both mutants.
    """
    from corvus.llm.price_book import ModelPrice
    from corvus.llm.spend import record_spend

    prices = {
        "fake-sweep": ModelPrice(
            model="fake-sweep",
            input_per_mtok=0.0,
            cached_input_per_mtok=0.0,
            output_per_mtok=10000.0,
            source="test",
            date="2026-11-04",
        )
    }
    monkeypatch.setattr(sweep_mod, "_task_reservation_usd", lambda: 0.0)
    _fake_poll(
        monkeypatch,
        [
            {"key": "e-first", "floor": 5, "uids": ["u1"]},
            {"key": "e-second", "floor": 5, "uids": ["u2"]},
        ],
    )
    model_calls = 0

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        nonlocal model_calls
        model_calls += 1
        record_spend(
            "fake-sweep",
            0,
            0,
            1000,
            incident_id,
            database_url=database_url,
            prices=prices,
        )
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(
            min_floor=4, max_analyses=2, spend_cap_usd=10.0, triage_workers=1
        ),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 1
    assert summary["skipped_budget"] == 1
    assert model_calls == 1


@pytest.mark.parametrize("reservation", [10.0, 0.0])
def test_zero_cap_calls_no_model(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch, reservation: float
) -> None:
    """A cap already reached means no task calls any model.

    The zero reservation pins the ``>=`` boundary: with ``>`` instead,
    a zero hold would pass the re-check and ``reserve`` would admit it,
    so this test kills that mutant.
    """
    monkeypatch.setattr(sweep_mod, "_task_reservation_usd", lambda: reservation)
    _fake_poll(
        monkeypatch,
        [{"key": f"z{i}", "floor": 5, "uids": [f"u{i}"]} for i in range(3)],
    )
    model_calls = 0

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        nonlocal model_calls
        model_calls += 1
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        nonlocal model_calls
        model_calls += 1
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(spend_cap_usd=0.0),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 0
    assert summary["skipped_budget"] == 3
    assert model_calls == 0


def test_stop_event_stops_submission(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stop request runs no new tasks and ends the row ok/stopped."""
    _fake_poll(
        monkeypatch,
        [{"key": f"s{i}", "floor": 5, "uids": [f"u{i}"]} for i in range(4)],
    )
    started: list[int] = []
    lock = threading.Lock()
    proceed = threading.Event()

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        with lock:
            started.append(incident_id)
        assert proceed.wait(timeout=30.0)
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    stop = threading.Event()

    def _release() -> None:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            with lock:
                if len(started) >= 2:
                    break
            time.sleep(0.02)
        stop.set()
        proceed.set()

    helper = threading.Thread(target=_release, daemon=True)
    helper.start()
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(triage_workers=2),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
        stop_event=stop,
        stop_grace_seconds=60.0,
    )
    helper.join(timeout=30.0)
    assert summary["stopped_early"] is True
    assert len(started) == 2
    rows = _decisions(sweep_db, int(summary["sweep_run_id"]))
    stopped = [r for r in rows if r[2] == "cycle_stopped"]
    assert len(stopped) == 2
    total = (
        summary["analyzed"]
        + summary["failed_analyses"]
        + summary["skipped_policy"]
        + summary["skipped_budget"]
    )
    assert total == summary["candidates"] == 4
    row = _sweep_row(sweep_db)
    assert row[0] == "ok" and row[1] == "stopped"
    assert summary["analyzed"] == 2


def test_sigterm_during_cycle(sweep_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real SIGTERM mid-cycle stops submission and ends the row cleanly."""
    _fake_poll(
        monkeypatch,
        [{"key": f"t{i}", "floor": 5, "uids": [f"u{i}"]} for i in range(3)],
    )
    started: list[int] = []
    lock = threading.Lock()
    proceed = threading.Event()
    before = signal.getsignal(signal.SIGTERM)

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        with lock:
            started.append(incident_id)
        assert proceed.wait(timeout=30.0)
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        return _Outcome()

    def _kill() -> None:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            with lock:
                if len(started) >= 1:
                    break
            time.sleep(0.02)
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.5)
        proceed.set()

    helper = threading.Thread(target=_kill, daemon=True)
    helper.start()
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(triage_workers=1),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
        stop_grace_seconds=60.0,
    )
    helper.join(timeout=30.0)
    assert signal.getsignal(signal.SIGTERM) == before
    assert summary["stopped_early"] is True
    assert len(started) == 1
    row = _sweep_row(sweep_db)
    assert row[0] == "ok" and row[1] == "stopped"


def test_worker_rechecks_already_analyzed(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An incident resolved mid-cycle is skipped without model calls."""
    _fake_poll(
        monkeypatch,
        [
            {"key": "r-first", "floor": 5, "uids": ["u1"]},
            {"key": "r-second", "floor": 5, "uids": ["u2"]},
        ],
    )
    model_calls: list[int] = []
    second_id: list[int] = []

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        with psycopg.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, correlation_key FROM incidents WHERE id = %s",
                    (incident_id,),
                )
                row = cur.fetchone()
                assert row is not None
                key = str(row[1])
                cur.execute(
                    "SELECT id FROM incidents WHERE correlation_key = 'r-second'"
                )
                found = cur.fetchone()
                assert found is not None
                if not second_id:
                    second_id.append(int(found[0]))
        if key == "r-first":
            with psycopg.connect(database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO incident_analyses (incident_id, stage,"
                        " status, payload, language, model,"
                        " deterministic_floor)"
                        " VALUES (%s, 'analysis', 'resolved', %s, 'en',"
                        " 'test', 5)",
                        (second_id[0], Jsonb({"verdict": "true_positive"})),
                    )
                conn.commit()
            model_calls.append(incident_id)
            return "resolved"
        model_calls.append(incident_id)
        return "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        model_calls.append(incident_id)
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(triage_workers=1),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 1
    assert summary["skipped_policy"] == 1
    rows = _decisions(sweep_db, int(summary["sweep_run_id"]))
    by_id = {r[0]: (r[1], r[2]) for r in rows}
    assert by_id[second_id[0]] == ("skipped_policy", "already_analyzed")
    assert model_calls.count(second_id[0]) == 0


def test_triage_workers_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """--triage-workers / SWEEP_TRIAGE_WORKERS accept only 1..16."""
    for name in (
        "SWEEP_INTERVAL_SECONDS",
        "SWEEP_MIN_FLOOR",
        "SWEEP_MAX_ANALYSES",
        "SWEEP_ALWAYS_INJECTION",
        "SWEEP_TRIAGE_WORKERS",
        "SWEEP_LANG",
        "SPEND_CAP_USD",
    ):
        monkeypatch.delenv(name, raising=False)
    assert effective_policy().triage_workers == 4
    assert effective_policy(triage_workers=1).triage_workers == 1
    assert effective_policy(triage_workers=16).triage_workers == 16
    for bad in (0, 17, -1, True, False, 4.0, "8"):
        with pytest.raises(ValueError):
            effective_policy(triage_workers=bad)  # type: ignore[arg-type]
    for raw in ("0", "17", "-1", "text", "true", "1.5", ""):
        monkeypatch.setenv("SWEEP_TRIAGE_WORKERS", raw)
        if raw == "":
            assert effective_policy().triage_workers == 4
        else:
            with pytest.raises(ValueError):
                effective_policy()
    for raw, want in (("1", 1), ("16", 16), (" 4 ", 4)):
        monkeypatch.setenv("SWEEP_TRIAGE_WORKERS", raw)
        assert effective_policy().triage_workers == want
    monkeypatch.setenv("SWEEP_TRIAGE_WORKERS", "2")
    assert effective_policy(triage_workers=7).triage_workers == 7


def test_settings_route_shows_triage_workers(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/settings carries the resolved worker count."""
    from fastapi.testclient import TestClient

    from corvus.api.main import app

    monkeypatch.setenv("DATABASE_URL", sweep_db)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("META_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("SWEEP_TRIAGE_WORKERS", "6")
    body = TestClient(app, raise_server_exceptions=False).get("/api/settings").json()
    assert body["sweep_policy"]["source"] == "configured"
    assert body["sweep_policy"]["policy"]["triage_workers"] == 6


def test_pseudonym_concurrent_same_host(sweep_db: str) -> None:
    """Concurrent allocations agree: one value, one pseudonym.

    Two threads registering the same host (plus two distinct hosts)
    through separate connections must see the same pseudonym for the
    shared value and different pseudonyms for different values, with
    no UNIQUE(pseudonym) violation and no pseudonym shared by two
    values — the advisory transaction lock in ``register`` serializes
    the allocations.
    """
    from corvus.guardrails.pseudonymizer import Pseudonymizer

    barrier = threading.Barrier(2, timeout=30.0)
    results: list[dict[tuple[str, str], str]] = []
    errors: list[Exception] = []

    def _register() -> None:
        try:
            barrier.wait()
            mapping = Pseudonymizer(sweep_db).register(
                [
                    ("host", "web01-sweep-concurrency"),
                    ("host", "web02-sweep-concurrency"),
                ]
            )
            results.append(mapping)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_register) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30.0)
    assert not errors
    assert len(results) == 2
    assert (
        results[0][("host", "web01-sweep-concurrency")]
        == results[1][("host", "web01-sweep-concurrency")]
    )
    assert (
        results[0][("host", "web02-sweep-concurrency")]
        == results[1][("host", "web02-sweep-concurrency")]
    )
    assert (
        results[0][("host", "web01-sweep-concurrency")]
        != results[0][("host", "web02-sweep-concurrency")]
    )
    with psycopg.connect(sweep_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT pseudonym, COUNT(DISTINCT entity_value)"
                " FROM pseudonyms WHERE entity_kind = 'host'"
                " AND entity_value LIKE '%sweep-concurrency%'"
                " GROUP BY pseudonym HAVING COUNT(DISTINCT entity_value) > 1"
            )
            assert cur.fetchall() == []
            cur.execute(
                "SELECT entity_value, COUNT(DISTINCT pseudonym)"
                " FROM pseudonyms WHERE entity_kind = 'host'"
                " AND entity_value LIKE '%sweep-concurrency%'"
                " GROUP BY entity_value HAVING COUNT(DISTINCT pseudonym) > 1"
            )
            assert cur.fetchall() == []
