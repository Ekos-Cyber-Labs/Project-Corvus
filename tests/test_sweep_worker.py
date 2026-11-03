"""Sweep worker tests with fakes only (no network, no model calls).

The SIEM side is faked by replacing
:func:`corvus.live.sweep.run_poll_cycle` with a stand-in that writes
the same ``wazuh_poll_cycles`` bookkeeping through the real poll
helpers and inserts incidents directly. Analysis is faked with small
runners. Every Postgres test uses the throwaway-database helpers.
"""

from __future__ import annotations

import time
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

import corvus.live.sweep as sweep_mod
from corvus.live.sweep import (
    SweepPolicy,
    effective_policy,
    run_sweep_loop,
    sweep_once,
    try_acquire_sweep_lock,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def sweep_db(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name in (
        "SWEEP_INTERVAL_SECONDS",
        "SWEEP_MIN_FLOOR",
        "SWEEP_MAX_ANALYSES",
        "SWEEP_ALWAYS_INJECTION",
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
        "min_floor": 4,
        "max_analyses": 5,
        "always_analyze_injection": True,
        "spend_cap_usd": 100.0,
        "lang": "en",
        "interval_seconds": 300.0,
    }
    base.update(over)
    return SweepPolicy(**base)


def _insert_incident(
    database_url: str,
    key: str,
    floor: int,
    uids: list[str],
    injection: bool = False,
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
            if injection:
                cur.execute(
                    "INSERT INTO incident_signals (incident_id, kind, event_uid,"
                    " field, pattern_id, requested_effect) VALUES"
                    " (%s, 'injection', %s, 'command', 'exec-echo', 'suppress')",
                    (incident_id, uids[0] if uids else "evt-x"),
                )
        conn.commit()
    return incident_id


def _fake_poll(
    monkeypatch: pytest.MonkeyPatch,
    plan: list[dict[str, Any]] | Exception,
    calls: list[str],
) -> None:
    """Replace the poll cycle with a fake that books a real cycle row."""

    def _fake(**kwargs: Any) -> Any:
        from corvus.live.poll import (
            PollCycleReport,
            _record_cycle_end,
            _record_cycle_start,
        )

        calls.append("poll")
        database_url = kwargs["database_url"]
        if isinstance(plan, Exception):
            raise plan
        cycle_id = _record_cycle_start(database_url)
        report = PollCycleReport(alerts_seen=1, incidents_upserted=len(plan))
        for item in plan:
            _insert_incident(
                database_url,
                item["key"],
                item["floor"],
                item["uids"],
                item.get("injection", False),
            )
        _record_cycle_end(database_url, cycle_id, report)
        return report

    monkeypatch.setattr(sweep_mod, "run_poll_cycle", _fake)


def _ok_runners(calls: list[tuple[str, int]]) -> tuple[Any, Any]:
    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        calls.append(("triage", incident_id))
        return "resolved"

    class _Outcome:
        status = "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        calls.append(("analysis", incident_id))
        return _Outcome()

    return triage, analysis


def _sweep_row(database_url: str) -> Any:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, analyzed, failed_analyses, skipped_policy,"
                " skipped_budget, poll_cycle_id, policy FROM sweep_runs"
                " ORDER BY id DESC LIMIT 1"
            )
            return cur.fetchone()


def test_threshold_and_ranking(sweep_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    _fake_poll(
        monkeypatch,
        [
            {"key": "a-low", "floor": 2, "uids": ["u1"]},
            {"key": "b-high", "floor": 4, "uids": ["u2", "u3"]},
            {"key": "c-crit", "floor": 5, "uids": ["u4"]},
        ],
        calls,
    )
    ran: list[tuple[str, int]] = []
    triage, analysis = _ok_runners(ran)
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(min_floor=4, max_analyses=2),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 2
    assert summary["skipped_policy"] == 1
    analyzed_ids = [i for kind, i in ran if kind == "analysis"]
    assert len(analyzed_ids) == 2
    row = _sweep_row(sweep_db)
    assert row[0] == "ok" and row[1] == 2 and row[3] == 1
    assert row[5] is not None


def test_injection_override_and_opt_out(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for always in (True, False):
        calls: list[str] = []
        key = f"inj-{int(always)}"
        _fake_poll(
            monkeypatch,
            [{"key": key, "floor": 2, "uids": [f"uid-{key}"], "injection": True}],
            calls,
        )
        ran: list[tuple[str, int]] = []
        triage, analysis = _ok_runners(ran)
        summary = sweep_once(
            database_url=sweep_db,
            store_dir="/tmp/sweep-test-store",
            replay_dir="data/replay",
            policy=_policy(always_analyze_injection=always),
            adapter_factory=lambda: object(),
            triage_runner=triage,
            analysis_runner=analysis,
        )
        assert summary["analyzed"] == (1 if always else 0)


def test_spend_cap_skips_budget_but_collects(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _fake_poll(
        monkeypatch,
        [{"key": "cap-1", "floor": 6, "uids": ["u9"]}],
        calls,
    )
    ran: list[tuple[str, int]] = []
    triage, analysis = _ok_runners(ran)
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
    assert summary["skipped_budget"] == 1
    assert ran == []
    row = _sweep_row(sweep_db)
    assert row[0] == "ok" and row[4] == 1


def test_one_backend_failure_never_stops_cycle(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _fake_poll(
        monkeypatch,
        [
            {"key": "f1", "floor": 5, "uids": ["u1"]},
            {"key": "f2", "floor": 5, "uids": ["u2"]},
        ],
        calls,
    )
    seen: list[int] = []

    def triage(database_url: str, incident_id: int, **kwargs: Any) -> str:
        return "resolved"

    class _Outcome:
        status = "resolved"

    def analysis(incident_id: int, **kwargs: Any) -> Any:
        seen.append(incident_id)
        if len(seen) == 1:
            raise RuntimeError("spark is down")
        return _Outcome()

    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 2
    assert summary["failed_analyses"] == 1
    assert len(seen) == 2


def test_no_double_analysis(sweep_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = _insert_incident(sweep_db, "grown", 5, ["u1"])

    def _grow(**kwargs: Any) -> Any:
        from corvus.live.poll import (
            PollCycleReport,
            _record_cycle_end,
            _record_cycle_start,
        )

        database_url = kwargs["database_url"]
        cycle_id = _record_cycle_start(database_url)
        with psycopg.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE incidents SET event_uids = event_uids || %s WHERE id = %s",
                    (Jsonb(["u2"]), incident_id),
                )
                cur.execute(
                    "INSERT INTO incident_analyses (incident_id, stage, status,"
                    " payload, language, model, deterministic_floor)"
                    " VALUES (%s, 'analysis', 'resolved', %s, 'en', 'm', 5)",
                    (incident_id, Jsonb({"verdict": "true_positive"})),
                )
            conn.commit()
        report = PollCycleReport(incidents_upserted=1)
        _record_cycle_end(database_url, cycle_id, report)
        return report

    monkeypatch.setattr(sweep_mod, "run_poll_cycle", _grow)
    ran: list[tuple[str, int]] = []
    triage, analysis = _ok_runners(ran)
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 0
    assert ran == []
    with psycopg.connect(sweep_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT decision, reason_code FROM sweep_decisions"
                " WHERE incident_id = %s",
                (incident_id,),
            )
            row = cur.fetchone()
    assert (
        row is not None and row[0] == "skipped_policy" and row[1] == "already_analyzed"
    )


def test_wazuh_failure_then_recovery(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    boom = ConnectionError("indexer down")

    def _boom(**kwargs: Any) -> Any:
        from corvus.live.poll import (
            PollCycleReport,
            _record_cycle_failed,
            _record_cycle_start,
        )

        calls.append("poll")
        database_url = kwargs["database_url"]
        cycle_id = _record_cycle_start(database_url)
        _record_cycle_failed(
            database_url, cycle_id, PollCycleReport(), type(boom).__name__
        )
        raise boom

    monkeypatch.setattr(sweep_mod, "run_poll_cycle", _boom)
    ran: list[tuple[str, int]] = []
    triage, analysis = _ok_runners(ran)
    with pytest.raises(ConnectionError):
        sweep_once(
            database_url=sweep_db,
            store_dir="/tmp/sweep-test-store",
            replay_dir="data/replay",
            policy=_policy(),
            adapter_factory=lambda: object(),
            triage_runner=triage,
            analysis_runner=analysis,
        )
    row = _sweep_row(sweep_db)
    assert row[0] == "failed" and row[5] is not None
    _fake_poll(monkeypatch, [{"key": "back", "floor": 5, "uids": ["u1"]}], calls)
    summary = sweep_once(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        replay_dir="data/replay",
        policy=_policy(),
        adapter_factory=lambda: object(),
        triage_runner=triage,
        analysis_runner=analysis,
    )
    assert summary["analyzed"] == 1
    assert _sweep_row(sweep_db)[0] == "ok"


def test_advisory_lock_overlap(sweep_db: str) -> None:
    first = try_acquire_sweep_lock(sweep_db)
    assert first is not None
    try:
        assert try_acquire_sweep_lock(sweep_db) is None
    finally:
        first.close()
    second = try_acquire_sweep_lock(sweep_db)
    assert second is not None
    second.close()


def test_sweep_command_second_exits_cleanly(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from corvus.cli import main

    monkeypatch.setenv("DATABASE_URL", sweep_db)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.example.com:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "tester")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "dummy-not-used")
    first = try_acquire_sweep_lock(sweep_db)
    assert first is not None
    try:
        code = main(["sweep", "--once"])
    finally:
        first.close()
    assert code == 0
    assert "already running" in capsys.readouterr().out


def test_stop_flag_stops_after_current_step(
    sweep_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = [False]
    seen: list[dict[str, Any]] = []

    def _fake(**kwargs: Any) -> Any:
        from corvus.live.poll import (
            PollCycleReport,
            _record_cycle_end,
            _record_cycle_start,
        )

        stop[0] = True
        database_url = kwargs["database_url"]
        cycle_id = _record_cycle_start(database_url)
        report = PollCycleReport()
        _record_cycle_end(database_url, cycle_id, report)
        return report

    monkeypatch.setattr(sweep_mod, "run_poll_cycle", _fake)
    code = run_sweep_loop(
        database_url=sweep_db,
        store_dir="/tmp/sweep-test-store",
        policy=_policy(),
        once=False,
        stop_flag=stop,
        on_cycle=seen.append,
        adapter_factory=lambda: object(),
    )
    assert code == 0
    assert len(seen) == 1


def test_interruptible_sleep_returns_early() -> None:
    from corvus.live.sweep import _interruptible_sleep

    started = time.monotonic()
    _interruptible_sleep(30.0, [True])
    assert time.monotonic() - started < 5.0


def test_effective_policy_env_flag_precedence_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWEEP_MIN_FLOOR", "low")
    assert effective_policy(min_floor="critical").min_floor == 5
