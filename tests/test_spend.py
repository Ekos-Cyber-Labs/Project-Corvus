"""Spend ledger and USD budget guard (Postgres-backed)."""

import threading

import psycopg
import pytest

from corvus.llm.price_book import PriceBookError
from corvus.llm.spend import (
    BudgetExceededError,
    ConversionResult,
    budget_state,
    convert_reservation,
    get_spend_cap,
    held_usd,
    hold_ttl,
    purge_expired_reservations,
    record_spend,
    release_reservation,
    reserve,
    spent_usd,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def spend_db() -> str:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _row(test_url: str) -> tuple:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT model, tokens_in, tokens_out, usd, incident_id "
                "FROM spend ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            assert row is not None
            return row


def test_record_spend_computes_usd(spend_db: str) -> None:
    usd = record_spend("muse-spark-1.3", 1000, 200, 500, None, spend_db)
    assert usd == pytest.approx(0.003155)
    model, tokens_in, tokens_out, stored_usd, incident_id = _row(spend_db)
    assert model == "muse-spark-1.3"
    assert (tokens_in, tokens_out) == (1000, 500)
    assert float(stored_usd) == pytest.approx(0.003155)
    assert incident_id is None
    assert spent_usd(spend_db) == pytest.approx(0.003155)


def test_local_model_spend_is_zero(spend_db: str) -> None:
    usd = record_spend("glimmer", 10000, 1000, 5000, None, spend_db)
    assert usd == 0.0
    assert float(_row(spend_db)[3]) == 0.0


def test_record_spend_rejects_unknown_model(spend_db: str) -> None:
    with pytest.raises(PriceBookError, match="unknown model"):
        record_spend("nope", 10, 0, 10, None, spend_db)


def test_budget_state_and_cap(spend_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPEND_CAP_USD", raising=False)
    assert get_spend_cap() == 100.0
    assert budget_state(database_url=spend_db) == "ok"
    assert budget_state(0.01, spend_db) == "ok"
    record_spend("muse-spark-1.3", 1000, 200, 500, None, spend_db)
    assert budget_state(0.003, spend_db) == "degraded"
    assert budget_state(100.0, spend_db) == "ok"
    monkeypatch.setenv("SPEND_CAP_USD", "0.001")
    assert get_spend_cap() == pytest.approx(0.001)
    assert budget_state(database_url=spend_db) == "degraded"
    monkeypatch.setenv("SPEND_CAP_USD", "bogus")
    with pytest.raises(ValueError, match="SPEND_CAP_USD"):
        get_spend_cap()


def test_reserve_refuse_release_convert(spend_db: str) -> None:
    first = reserve(0.6, spend_db, cap_usd=1.0)
    assert held_usd(spend_db) == pytest.approx(0.6)
    with pytest.raises(BudgetExceededError):
        reserve(0.5, spend_db, cap_usd=1.0)
    assert release_reservation(first.id, spend_db) is True
    assert release_reservation(first.id, spend_db) is False
    assert held_usd(spend_db) == 0.0
    second = reserve(0.5, spend_db, cap_usd=1.0)
    result = convert_reservation(
        second.id, "muse-spark-1.3", 100, 0, 100, None, spend_db
    )
    assert isinstance(result, ConversionResult)
    assert result.hold_active is True
    expected = (100 * 1.25 + 100 * 4.25) / 1e6
    assert result.usd == pytest.approx(expected)
    assert held_usd(spend_db) == 0.0
    assert spent_usd(spend_db) == pytest.approx(expected)
    # Converting the same id again still records the spend; the hold is gone.
    again = convert_reservation(second.id, "glimmer", 1, 0, 1, None, spend_db)
    assert again.hold_active is False
    assert again.usd == 0.0
    assert spent_usd(spend_db) == pytest.approx(expected)


def test_concurrent_reserves_never_overshoot(spend_db: str) -> None:
    barrier = threading.Barrier(8)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            reservation = reserve(0.3, spend_db, cap_usd=1.0)
            ok = reservation is not None
        except BudgetExceededError:
            ok = False
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count(True) == 3
    assert held_usd(spend_db) == pytest.approx(0.9)
    assert spent_usd(spend_db) == 0.0


def test_expired_reservations_free_the_budget(spend_db: str) -> None:
    reserve(1.0, spend_db, cap_usd=1.0, ttl_seconds=0)
    assert held_usd(spend_db) == 0.0
    # The expired hold no longer blocks a full-cap reservation.
    fresh = reserve(1.0, spend_db, cap_usd=1.0)
    assert held_usd(spend_db) == pytest.approx(1.0)
    assert purge_expired_reservations(spend_db) >= 1
    assert release_reservation(fresh.id, spend_db) is True
    assert held_usd(spend_db) == 0.0


def test_convert_expired_purged_hold_still_records_spend(
    spend_db: str,
) -> None:
    expired = reserve(1.0, spend_db, cap_usd=1.0, ttl_seconds=0)
    assert purge_expired_reservations(spend_db) >= 1
    result = convert_reservation(
        expired.id, "muse-spark-1.3", 1000, 200, 500, None, spend_db
    )
    assert result.hold_active is False
    assert result.usd == pytest.approx(0.003155)
    assert float(_row(spend_db)[3]) == pytest.approx(0.003155)
    assert spent_usd(spend_db) == pytest.approx(0.003155)


def test_convert_unknown_id_records_spend(spend_db: str) -> None:
    result = convert_reservation(
        999999999, "muse-spark-1.3", 100, 0, 100, None, spend_db
    )
    assert result.hold_active is False
    assert result.usd == pytest.approx((100 * 1.25 + 100 * 4.25) / 1e6)
    assert spent_usd(spend_db) == pytest.approx(result.usd)


def test_convert_logs_nothing(spend_db: str, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("DEBUG"):
        result = convert_reservation(
            999999998, "muse-spark-1.3", 10, 0, 10, None, spend_db
        )
    assert result.hold_active is False
    assert caplog.text == ""


def test_hold_ttl_covers_timeout_times_attempts_plus_margin() -> None:
    assert hold_ttl(30.0, 3) == pytest.approx(30.0 * 3 + 60.0)
    assert hold_ttl(30.0, 3, 0.0) == pytest.approx(90.0)
    with pytest.raises(ValueError, match="request_timeout_seconds"):
        hold_ttl(0.0, 3)
    with pytest.raises(ValueError, match="max_attempts"):
        hold_ttl(30.0, 0)
    with pytest.raises(ValueError, match="margin_seconds"):
        hold_ttl(30.0, 3, -1.0)


def test_reserve_rejects_negative(spend_db: str) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        reserve(-1.0, spend_db, cap_usd=1.0)


def test_reserve_rejects_non_finite_amounts(spend_db: str) -> None:
    # NaN would poison the SUM comparisons and bypass the cap; inf can
    # never fit under a finite cap, so both are refused up front.
    with pytest.raises(ValueError, match="finite"):
        reserve(float("nan"), spend_db, cap_usd=1.0)
    with pytest.raises(ValueError, match="finite"):
        reserve(float("inf"), spend_db, cap_usd=1.0)
    assert held_usd(spend_db) == 0.0


def test_non_finite_cap_rejected(spend_db: str) -> None:
    with pytest.raises(ValueError, match="finite"):
        budget_state(float("nan"), spend_db)
