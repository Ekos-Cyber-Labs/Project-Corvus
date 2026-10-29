"""record_attempt: attempt row plus exactly-once reservation spend."""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from corvus.llm.attempts import record_attempt
from corvus.llm.price_book import PriceBookError, cost_usd, load_price_book
from corvus.llm.spend import held_usd, reserve
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def llm_db() -> str:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _base_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "call_id": "call-1",
        "incident_id": None,
        "model": "muse-spark-1.3",
        "purpose": "analysis",
        "attempt_number": 1,
        "failed_validator": None,
        "errors": [],
        "prompt_tokens": 240,
        "cached_tokens": 0,
        "reasoning_tokens": 267,
        "answer_tokens": 88,
        "overhead_tokens": 10,
        "token_source": "exact_ids",
        "latency_ms": 12,
        "outcome": "ok",
        "reasoning": "audit trace",
        "billed": True,
        "reservation_id": None,
    }
    kwargs.update(overrides)
    return kwargs


def _attempt_row(test_url: str) -> tuple:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT call_id, incident_id, model, purpose, attempt_number, "
                "failed_validator, errors, prompt_tokens, cached_tokens, "
                "reasoning_tokens, answer_tokens, overhead_tokens, "
                "latency_ms, outcome, token_source, reasoning "
                "FROM llm_attempts ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            assert row is not None
            return row


def _spend_rows(test_url: str) -> list:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT model, tokens_in, tokens_out, usd, incident_id "
                "FROM spend ORDER BY id"
            )
            return list(cur.fetchall())


def _attempt_count(test_url: str) -> int:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM llm_attempts")
            row = cur.fetchone()
            assert row is not None
            return int(row[0])


def _reservation_status(test_url: str, reservation_id: int) -> str | None:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM spend_reservations WHERE id = %s",
                (reservation_id,),
            )
            row = cur.fetchone()
            return None if row is None else str(row[0])


def test_record_attempt_billed_converts_once(llm_db: str) -> None:
    hold = reserve(0.05, llm_db)
    attempt_id, conversion = record_attempt(
        **_base_kwargs(reservation_id=hold.id), database_url=llm_db
    )
    assert isinstance(attempt_id, int)
    assert conversion is not None
    assert conversion.hold_active is True
    prices = load_price_book()
    expected = cost_usd(prices, "muse-spark-1.3", 240, 0, 365)
    assert conversion.usd == pytest.approx(expected)
    row = _attempt_row(llm_db)
    assert row[0] == "call-1"
    assert row[1] is None
    assert (row[2], row[3], row[4]) == ("muse-spark-1.3", "analysis", 1)
    assert row[5] is None
    assert list(row[6]) == []
    assert (row[7], row[8], row[9], row[10], row[11]) == (240, 0, 267, 88, 10)
    assert row[12] == 12
    assert (row[13], row[14]) == ("ok", "exact_ids")
    assert row[15] == "audit trace"
    spend = _spend_rows(llm_db)
    assert len(spend) == 1
    assert spend[0][0] == "muse-spark-1.3"
    assert (spend[0][1], spend[0][2]) == (240, 365)
    # spend.usd is NUMERIC(12, 6): the stored value is rounded to 6 decimals.
    assert float(spend[0][3]) == pytest.approx(round(expected, 6))
    assert spend[0][4] is None
    assert _reservation_status(llm_db, hold.id) == "converted"
    assert held_usd(llm_db) == 0.0


def test_record_attempt_double_conversion_spends_once_for_hold(
    llm_db: str,
) -> None:
    hold = reserve(0.05, llm_db)
    _, first = record_attempt(
        **_base_kwargs(call_id="c1", reservation_id=hold.id), database_url=llm_db
    )
    _, second = record_attempt(
        **_base_kwargs(call_id="c2", reservation_id=hold.id), database_url=llm_db
    )
    assert first is not None and first.hold_active is True
    # The hold is consumed exactly once; the second call says so.
    assert second is not None and second.hold_active is False
    assert _attempt_count(llm_db) == 2
    assert len(_spend_rows(llm_db)) == 2
    assert _reservation_status(llm_db, hold.id) == "converted"


def test_record_attempt_failure_after_insert_rolls_back(llm_db: str) -> None:
    """An unknown model fails cost math after the attempt insert.

    Nothing lands: no attempt row, no spend row, and the hold stays.
    """
    hold = reserve(0.05, llm_db)
    with pytest.raises(PriceBookError):
        record_attempt(
            **_base_kwargs(model="no-such-model", reservation_id=hold.id),
            database_url=llm_db,
        )
    assert _attempt_count(llm_db) == 0
    assert _spend_rows(llm_db) == []
    assert _reservation_status(llm_db, hold.id) == "held"
    assert held_usd(llm_db) == pytest.approx(0.05)


def test_record_attempt_billed_without_reservation_rejected() -> None:
    """Billed without a reservation fails before any database connection."""
    with pytest.raises(ValueError, match="reservation_id"):
        record_attempt(
            **_base_kwargs(billed=True, reservation_id=None),
            database_url="postgresql://127.0.0.1:1/unreachable",
        )


def test_record_attempt_unbilled_rejects_reservation() -> None:
    with pytest.raises(ValueError, match="reservation_id"):
        record_attempt(
            **_base_kwargs(billed=False, reservation_id=7),
            database_url="postgresql://127.0.0.1:1/unreachable",
        )


def test_record_attempt_unbilled_writes_no_spend(llm_db: str) -> None:
    attempt_id, conversion = record_attempt(
        **_base_kwargs(
            call_id="call-2",
            model="glimmer",
            purpose="triage",
            billed=False,
            reservation_id=None,
            failed_validator="schema",
            errors=["not JSON"],
            token_source="estimated",
            latency_ms=None,
            reasoning=None,
            outcome="retry",
            reasoning_tokens=61,
            answer_tokens=0,
            overhead_tokens=3,
        ),
        database_url=llm_db,
    )
    assert isinstance(attempt_id, int)
    assert conversion is None
    row = _attempt_row(llm_db)
    assert (row[0], row[5], row[13], row[14]) == (
        "call-2",
        "schema",
        "retry",
        "estimated",
    )
    assert list(row[6]) == ["not JSON"]
    assert row[12] is None
    assert _spend_rows(llm_db) == []


def test_record_attempt_errors_round_trip(llm_db: str) -> None:
    mapping = {"code": "SCHEMA", "path": "summary", "message": "missing"}
    hold = reserve(0.05, llm_db)
    _, conversion = record_attempt(
        **_base_kwargs(errors=["plain", mapping], reservation_id=hold.id),
        database_url=llm_db,
    )
    assert conversion is not None and conversion.hold_active is True
    assert list(_attempt_row(llm_db)[6]) == ["plain", mapping]


def test_record_attempt_rejects_bad_error_entries() -> None:
    for bad in (42, [{"code": "X", 7: "y"}], [["nested"]]):
        with pytest.raises(ValueError, match="errors"):
            record_attempt(
                **_base_kwargs(errors=bad),  # type: ignore[arg-type]
                database_url="postgresql://127.0.0.1:1/unreachable",
            )


def test_record_attempt_rejects_bad_token_source() -> None:
    """Python-side validation fires before any database connection."""
    with pytest.raises(ValueError, match="token_source"):
        record_attempt(
            **_base_kwargs(billed=False, reservation_id=None, token_source="telepathy"),
            database_url="postgresql://127.0.0.1:1/unreachable",
        )
