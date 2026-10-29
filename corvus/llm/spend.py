"""Model spend ledger and USD budget guard, backed by Postgres.

- :func:`record_spend` writes one row to the existing ``spend`` table
  with the USD cost computed from the static price book. Local-model
  (``glimmer``) spend is recorded with ``usd`` 0: the price book carries
  no per-token charge for on-prem inference.
- :func:`budget_state` reports ``"ok"`` / ``"degraded"`` from the SUM of
  ``spend.usd`` against the ``SPEND_CAP_USD`` cap (default 100.0).
- :func:`reserve` is the pre-call guard: it refuses (raising
  :class:`BudgetExceededError`) when ``spent + held + worst_case`` would
  cross the cap, so N concurrent callers cannot jointly overshoot it.
  The reservation is later :func:`release`d or :func:`convert`ed into
  real spend when the call finishes. Pass ``ttl_seconds`` from
  :func:`hold_ttl` (request timeout x max attempts, plus a margin);
  600 s is only the fallback default.
- :func:`convert_reservation` always records the real spend, even when
  the hold expired, was purged, or never existed: a call that outlived
  its hold is a bookkeeping event, never lost spend. The returned
  :class:`ConversionResult` reports whether the hold was still active.

Reservations live in the ``spend_reservations`` table (migration
``0004_llm_audit.sql``), never in process memory, so every worker and
thread sees the same holds. Each reservation carries ``expires_at`` so a
crash before convert/release frees the budget instead of locking it
forever. Check-and-insert runs in one transaction under a
transaction-scoped advisory lock, which serializes concurrent reservers
across processes and threads.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import psycopg

from corvus.llm.price_book import ModelPrice, cost_usd, load_price_book

DEFAULT_SPEND_CAP_USD = 100.0
SPEND_CAP_VAR = "SPEND_CAP_USD"
DATABASE_URL_VAR = "DATABASE_URL"
#: Extra seconds :func:`hold_ttl` adds over timeout x attempts.
HOLD_TTL_MARGIN_SECONDS = 60.0

# Transaction-scoped advisory lock serializing reserve/convert/record.
# (The migration runner uses a different, session-scoped lock.)
_SPEND_ADVISORY_LOCK = 20261029


class BudgetExceededError(RuntimeError):
    """Raised when a reservation would cross the USD spend cap."""


@dataclass(frozen=True)
class Reservation:
    """A held slice of the USD budget, freed by release or convert."""

    id: int
    amount_usd: float


@dataclass(frozen=True)
class ConversionResult:
    """Outcome of converting a reservation into recorded spend."""

    usd: float
    hold_active: bool


def get_spend_cap() -> float:
    """Return the USD spend cap from ``SPEND_CAP_USD`` (default 100.0)."""
    raw = os.environ.get(SPEND_CAP_VAR)
    if raw is None or raw.strip() == "":
        return DEFAULT_SPEND_CAP_USD
    try:
        cap = float(raw.strip())
    except ValueError:
        raise ValueError(
            f"{SPEND_CAP_VAR} must be a number, got {raw.strip()!r}"
        ) from None
    if not math.isfinite(cap) or cap < 0:
        raise ValueError(f"{SPEND_CAP_VAR} must be a finite number >= 0, got {cap!r}")
    return cap


def _database_url(explicit: str | None) -> str:
    url = explicit or os.environ.get(DATABASE_URL_VAR)
    if not url:
        raise ValueError(
            f"missing database URL: pass database_url or set {DATABASE_URL_VAR}"
        )
    return url


def _spent_usd(cur: psycopg.Cursor) -> float:
    cur.execute("SELECT COALESCE(SUM(usd), 0) FROM spend")
    row = cur.fetchone()
    assert row is not None
    return float(row[0])


def _held_usd(cur: psycopg.Cursor) -> float:
    cur.execute(
        "SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations "
        "WHERE status = 'held' AND expires_at > NOW()"
    )
    row = cur.fetchone()
    assert row is not None
    return float(row[0])


def spent_usd(database_url: str | None = None) -> float:
    """Return total committed spend USD (SUM over ``spend``)."""
    with psycopg.connect(_database_url(database_url), autocommit=True) as conn:
        with conn.cursor() as cur:
            return _spent_usd(cur)


def held_usd(database_url: str | None = None) -> float:
    """Return total active (unexpired, held) reservation USD."""
    with psycopg.connect(_database_url(database_url), autocommit=True) as conn:
        with conn.cursor() as cur:
            return _held_usd(cur)


def budget_state(
    cap_usd: float | None = None, database_url: str | None = None
) -> Literal["ok", "degraded"]:
    """Return ``"ok"`` while SUM(spend) is below the cap, else ``"degraded"``."""
    cap = get_spend_cap() if cap_usd is None else cap_usd
    if not isinstance(cap, (int, float)) or not math.isfinite(cap) or cap < 0:
        raise ValueError(f"cap_usd must be a finite number >= 0, got {cap!r}")
    return "degraded" if spent_usd(database_url) >= cap else "ok"


def _insert_spend(
    cur: psycopg.Cursor,
    model: str,
    tokens_in: int,
    tokens_cached: int,
    tokens_out: int,
    usd: float,
    incident_id: int | None,
) -> None:
    """Insert one ``spend`` row on an already-open cursor (no commit)."""
    cur.execute(
        "INSERT INTO spend (model, tokens_in, tokens_out, usd, "
        "incident_id) VALUES (%s, %s, %s, %s, %s)",
        (model, tokens_in, tokens_out, usd, incident_id),
    )


def record_spend(
    model: str,
    tokens_in: int,
    tokens_cached: int,
    tokens_out: int,
    incident_id: int | None,
    database_url: str | None = None,
    prices: Mapping[str, ModelPrice] | None = None,
    conn: psycopg.Connection | None = None,
) -> float:
    """Write one row to ``spend`` with the price-book USD cost; return it.

    ``tokens_cached`` is the subset of ``tokens_in`` served from cache.
    When ``conn`` (an open connection already in a transaction) is
    given, the row is written on it and the caller commits; otherwise
    a private autocommit connection is used exactly as before.
    """
    table = prices if prices is not None else load_price_book()
    usd = cost_usd(table, model, tokens_in, tokens_cached, tokens_out)
    if conn is not None:
        with conn.cursor() as cur:
            _insert_spend(
                cur, model, tokens_in, tokens_cached, tokens_out, usd, incident_id
            )
        return usd
    with psycopg.connect(_database_url(database_url), autocommit=True) as fresh:
        with fresh.cursor() as cur:
            _insert_spend(
                cur, model, tokens_in, tokens_cached, tokens_out, usd, incident_id
            )
    return usd


def hold_ttl(
    request_timeout_seconds: float,
    max_attempts: int,
    margin_seconds: float = HOLD_TTL_MARGIN_SECONDS,
) -> float:
    """Hold length covering (request timeout x max attempts) plus a margin.

    Pass the result as ``reserve(ttl_seconds=...)`` so a hold outlives
    the slowest successful call but still expires after a crash.
    """
    if (
        isinstance(request_timeout_seconds, bool)
        or not isinstance(request_timeout_seconds, (int, float))
        or not math.isfinite(request_timeout_seconds)
        or request_timeout_seconds <= 0
    ):
        raise ValueError(
            "request_timeout_seconds must be a finite number > 0, "
            f"got {request_timeout_seconds!r}"
        )
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or max_attempts < 1
    ):
        raise ValueError(f"max_attempts must be an int >= 1, got {max_attempts!r}")
    if (
        isinstance(margin_seconds, bool)
        or not isinstance(margin_seconds, (int, float))
        or not math.isfinite(margin_seconds)
        or margin_seconds < 0
    ):
        raise ValueError(
            f"margin_seconds must be a finite number >= 0, got {margin_seconds!r}"
        )
    return request_timeout_seconds * max_attempts + margin_seconds


def reserve(
    worst_case_usd: float,
    database_url: str | None = None,
    cap_usd: float | None = None,
    ttl_seconds: float = 600.0,
) -> Reservation:
    """Hold ``worst_case_usd`` of budget; refuse when it would cross the cap.

    Raises :class:`BudgetExceededError` when
    ``spent + held + worst_case_usd`` exceeds the cap, and
    :class:`ValueError` for a negative amount. The hold expires
    ``ttl_seconds`` after creation so a crashed caller cannot lock the
    budget forever; pass ``hold_ttl(...)`` — 600 s is only the fallback.
    """
    if (
        isinstance(worst_case_usd, bool)
        or not isinstance(worst_case_usd, (int, float))
        or not math.isfinite(worst_case_usd)
    ):
        raise ValueError(
            f"worst_case_usd must be a finite number, got {worst_case_usd!r}"
        )
    if worst_case_usd < 0:
        raise ValueError(f"worst_case_usd must not be negative, got {worst_case_usd!r}")
    if not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds):
        raise ValueError(f"ttl_seconds must be a finite number, got {ttl_seconds!r}")
    if ttl_seconds < 0:
        raise ValueError(f"ttl_seconds must not be negative, got {ttl_seconds!r}")
    cap = get_spend_cap() if cap_usd is None else cap_usd
    if not isinstance(cap, (int, float)) or not math.isfinite(cap) or cap < 0:
        raise ValueError(f"cap_usd must be a finite number >= 0, got {cap!r}")
    with psycopg.connect(_database_url(database_url)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SPEND_ADVISORY_LOCK,))
            spent = _spent_usd(cur)
            held = _held_usd(cur)
            if spent + held + worst_case_usd > cap:
                raise BudgetExceededError(
                    f"spend cap {cap} USD would be crossed: spent {spent}, "
                    f"held {held}, requested {worst_case_usd}"
                )
            cur.execute(
                "INSERT INTO spend_reservations (amount_usd, expires_at) "
                "VALUES (%s, NOW() + make_interval(secs => %s)) "
                "RETURNING id",
                (worst_case_usd, ttl_seconds),
            )
            row = cur.fetchone()
            assert row is not None
            reservation_id = int(row[0])
        conn.commit()
    return Reservation(id=reservation_id, amount_usd=float(worst_case_usd))


def release_reservation(reservation_id: int, database_url: str | None = None) -> bool:
    """Release a held reservation; return True when a hold was freed."""
    with psycopg.connect(_database_url(database_url), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE spend_reservations SET status = 'released' "
                "WHERE id = %s AND status = 'held'",
                (reservation_id,),
            )
            return cur.rowcount == 1


def _convert_locked(
    cur: psycopg.Cursor,
    reservation_id: int,
    model: str,
    tokens_in: int,
    tokens_cached: int,
    tokens_out: int,
    usd: float,
    incident_id: int | None,
) -> ConversionResult:
    """Flip one live hold to converted and insert its spend row.

    Runs on an already-open cursor inside the caller's transaction;
    the transaction-scoped advisory lock serializes concurrent
    converters. Spend is always recorded, even when the hold expired,
    was purged, or never existed.
    """
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SPEND_ADVISORY_LOCK,))
    cur.execute(
        "UPDATE spend_reservations SET status = 'converted' "
        "WHERE id = %s AND status = 'held' AND expires_at > NOW() "
        "RETURNING id",
        (reservation_id,),
    )
    hold_active = cur.fetchone() is not None
    _insert_spend(cur, model, tokens_in, tokens_cached, tokens_out, usd, incident_id)
    return ConversionResult(usd=usd, hold_active=hold_active)


def convert_reservation(
    reservation_id: int,
    model: str,
    tokens_in: int,
    tokens_cached: int,
    tokens_out: int,
    incident_id: int | None = None,
    database_url: str | None = None,
    prices: Mapping[str, ModelPrice] | None = None,
    conn: psycopg.Connection | None = None,
) -> ConversionResult:
    """Convert a held reservation into real spend; report the outcome.

    The spend row is always recorded — even when the hold expired, was
    purged, or never existed — because a call that outlived its hold is
    a bookkeeping event, never lost spend. ``hold_active`` reports
    whether the hold was still live when the call finished. The
    function logs nothing. When ``conn`` (an open connection already
    in a transaction) is given, the conversion joins it — lock,
    update and spend row all land in the caller's transaction and the
    caller commits; otherwise a private connection is used exactly as
    before.
    """
    table = prices if prices is not None else load_price_book()
    usd = cost_usd(table, model, tokens_in, tokens_cached, tokens_out)
    if conn is not None:
        with conn.cursor() as cur:
            return _convert_locked(
                cur,
                reservation_id,
                model,
                tokens_in,
                tokens_cached,
                tokens_out,
                usd,
                incident_id,
            )
    with psycopg.connect(_database_url(database_url)) as fresh:
        with fresh.cursor() as cur:
            result = _convert_locked(
                cur,
                reservation_id,
                model,
                tokens_in,
                tokens_cached,
                tokens_out,
                usd,
                incident_id,
            )
        fresh.commit()
    return result


def purge_expired_reservations(database_url: str | None = None) -> int:
    """Mark expired held reservations released; return the count freed."""
    with psycopg.connect(_database_url(database_url), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE spend_reservations SET status = 'released' "
                "WHERE status = 'held' AND expires_at <= NOW()"
            )
            return cur.rowcount
