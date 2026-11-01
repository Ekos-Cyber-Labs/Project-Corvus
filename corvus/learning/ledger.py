"""Model-ledger checks for the learning proof (no model calls).

:func:`ledger_check` counts the ``llm_attempts`` and ``spend`` rows
created in a time window, grouped by purpose and model, and prints
them. With ``expect_zero`` it returns 1 when any row exists in the
window, so ``corvus rules ledger-check --expect-zero`` proves the
detection path spent nothing. Times are ISO-8601 (naive means UTC);
``start`` must not be after ``end``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psycopg

__all__ = ["ledger_check", "ledger_counts", "parse_window"]


def parse_window(start: str, end: str) -> tuple[datetime, datetime]:
    """Parse an ISO-8601 window to aware datetimes (naive means UTC)."""
    try:
        start_dt = datetime.fromisoformat(start.strip())
        end_dt = datetime.fromisoformat(end.strip())
    except ValueError:
        raise ValueError(
            f"ledger window bounds must be ISO-8601, got start={start!r} end={end!r}"
        ) from None
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=UTC)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=UTC)
    if start_dt > end_dt:
        raise ValueError(f"ledger window start {start!r} is after end {end!r}")
    return start_dt, end_dt


def ledger_counts(database_url: str, start: datetime, end: datetime) -> dict[str, Any]:
    """Count ledger rows in ``[start, end)`` grouped by purpose/model."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT purpose, model, COUNT(*) FROM llm_attempts"
                " WHERE created_at >= %s AND created_at < %s"
                " GROUP BY purpose, model ORDER BY purpose, model",
                (start, end),
            )
            attempts = [
                {"purpose": str(row[0]), "model": str(row[1]), "rows": int(row[2])}
                for row in (cur.fetchall() or [])
            ]
            cur.execute(
                "SELECT model, COUNT(*), COALESCE(SUM(usd), 0) FROM spend"
                " WHERE created_at >= %s AND created_at < %s"
                " GROUP BY model ORDER BY model",
                (start, end),
            )
            spend = [
                {
                    "model": str(row[0]),
                    "rows": int(row[1]),
                    "usd": float(row[2]),
                }
                for row in (cur.fetchall() or [])
            ]
    return {
        "attempt_rows": sum(entry["rows"] for entry in attempts),
        "attempts": attempts,
        "spend_rows": sum(entry["rows"] for entry in spend),
        "spend_usd": sum(entry["usd"] for entry in spend),
        "spend": spend,
    }


def ledger_check(
    database_url: str, start: str, end: str, *, expect_zero: bool = False
) -> int:
    """Print the ledger counts in the window; return the exit code.

    Returns 0 normally, or with ``expect_zero`` 1 when any
    ``llm_attempts`` or ``spend`` row exists in the window (0 when
    the window is clean).
    """
    start_dt, end_dt = parse_window(start, end)
    counts = ledger_counts(database_url, start_dt, end_dt)
    print(f"llm_attempts in [{start}, {end}): {counts['attempt_rows']} rows")
    for entry in counts["attempts"]:
        print(f"  purpose={entry['purpose']} model={entry['model']}: {entry['rows']}")
    print(
        f"spend in [{start}, {end}): {counts['spend_rows']} rows"
        f" (${counts['spend_usd']:.6f} total)"
    )
    for entry in counts["spend"]:
        print(f"  model={entry['model']}: {entry['rows']} (${entry['usd']:.6f})")
    if expect_zero and (counts["attempt_rows"] or counts["spend_rows"]):
        print("ledger is not empty: detection spent model budget in this window")
        return 1
    return 0
