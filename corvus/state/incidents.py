"""Durable incident storage over the ``incidents`` table (0002/0003).

Each deterministic incident upserts by its ``correlation_key``: a
re-run over the same data updates the same rows instead of creating
duplicates. ``first_seen``/``last_seen`` arrive as UTC epoch
milliseconds (the :class:`corvus.correlate.Incident` shape) and are
stored as ``timestamptz``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

__all__ = [
    "ms_to_timestamptz",
    "stored_correlation_keys",
    "stored_incident_count",
    "upsert_incidents",
]


def ms_to_timestamptz(moment_ms: int) -> datetime:
    """Convert UTC epoch milliseconds to a timezone-aware UTC datetime."""
    return datetime.fromtimestamp(moment_ms / 1000, tz=UTC)


def stored_correlation_keys(database_url: str) -> set[str]:
    """Return the ``correlation_key`` values currently stored."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT correlation_key FROM incidents")
            rows = cur.fetchall()
    assert rows is not None
    return {str(row[0]) for row in rows}


def upsert_incidents(database_url: str, incidents: Sequence[Mapping[str, Any]]) -> int:
    """Upsert deterministic incidents by ``correlation_key``.

    Returns the number of incident dicts written. Re-running with the
    same incidents leaves the same rows (same count, same content),
    except that a stored ``severity_id`` a model raised within one
    level is kept: on conflict the stored value survives while it is
    still within the new ``[floor, floor + 1]`` range, otherwise it
    resets to the new floor (so the table CHECK always holds).
    """
    if not incidents:
        return 0
    rows = [
        (
            incident["correlation_key"],
            incident["title"],
            Jsonb(incident["entity_keys"]),
            Jsonb(incident["techniques"]),
            Jsonb(incident["event_uids"]),
            ms_to_timestamptz(incident["first_seen"]),
            ms_to_timestamptz(incident["last_seen"]),
            incident["deterministic_score"],
            incident["severity_floor"],
            incident["severity_id"],
            Jsonb(incident["severity_factors"]),
        )
        for incident in incidents
    ]
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO incidents (correlation_key, title, entity_keys, "
                "techniques, event_uids, first_seen, last_seen, "
                "deterministic_score, severity_floor, severity_id, "
                "severity_factors, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) "
                "ON CONFLICT (correlation_key) DO UPDATE SET "
                "title = EXCLUDED.title, "
                "entity_keys = EXCLUDED.entity_keys, "
                "techniques = EXCLUDED.techniques, "
                "event_uids = EXCLUDED.event_uids, "
                "first_seen = EXCLUDED.first_seen, "
                "last_seen = EXCLUDED.last_seen, "
                "deterministic_score = EXCLUDED.deterministic_score, "
                "severity_floor = EXCLUDED.severity_floor, "
                "severity_id = CASE WHEN incidents.severity_id BETWEEN "
                "EXCLUDED.severity_floor AND EXCLUDED.severity_floor + 1 "
                "THEN incidents.severity_id ELSE EXCLUDED.severity_floor END, "
                "severity_factors = EXCLUDED.severity_factors, "
                "updated_at = NOW()",
                rows,
            )
        conn.commit()
    return len(rows)


def stored_incident_count(database_url: str) -> int:
    """Return the number of rows in ``incidents``."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incidents")
            row = cur.fetchone()
    assert row is not None
    return int(row[0])
