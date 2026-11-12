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

    An incident that loses members (a stored event uid is missing from
    the new ``event_uids``, as after re-correlating with a different
    configuration) describes different activity than its model
    analysis did: it returns to ``ai_status = 'pending'`` with no
    verdict, summary or response, its severity drops back to the floor and its
    ``incident_analyses`` rows are deleted, so the next analysis run
    sees it as new. Analyst feedback rows are kept. Growing incidents
    keep their analysis (the live poll appends events).
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
            Jsonb(incident.get("learned_rules") or []),
        )
        for incident in incidents
    ]
    new_members = {
        str(incident["correlation_key"]): {str(u) for u in incident["event_uids"]}
        for incident in incidents
    }
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, correlation_key, event_uids FROM incidents"
                " WHERE correlation_key = ANY(%s) FOR UPDATE",
                (list(new_members),),
            )
            shrunk = [
                int(row[0])
                for row in cur.fetchall()
                if not {str(u) for u in (row[2] or [])} <= new_members[str(row[1])]
            ]
            cur.executemany(
                "INSERT INTO incidents (correlation_key, title, entity_keys, "
                "techniques, event_uids, first_seen, last_seen, "
                "deterministic_score, severity_floor, severity_id, "
                "severity_factors, learned_rules, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) "
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
                "learned_rules = EXCLUDED.learned_rules, "
                "updated_at = NOW()",
                rows,
            )
            if shrunk:
                cur.execute(
                    "UPDATE incidents SET ai_status = 'pending', verdict = NULL,"
                    " summary = NULL, response = NULL, language = NULL,"
                    " severity_id = severity_floor, updated_at = NOW()"
                    " WHERE id = ANY(%s)",
                    (shrunk,),
                )
                cur.execute(
                    "DELETE FROM incident_analyses WHERE incident_id = ANY(%s)",
                    (shrunk,),
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
