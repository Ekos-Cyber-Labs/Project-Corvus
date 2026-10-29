"""Ingestion checkpoints over the ``checkpoints`` table (migration 0002).

One row per ``(adapter, stream)`` holds the opaque ``search_after``
cursor as JSONB, so crash re-runs and restarts resume where the last
run stopped instead of duplicating or skipping alerts.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

__all__ = ["load_checkpoint", "save_checkpoint"]


def load_checkpoint(database_url: str, adapter: str, stream: str) -> dict[str, Any]:
    """Return the stored cursor, or ``{}`` when no row exists."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cursor FROM checkpoints WHERE adapter = %s AND stream = %s",
                (adapter, stream),
            )
            row = cur.fetchone()
    assert row is None or isinstance(row[0], dict)
    return dict(row[0]) if row is not None else {}


def save_checkpoint(
    database_url: str, adapter: str, stream: str, cursor: Mapping[str, Any]
) -> None:
    """Upsert the cursor for ``(adapter, stream)``."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO checkpoints (adapter, stream, cursor, updated_at) "
                "VALUES (%s, %s, %s, NOW()) "
                "ON CONFLICT (adapter, stream) DO UPDATE SET "
                "cursor = EXCLUDED.cursor, updated_at = NOW()",
                (adapter, stream, Jsonb(dict(cursor))),
            )
        conn.commit()
