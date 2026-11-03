"""Sweep migration test: tables, constraints, and idempotency."""

from __future__ import annotations

import psycopg
import pytest
from psycopg import errors
from psycopg.types.json import Jsonb

from corvus.state.migrate import MIGRATIONS_DIR, migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.mark.integration
def test_migration_013_sweep_constraints() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        applied = migrate(test_url)
        assert "0013_sweep_runs.sql" in applied
        assert migrate(test_url) == []

        sql_text = (MIGRATIONS_DIR / "0013_sweep_runs.sql").read_text(encoding="utf-8")
        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(sql_text)
                cur.execute(sql_text)
            conn.commit()

        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO sweep_runs (status, policy, interval_seconds)"
                    " VALUES ('running', %s, 300) RETURNING id",
                    (Jsonb({"min_floor": 4}),),
                )
                run_id = int(cur.fetchone()[0])  # type: ignore[index]
                cur.execute(
                    "INSERT INTO incidents (correlation_key)"
                    " VALUES ('sweep-1') RETURNING id"
                )
                incident_id = int(cur.fetchone()[0])  # type: ignore[index]
                cur.execute(
                    "INSERT INTO sweep_decisions (sweep_run_id, incident_id,"
                    " decision, reason_code)"
                    " VALUES (%s, %s, 'analyze', 'selected')",
                    (run_id, incident_id),
                )
            conn.commit()

        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                with pytest.raises(errors.CheckViolation):
                    cur.execute("INSERT INTO sweep_runs (status) VALUES ('bogus')")
            conn.rollback()
            with conn.cursor() as cur:
                with pytest.raises(errors.CheckViolation):
                    cur.execute(
                        "INSERT INTO sweep_decisions (sweep_run_id, incident_id,"
                        " decision) VALUES (%s, %s, 'maybe')",
                        (run_id, incident_id),
                    )
            conn.rollback()
            with conn.cursor() as cur:
                with pytest.raises(errors.ForeignKeyViolation):
                    cur.execute(
                        "INSERT INTO sweep_decisions (sweep_run_id, incident_id,"
                        " decision) VALUES (999999, %s, 'analyze')",
                        (incident_id,),
                    )
            conn.rollback()
    finally:
        _drop_database(admin_url, name)
