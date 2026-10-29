"""Migration runner integration test (always runs; never skips)."""

from pathlib import Path

import psycopg
import pytest
from psycopg import errors

from corvus.state.migrate import MIGRATIONS_DIR, migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls

EXPECTED_TABLES = {
    "schema_migrations",
    "checkpoints",
    "work_queue",
    "incidents",
    "agent_steps",
    "rules",
    "dispositions",
    "pseudonyms",
    "spend",
    "llm_attempts",
}

# Key columns per table, exactly as named in the migration-002 spec.
EXPECTED_COLUMNS: dict[str, set[str]] = {
    "checkpoints": {"adapter", "stream", "cursor", "created_at", "updated_at"},
    "work_queue": {
        "id",
        "kind",
        "payload",
        "dedupe_key",
        "status",
        "attempts",
        "available_at",
        "locked_by",
        "locked_at",
        "lease_expires_at",
        "last_error",
    },
    "incidents": {
        "id",
        "correlation_key",
        "deterministic_score",
        "severity_floor",
        "severity_id",
        "severity_factors",
        "status",
        "ai_status",
        "created_at",
        "updated_at",
    },
    "agent_steps": {
        "id",
        "incident_id",
        "step_number",
        "tool",
        "arguments",
        "result_summary",
        "tokens",
        "started_at",
        "finished_at",
        "created_at",
    },
    "rules": {
        "id",
        "sigma_text",
        "native_text",
        "native_rule_id",
        "version",
        "status",
        "lineage",
        "ttl",
        "hits",
        "false_positives",
        "created_at",
        "updated_at",
    },
    "dispositions": {
        "id",
        "incident_id",
        "rule_id",
        "verdict",
        "analyst",
        "note",
        "created_at",
    },
    "pseudonyms": {"id", "entity_kind", "entity_value", "pseudonym", "created_at"},
    "spend": {"id", "model", "tokens_in", "tokens_out", "usd", "created_at"},
    "llm_attempts": {
        "id",
        "call_id",
        "incident_id",
        "model",
        "purpose",
        "attempt_number",
        "failed_validator",
        "errors",
        "prompt_tokens",
        "cached_tokens",
        "reasoning_tokens",
        "answer_tokens",
        "overhead_tokens",
        "latency_ms",
        "outcome",
        "created_at",
    },
}

EXPECTED_INDEXES = {
    "idx_work_queue_claim",
    "idx_work_queue_lease",
    "idx_incidents_list",
    "idx_incidents_status_list",
    "idx_incidents_ai_status_list",
    "idx_spend_created_at",
}


def _execute(test_url: str, statement: str, params: tuple = ()) -> None:
    """Run one statement on its own autocommit connection."""
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(statement, params)  # type: ignore[arg-type]


@pytest.mark.integration
def test_migrate_applies_twice_idempotently() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        first = migrate(test_url)
        assert "0001_schema_migrations.sql" in first
        assert "0002_core_tables.sql" in first
        assert "0003_severity_factors.sql" in first
        assert migrate(test_url) == []
        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT filename FROM schema_migrations ORDER BY filename")
                assert [row[0] for row in cur.fetchall()] == [
                    "0001_schema_migrations.sql",
                    "0002_core_tables.sql",
                    "0003_severity_factors.sql",
                ]

        # File-level idempotency: executing 0002 directly, twice, is safe.
        sql_text = (Path(MIGRATIONS_DIR) / "0002_core_tables.sql").read_text(
            encoding="utf-8"
        )
        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(sql_text)
                cur.execute(sql_text)
            conn.commit()

        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public'"
                )
                tables = {row[0] for row in cur.fetchall()}
                assert EXPECTED_TABLES <= tables

                cur.execute(
                    "SELECT table_name, column_name, data_type "
                    "FROM information_schema.columns WHERE table_schema = 'public'"
                )
                columns: dict[str, set[str]] = {}
                tz_columns: dict[str, set[str]] = {}
                for table, column, data_type in cur.fetchall():
                    columns.setdefault(table, set()).add(column)
                    if data_type == "timestamp with time zone":
                        tz_columns.setdefault(table, set()).add(column)
                for table, expected in EXPECTED_COLUMNS.items():
                    missing = expected - columns.get(table, set())
                    assert not missing, f"{table} missing columns {sorted(missing)}"
                # Spot-check timestamptz on the timestamp columns.
                assert "available_at" in tz_columns["work_queue"]
                assert "created_at" in tz_columns["incidents"]
                assert "created_at" in tz_columns["llm_attempts"]

                cur.execute(
                    "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
                )
                indexes = {row[0] for row in cur.fetchall()}
                assert EXPECTED_INDEXES <= indexes
                # UNIQUE(pseudonym) already indexes it; no redundant index.
                assert "idx_pseudonyms_pseudonym" not in indexes
    finally:
        _drop_database(admin_url, name)


@pytest.mark.integration
def test_migration_002_constraints() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)

        # One level above the floor is allowed; two levels is not.
        with psycopg.connect(test_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO incidents "
                    "(correlation_key, severity_floor, severity_id) "
                    "VALUES ('corr-1', 3, 4) RETURNING id"
                )
                incident_id = cur.fetchone()[0]  # type: ignore[index]
        with pytest.raises(errors.CheckViolation):
            _execute(
                test_url,
                "INSERT INTO incidents "
                "(correlation_key, severity_floor, severity_id) "
                "VALUES ('corr-2', 3, 5)",
            )
        with pytest.raises(errors.CheckViolation):
            _execute(
                test_url,
                "INSERT INTO incidents "
                "(correlation_key, severity_floor, severity_id) "
                "VALUES ('corr-3', 3, 2)",
            )

        # Re-running correlation cannot create a duplicate incident.
        with pytest.raises(errors.UniqueViolation):
            _execute(
                test_url,
                "INSERT INTO incidents "
                "(correlation_key, severity_floor, severity_id) "
                "VALUES ('corr-1', 3, 3)",
            )

        # The same job cannot be enqueued twice; NULL keys never collide.
        _execute(
            test_url,
            "INSERT INTO work_queue (kind, dedupe_key) VALUES ('triage', 'job-1')",
        )
        _execute(test_url, "INSERT INTO work_queue (kind) VALUES ('triage')")
        _execute(test_url, "INSERT INTO work_queue (kind) VALUES ('triage')")
        with pytest.raises(errors.UniqueViolation):
            _execute(
                test_url,
                "INSERT INTO work_queue (kind, dedupe_key) VALUES ('triage', 'job-1')",
            )

        # Analyst verdicts are never deleted silently with the incident.
        _execute(
            test_url,
            "INSERT INTO dispositions (incident_id, verdict, analyst) "
            "VALUES (%s, 'tp', 'analyst-1')",
            (incident_id,),
        )
        with pytest.raises(errors.RestrictViolation):
            _execute(test_url, "DELETE FROM incidents WHERE id = %s", (incident_id,))
    finally:
        _drop_database(admin_url, name)
