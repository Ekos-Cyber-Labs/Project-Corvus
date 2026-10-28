"""Migration runner integration test (always runs; never skips)."""

import os
import uuid
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from psycopg import sql

from corvus.state.migrate import migrate

TEST_PORT = 55432
TEST_DB_PREFIX = "corvus_test_"


def _test_database_urls() -> tuple[str, str]:
    """Return (admin_url, test_url) or fail when DATABASE_URL is unsafe."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        pytest.fail(
            "DATABASE_URL must be set, e.g. "
            "postgresql://corvus:<pw>@127.0.0.1:55432/corvus_test_<name>"
        )
    parsed = urlparse(database_url)
    if parsed.port != TEST_PORT:
        pytest.fail(
            f"refusing to run: DATABASE_URL port is {parsed.port}, "
            f"expected {TEST_PORT} (host 5432 belongs to another stack)"
        )
    base = parsed.path.lstrip("/")
    if not base.startswith(TEST_DB_PREFIX):
        pytest.fail(
            f"refusing to run: database {base!r} does not start with {TEST_DB_PREFIX!r}"
        )
    name = f"{base}_{uuid.uuid4().hex[:8]}"
    test_url = urlunparse(parsed._replace(path=f"/{name}"))
    admin_url = urlunparse(parsed._replace(path="/postgres"))
    return admin_url, test_url


@pytest.mark.integration
def test_migrate_applies_twice_idempotently() -> None:
    admin_url, test_url = _test_database_urls()
    name = urlparse(test_url).path.lstrip("/")
    with psycopg.connect(admin_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        first = migrate(test_url)
        assert "0001_schema_migrations.sql" in first
        assert migrate(test_url) == []
        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT filename FROM schema_migrations")
                assert [row[0] for row in cur.fetchall()] == [
                    "0001_schema_migrations.sql"
                ]
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
