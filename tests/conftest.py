"""Shared Postgres guard and database helpers for integration tests.

Every Postgres-backed test must use these helpers: they fail (never
skip) unless ``DATABASE_URL`` points at port 55432 with a
``corvus_test_`` database, so a test can never run against the wrong
stack or silently pass without a database.
"""

import os
import uuid
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from psycopg import sql

TEST_PORT = 55432
TEST_DB_PREFIX = "corvus_test_"


#: Marker ``lab_data`` tests read recorded lab runs (``data/replay-linux-*``,
#: ``data/lab-*``) that cannot be published. They skip, with this reason,
#: on a checkout that never had them; fetched public datasets are not
#: covered by this (a missing public dataset is a setup error and fails).
LAB_DATA_PROBE = "data/replay-linux-chain1"


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if (config.rootpath / LAB_DATA_PROBE).is_dir():
        return
    skip = pytest.mark.skip(
        reason=f"needs the maintainer's lab replay data ({LAB_DATA_PROBE}), "
        "which is not published"
    )
    for item in items:
        if item.get_closest_marker("lab_data"):
            item.add_marker(skip)


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


def _create_database(admin_url: str, test_url: str) -> str:
    """Create the throwaway database; return its name."""
    name = urlparse(test_url).path.lstrip("/")
    with psycopg.connect(admin_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    return name


def _drop_database(admin_url: str, name: str) -> None:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
