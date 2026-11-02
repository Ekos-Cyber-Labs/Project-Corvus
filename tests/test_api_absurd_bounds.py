"""Absurd-integer bounds for the read-only API.

``offset`` beyond ``MAX_OFFSET`` returns 422 (never 503) on both
paged lists; a rule id outside the BIGINT range (or below 1) returns
404 (never 503). Uses the real Postgres-backed app with the shared
guard in ``tests/conftest.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from corvus.api.main import MAX_OFFSET, MAX_RULE_ID, app
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def bounds_db() -> Any:
    """Throwaway Postgres with migrations applied (guarded, never skips)."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _client(db: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", db)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("route", ["/api/incidents", "/api/rules"])
@pytest.mark.parametrize(
    "offset",
    [MAX_OFFSET + 1, 10**18, 10**30, 2**63],
)
def test_absurd_offset_returns_422(
    bounds_db: str, monkeypatch: pytest.MonkeyPatch, route: str, offset: int
) -> None:
    """Absurd offsets are 422, never 503 'database unavailable'."""
    response = _client(bounds_db, monkeypatch).get(f"{route}?offset={offset}")
    assert response.status_code == 422, (route, offset)
    assert response.json() == {"detail": "invalid query parameters"}


@pytest.mark.parametrize(
    "rule_id",
    [0, -1, MAX_RULE_ID + 1, 10**19, 10**30, 2**63],
)
def test_absurd_rule_id_returns_404(
    bounds_db: str, monkeypatch: pytest.MonkeyPatch, rule_id: int
) -> None:
    """Absurd rule ids are 404, never 503 'database unavailable'."""
    response = _client(bounds_db, monkeypatch).get(f"/api/rules/{rule_id}")
    assert response.status_code == 404, rule_id
    assert response.json() == {"detail": "rule not found"}


def test_offset_at_bound_still_works(
    bounds_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound itself stays a valid (empty) page."""
    for route in ("/api/incidents", "/api/rules"):
        response = _client(bounds_db, monkeypatch).get(f"{route}?offset={MAX_OFFSET}")
        assert response.status_code == 200, route
        body = response.json()
        assert body["items"] == [] and body["offset"] == MAX_OFFSET
