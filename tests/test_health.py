"""Health endpoint reports degraded status without live dependencies."""

import pytest
from fastapi.testclient import TestClient

from corvus.api import main
from corvus.api.main import app


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def test_health_degraded_with_unreachable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "postgresql://" has no host: psycopg fails before any network traffic.
    monkeypatch.setenv("DATABASE_URL", "postgresql://")
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("META_BASE_URL", "http://127.0.0.1:9/v1")
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["database"]["reachable"] is False


def test_health_degraded_with_missing_glimmer_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLIMMER_BASE_URL", raising=False)
    response = _client().get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"


def test_meta_401_counts_as_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 is an answer from the model endpoint, not an outage."""

    class _Response:
        status_code = 401

    monkeypatch.setattr(main.httpx2, "get", lambda *args, **kwargs: _Response())
    assert main.check_endpoint("meta", "http://meta-host/v1") == {
        "reachable": True,
        "detail": "HTTP 401",
    }


def test_endpoint_connection_error_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*args: object, **kwargs: object) -> object:
        raise main.httpx2.ConnectError("refused")

    monkeypatch.setattr(main.httpx2, "get", _boom)
    result = main.check_endpoint("glimmer", "http://127.0.0.1:9/v1")
    assert result["reachable"] is False
