"""FastAPI service backing the UI."""

from typing import Any

import httpx
import psycopg
from fastapi import FastAPI
from pydantic import ValidationError

from corvus.settings import get_settings

app = FastAPI(title="corvus-api")


def check_database(database_url: str | None) -> dict[str, Any]:
    """Return database connectivity without leaking secrets."""
    if not database_url:
        return {"reachable": False, "detail": "DATABASE_URL is not set"}
    try:
        with psycopg.connect(database_url, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"reachable": True, "detail": "ok"}
    except Exception as exc:
        return {"reachable": False, "detail": type(exc).__name__}


def check_endpoint(name: str, base_url: str | None) -> dict[str, Any]:
    """Return HTTP reachability for a model endpoint (no secrets sent).

    Any HTTP answer below 500 — including 401 — counts as reachable:
    the endpoint is alive, only the credentials (if any) were refused.
    """
    if not base_url:
        return {"reachable": False, "detail": f"{name} URL is not set"}
    url = base_url.rstrip("/") + "/models"
    try:
        response = httpx.get(url, timeout=3.0)
        return {
            "reachable": response.status_code < 500,
            "detail": f"HTTP {response.status_code}",
        }
    except Exception as exc:
        return {"reachable": False, "detail": type(exc).__name__}


def _misconfigured(detail: str = "invalid configuration") -> dict[str, Any]:
    """Degraded health body used when settings fail validation.

    Only a static detail is reported: validation errors can echo
    untrusted input, so they are never serialized into the response.
    """
    down = {"reachable": False, "detail": detail}
    return {
        "status": "degraded",
        "database": down,
        "models": {"glimmer": down, "meta": down},
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Report database and model reachability.

    Status is "ok" only when the database and Glimmer both answer.
    Meta reachability is informational and never affects the status.
    """
    try:
        settings = get_settings()
    except ValidationError:
        return _misconfigured()
    database = check_database(settings.database_url)
    glimmer = check_endpoint("glimmer", settings.glimmer_base_url)
    meta = check_endpoint("meta", settings.meta_base_url)
    status = "ok" if (database["reachable"] and glimmer["reachable"]) else "degraded"
    return {
        "status": status,
        "database": database,
        "models": {"glimmer": glimmer, "meta": meta},
    }
