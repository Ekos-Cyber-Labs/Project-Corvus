"""FastAPI service backing the UI (read-only).

Every route is a GET. Untrusted values (usernames, command lines,
file names, URLs, user agents, model output) are returned as plain
JSON strings; the UI renders them as text only. Error bodies are
static strings: no stack traces, SQL, or database URLs.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
import psycopg
from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import ValidationError

from corvus.settings import get_settings

app = FastAPI(title="corvus-api")

MAX_LIMIT = 100
ADV_PREFIX = "adv-llm:"
_SEVERITY_NAMES = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}
_PSEUDONYM_RE = re.compile(r"\b(?:HOST|USER|IP)-\d{4,}\b")
_UI_DIST = Path(__file__).resolve().parents[2] / "ui" / "dist"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


@app.middleware("http")
async def _security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(Exception)
async def _generic_error(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "internal error"})


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
        response = httpx2.get(url, timeout=3.0)
        return {
            "reachable": response.status_code < 500,
            "detail": f"HTTP {response.status_code}",
        }
    except Exception as exc:
        return {"reachable": False, "detail": type(exc).__name__}


def _misconfigured(detail: str = "invalid configuration") -> dict[str, Any]:
    down = {"reachable": False, "detail": detail}
    return {
        "status": "degraded",
        "database": down,
        "models": {"glimmer": down, "meta": down},
        "self_observation": _not_measured(),
    }


def _not_measured() -> dict[str, Any]:
    return {
        "latest_model_latency_ms": "not measured",
        "model_error_rate": "not measured",
        "spend_today_usd": "not measured",
        "spend_cap_usd": "not measured",
        "queue_depth": "not measured",
    }


def _database_url() -> str | None:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    try:
        return str(get_settings().database_url)
    except Exception:
        return None


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    if isinstance(moment, str):
        text: str = moment
        return text
    if isinstance(moment, datetime):
        typed: datetime = moment
        if typed.tzinfo is None:
            typed = typed.replace(tzinfo=UTC)
        return typed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: str = str(moment)
    return result


def _self_observation(database_url: str | None) -> dict[str, Any]:
    """Plain numbers from existing tables only; 'not measured' otherwise."""
    if not database_url:
        return _not_measured()
    try:
        with psycopg.connect(database_url, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT latency_ms FROM llm_attempts"
                    " WHERE latency_ms IS NOT NULL"
                    " ORDER BY created_at DESC, id DESC LIMIT 1"
                )
                row = cur.fetchone()
                latency: Any = int(row[0]) if row else "not measured"
                cur.execute(
                    "SELECT COUNT(*), COUNT(failed_validator) FROM llm_attempts"
                )
                counts = cur.fetchone()
                total, failed = (counts[0], counts[1]) if counts else (0, 0)
                rate: Any = (
                    round(int(failed) / int(total), 4) if int(total) else "not measured"
                )
                cur.execute(
                    "SELECT COALESCE(SUM(usd),0) FROM spend"
                    " WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC')"
                )
                spend_row = cur.fetchone()
                spend_today = float(spend_row[0]) if spend_row else 0.0
                cur.execute(
                    "SELECT COUNT(*) FROM work_queue"
                    " WHERE status IN ('pending','locked','failed')"
                )
                queue_row = cur.fetchone()
                queue_depth = int(queue_row[0]) if queue_row else 0
        try:
            from corvus.llm.spend import get_spend_cap

            cap: Any = get_spend_cap()
        except Exception:
            cap = "not measured"
        return {
            "latest_model_latency_ms": latency,
            "model_error_rate": rate,
            "spend_today_usd": spend_today,
            "spend_cap_usd": cap,
            "queue_depth": queue_depth,
        }
    except Exception:
        return _not_measured()


def _health_body() -> dict[str, Any]:
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
        "self_observation": _self_observation(settings.database_url),
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Report database and model reachability plus self-observation."""
    return _health_body()


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    return _health_body()


def _pseudonym_map(cur: Any) -> dict[str, str]:
    try:
        cur.execute("SELECT pseudonym, entity_value FROM pseudonyms")
        return {str(r[0]): str(r[1]) for r in cur.fetchall()}
    except Exception:
        return {}


def _resolve_pseudonyms(value: Any, mapping: dict[str, str]) -> tuple[Any, bool]:
    found = False

    def repl(text: str) -> str:
        nonlocal found

        def _sub(m: re.Match[str]) -> str:
            nonlocal found
            token = m.group(0)
            if token in mapping:
                found = True
                return mapping[token]
            return token

        return _PSEUDONYM_RE.sub(_sub, text)

    if isinstance(value, str):
        return repl(value), found
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            nv, f = _resolve_pseudonyms(v, mapping)
            out[k] = nv
            found = found or f
        return out, found
    if isinstance(value, list):
        out_list = []
        for v in value:
            nv, f = _resolve_pseudonyms(v, mapping)
            out_list.append(nv)
            found = found or f
        return out_list, found
    return value, found


def _attack_names(technique_ids: list[str]) -> list[dict[str, Any]]:
    names: dict[str, str] = {}
    try:
        from corvus.attack.dictionary import load_dictionary

        dictionary = load_dictionary()
        for tid in technique_ids:
            tech = dictionary.get(tid) or dictionary.resolve(tid)
            if tech is not None:
                names[tid] = tech.name
    except Exception:
        names = {}
    return [
        {
            "id": tid,
            "name": names.get(tid),
            "name_source": "attack_dictionary" if tid in names else "not measured",
        }
        for tid in technique_ids
    ]


def _fetch_evidence(event_uids: list[str]) -> list[dict[str, Any]]:
    """Read cited events from the replay store by uid; missing stays missing."""
    if not event_uids:
        return []
    found: dict[str, Any] = {}
    replay_dir = Path(os.environ.get("REPLAY_DIR", "data/replay"))
    events_dir = replay_dir / "events"
    files = (
        sorted(str(p) for p in events_dir.glob("*.parquet"))
        if events_dir.is_dir()
        else []
    )
    if files:
        try:
            import duckdb

            with duckdb.connect() as conn:
                placeholders = ", ".join("?" for _ in event_uids)
                rows = conn.execute(
                    "SELECT uid, event_json FROM read_parquet(?)"
                    f" WHERE uid IN ({placeholders})",
                    [files, *event_uids],
                ).fetchall()
            for uid, payload in rows:
                try:
                    found[str(uid)] = json.loads(str(payload))
                except Exception:
                    found[str(uid)] = {"raw": str(payload)}
        except Exception:
            found = {}
    return [
        {
            "event_uid": uid,
            "found": uid in found,
            "event": found.get(uid),
            "note": "found in replay store"
            if uid in found
            else "missing: no event with this uid in the replay store",
        }
        for uid in event_uids
    ]


def _attempt_usd(row: dict[str, Any]) -> float | None:
    try:
        from corvus.llm.price_book import cost_usd, load_price_book

        prices = load_price_book()
        tokens_out = (
            int(row["reasoning_tokens"])
            + int(row["answer_tokens"])
            + int(row["overhead_tokens"])
        )
        return cost_usd(
            prices,
            str(row["model"]),
            int(row["prompt_tokens"]),
            int(row["cached_tokens"]),
            tokens_out,
        )
    except Exception:
        return None


@app.get("/api/incidents")
def list_incidents(
    limit: int = Query(default=20, ge=1),
    offset: int = Query(default=0, ge=0),
    min_floor: int | None = Query(default=None, ge=1, le=6),
) -> Any:
    capped = min(limit, MAX_LIMIT)
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                where = "WHERE correlation_key NOT LIKE 'adv-llm:%%'"
                params: list[Any] = []
                if min_floor is not None:
                    where += " AND severity_floor >= %s"
                    params.append(min_floor)
                cur.execute(f"SELECT COUNT(*) FROM incidents {where}", params)
                count_row = cur.fetchone()
                total = int(count_row[0]) if count_row else 0
                cur.execute(
                    "SELECT i.id, i.title, i.severity_floor, i.severity_id,"
                    " i.ai_status,"
                    " i.verdict, i.first_seen, i.last_seen,"
                    " COALESCE(jsonb_array_length(i.event_uids),0),"
                    " EXISTS(SELECT 1 FROM incident_signals s WHERE"
                    " s.incident_id=i.id AND s.kind='injection')"
                    f" FROM incidents i {where} ORDER BY i.created_at DESC, i.id"
                    " DESC LIMIT %s OFFSET %s",
                    [*params, capped, offset],
                )
                items = [
                    {
                        "id": int(r[0]),
                        "title": str(r[1] or ""),
                        "severity_floor": int(r[2]),
                        "severity_floor_name": _SEVERITY_NAMES.get(int(r[2])),
                        "severity_id": int(r[3]),
                        "severity_name": _SEVERITY_NAMES.get(int(r[3])),
                        "ai_status": str(r[4]),
                        "verdict": r[5],
                        "first_seen": _iso(r[6]),
                        "last_seen": _iso(r[7]),
                        "event_count": int(r[8] or 0),
                        "has_injection": bool(r[9]),
                    }
                    for r in cur.fetchall()
                ]
        return {"items": items, "total": total, "limit": capped, "offset": offset}
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int) -> Any:
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, title, severity_floor, severity_id, ai_status, verdict,"
                    " status, first_seen, last_seen, severity_factors,"
                    " techniques, event_uids,"
                    " review_required FROM incidents WHERE id=%s AND"
                    " correlation_key NOT LIKE 'adv-llm:%%'",
                    (incident_id,),
                )
                row = cur.fetchone()
                if row is None:
                    return JSONResponse(
                        status_code=404, content={"detail": "incident not found"}
                    )
                pseudo_map = _pseudonym_map(cur)
                analyses: dict[str, Any] = {}
                for stage in ("analysis", "triage"):
                    cur.execute(
                        "SELECT status, payload, language, model, deterministic_floor"
                        " FROM incident_analyses WHERE incident_id=%s AND stage=%s",
                        (incident_id, stage),
                    )
                    arow = cur.fetchone()
                    if arow is not None:
                        analyses[stage] = {
                            "status": str(arow[0]),
                            "payload": dict(arow[1] or {}),
                            "language": arow[2],
                            "model": arow[3],
                            "deterministic_floor": arow[4],
                        }
                cur.execute(
                    "SELECT event_uid, field, pattern_id, requested_effect, detail"
                    " FROM incident_signals WHERE incident_id=%s AND kind='injection'"
                    " ORDER BY event_uid, field, pattern_id",
                    (incident_id,),
                )
                signals = []
                for srow in cur.fetchall():
                    detail = dict(srow[4] or {})
                    signals.append(
                        {
                            "event_uid": str(srow[0]),
                            "field": str(srow[1]),
                            "pattern_id": str(srow[2]),
                            "requested_effect": str(srow[3]),
                            "detail": detail,
                            "payload_text": detail.get("excerpt"),
                            "payload_label": "payload (shown as text)",
                        }
                    )
                cur.execute(
                    "SELECT step_number, tool, arguments, result_summary, tokens"
                    " FROM agent_steps WHERE incident_id=%s ORDER BY step_number ASC",
                    (incident_id,),
                )
                steps = [
                    {
                        "step": int(r[0]),
                        "tool": str(r[1]),
                        "arguments": dict(r[2] or {}),
                        "result_summary": r[3],
                        "tokens": int(r[4] or 0),
                    }
                    for r in cur.fetchall()
                ]
                cur.execute(
                    "SELECT purpose, model, attempt_number, outcome, failed_validator,"
                    " prompt_tokens, cached_tokens, reasoning_tokens, answer_tokens,"
                    " overhead_tokens, token_source, reasoning, latency_ms"
                    " FROM llm_attempts WHERE incident_id=%s ORDER BY created_at"
                    " ASC, id ASC",
                    (incident_id,),
                )
                attempts = []
                reasoning_unverified: dict[str, Any] | None = None
                for a in cur.fetchall():
                    adict = {
                        "purpose": str(a[0]),
                        "model": str(a[1]),
                        "attempt_number": int(a[2]),
                        "outcome": str(a[3]),
                        "failed_validator": a[4],
                        "prompt_tokens": int(a[5] or 0),
                        "cached_tokens": int(a[6] or 0),
                        "reasoning_tokens": int(a[7] or 0),
                        "answer_tokens": int(a[8] or 0),
                        "overhead_tokens": int(a[9] or 0),
                        "token_source": a[10],
                        "latency_ms": a[12],
                    }
                    adict["tokens"] = (
                        adict["prompt_tokens"]
                        + adict["reasoning_tokens"]
                        + adict["answer_tokens"]
                        + adict["overhead_tokens"]
                    )
                    adict["usd"] = _attempt_usd(adict | {"model": adict["model"]})
                    attempts.append(adict)
                    if a[11]:
                        reasoning_unverified = {
                            "text": str(a[11]),
                            "unverified": True,
                            "label": "unverified reasoning (stored on-prem, D24)",
                        }
                cur.execute(
                    "SELECT COALESCE(SUM(usd),0) FROM spend WHERE incident_id=%s",
                    (incident_id,),
                )
                spend_total_row = cur.fetchone()
                spend_total = float(spend_total_row[0]) if spend_total_row else 0.0
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})

    techniques_raw = [str(t) for t in (row[10] or [])]
    analysis_payload = dict((analyses.get("analysis") or {}).get("payload") or {})
    resolved_payload, did_resolve = _resolve_pseudonyms(analysis_payload, pseudo_map)
    verdict_obj = None
    if analysis_payload:
        verdict_obj = {
            "verdict": resolved_payload.get("verdict"),
            "severity_id": resolved_payload.get("severity_id"),
            "confidence": resolved_payload.get("confidence"),
            "timeline": resolved_payload.get("timeline") or [],
            "response_plan": resolved_payload.get("response_plan") or [],
            "visibility_gaps": resolved_payload.get("visibility_gaps") or [],
            "uncertainties": resolved_payload.get("uncertainties") or [],
            "language": (analyses.get("analysis") or {}).get("language")
            or resolved_payload.get("language"),
            "model": (analyses.get("analysis") or {}).get("model"),
            "status": (analyses.get("analysis") or {}).get("status"),
        }
    triage_payload = dict((analyses.get("triage") or {}).get("payload") or {})
    _condensed_raw = triage_payload.get("condensed")
    condensed: dict[str, Any] = (
        _condensed_raw if isinstance(_condensed_raw, dict) else {}
    )
    timeline = (verdict_obj or {}).get("timeline") or []
    cited_uids: list[str] = []
    for entry in timeline:
        if isinstance(entry, dict) and entry.get("event_uid"):
            uid = str(entry["event_uid"])
            if uid not in cited_uids:
                cited_uids.append(uid)
    return {
        "id": int(row[0]),
        "title": str(row[1] or ""),
        "severity_floor": int(row[2]),
        "severity_floor_name": _SEVERITY_NAMES.get(int(row[2])),
        "severity_id": int(row[3]),
        "severity_name": _SEVERITY_NAMES.get(int(row[3])),
        "ai_status": str(row[4]),
        "verdict": row[5],
        "status": str(row[6]),
        "first_seen": _iso(row[7]),
        "last_seen": _iso(row[8]),
        "severity_factors": dict(row[9] or {}),
        "severity": {
            "floor": int(row[2]),
            "final": int(row[3]),
            "factors": dict(row[9] or {}),
        },
        "techniques": _attack_names(techniques_raw),
        "event_uids": [str(u) for u in (row[11] or [])],
        "event_count": len(row[11] or []),
        "review_required": bool(row[12]),
        "analysis": verdict_obj,
        "triage": {
            "status": (analyses.get("triage") or {}).get("status"),
            "model": (analyses.get("triage") or {}).get("model"),
            "language": (analyses.get("triage") or {}).get("language"),
            "summary": condensed.get("summary"),
            "condensed": condensed,
        }
        if analyses.get("triage")
        else None,
        "injection_signals": signals,
        "has_injection": bool(signals),
        "evidence": _fetch_evidence(cited_uids),
        "agent_trace": steps,
        "llm_attempts": attempts,
        "spend_total_usd": spend_total,
        "reasoning_unverified": reasoning_unverified,
        "pseudonym_resolution": {
            "mapping_persisted": bool(pseudo_map),
            "resolved": did_resolve,
            "note": (
                "Pseudonym tokens in the stored verdict were resolved"
                " locally from the persisted pseudonyms table."
                if did_resolve
                else "No unresolved pseudonym tokens in the stored verdict; it is"
                " shown as stored (analysis verdicts are revealed on-prem"
                " before storage). Pseudonyms table is persisted."
                if pseudo_map
                else "No persisted pseudonym mapping found; values are shown as stored."
            ),
        },
    }


@app.get("/{full_path:path}")
def serve_ui(full_path: str) -> Any:
    """Serve the built UI; never allow traversal outside ui/dist."""
    if full_path.startswith("api/") or full_path == "health":
        return JSONResponse(status_code=404, content={"detail": "not found"})
    root = _UI_DIST.resolve()
    if not root.is_dir():
        return PlainTextResponse("UI not built. Run: make ui-build", status_code=404)
    candidate = (root / full_path).resolve() if full_path else (root / "index.html")
    if candidate != root and root not in candidate.parents:
        return JSONResponse(status_code=404, content={"detail": "not found"})
    if full_path and candidate.is_file():
        return FileResponse(candidate)
    index = root / "index.html"
    if index.is_file():
        return FileResponse(index)
    return PlainTextResponse("UI not built. Run: make ui-build", status_code=404)
