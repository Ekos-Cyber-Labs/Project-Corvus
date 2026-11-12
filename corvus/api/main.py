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
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import psycopg
import yaml
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from corvus.adapters.wazuh.client import IndexerError, ReadOnlyIndexerClient
from corvus.settings import get_settings

app = FastAPI(title="corvus-api")

MAX_LIMIT = 100

#: Largest accepted ``offset`` for paged lists. Offsets beyond this are
#: never legitimate for this UI (tables fit in memory) and huge values
#: would otherwise reach Postgres as an out-of-range OFFSET and surface
#: as a 503; absurd integers now fail validation as 422 instead.
MAX_OFFSET = 1_000_000_000

#: Largest accepted ``rules.id`` (BIGSERIAL). Larger integers cannot
#: exist and would otherwise reach Postgres as an out-of-range
#: parameter and surface as a 503; they return 404 instead.
MAX_RULE_ID = 9_223_372_036_854_775_807
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


#: Static body for every 422: never echoes untrusted query input.
INVALID_QUERY = {"detail": "invalid query parameters"}


@app.exception_handler(RequestValidationError)
async def _validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(status_code=422, content=dict(INVALID_QUERY))


#: Verdicts the analysis loop may store; the only accepted values for
#: the ``verdict`` list filter. Anything else is a 422.
ALLOWED_VERDICTS = frozenset(
    {"true_positive", "benign_authorized", "false_positive", "needs_human"}
)


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


#: Index pattern the read probe searches: the alerts the sweep reads.
WAZUH_PROBE_INDEX = "wazuh-alerts-4.x-*"


def check_wazuh_indexer(
    base_url: str | None,
    username: str | None = None,
    password: str | None = None,
    *,
    transport: Any = None,
) -> dict[str, Any]:
    """Probe the Wazuh indexer with the sweep's read credentials.

    Runs one zero-hit search (``size: 0``) on
    :data:`WAZUH_PROBE_INDEX` through the same read-only client the
    sweep uses, so a pass means reachable, authenticated and allowed to
    read alerts. Only ``scheme://host[:port]`` of ``base_url`` is used
    (userinfo, path and query are dropped). TLS verifies against the
    ``WAZUH_INDEXER_CA`` bundle when set and the default store
    otherwise; verification is never disabled, and only ``https`` is
    accepted. ``auth`` is ``"ok"`` on success, ``"rejected"`` on HTTP
    401/403 (the indexer answered but refused the credentials: never
    reported as connected) and ``"missing"`` when the user or password
    is unset (nothing is sent). Every failure reports an HTTP status,
    a fixed text or an exception class name only, never a message,
    a URL or a credential.
    """
    if not base_url:
        return {"reachable": False, "detail": "wazuh_indexer URL is not set"}
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(base_url)
        if not parts.hostname:
            return {"reachable": False, "detail": "invalid wazuh_indexer URL"}
        host = parts.hostname.lower()
        port = f":{parts.port}" if parts.port else ""
        scheme = (parts.scheme or "https").lower()
        probe = f"{scheme}://{host}{port}"
    except Exception:
        return {"reachable": False, "detail": "invalid wazuh_indexer URL"}
    if scheme != "https":
        return {"reachable": False, "detail": "wazuh_indexer URL must use https"}
    if not username or not password:
        return {
            "reachable": False,
            "detail": "wazuh_indexer credentials are not set",
            "auth": "missing",
        }
    try:
        client = ReadOnlyIndexerClient(
            probe,
            username,
            password,
            ca_path=os.environ.get("WAZUH_INDEXER_CA") or None,
            timeout=httpx2.Timeout(3.0),
            max_retries=0,
            transport=transport,
        )
    except Exception as exc:
        return {"reachable": False, "detail": type(exc).__name__}
    try:
        with client:
            client.search(WAZUH_PROBE_INDEX, {"size": 0, "track_total_hits": False})
    except IndexerError as exc:
        if exc.status in (401, 403):
            return {
                "reachable": True,
                "detail": f"HTTP {exc.status}",
                "auth": "rejected",
            }
        if exc.status is not None:
            return {"reachable": False, "detail": f"HTTP {exc.status}"}
        return {"reachable": False, "detail": exc.transport or "IndexerError"}
    except Exception as exc:
        return {"reachable": False, "detail": type(exc).__name__}
    return {"reachable": True, "detail": "HTTP 200", "auth": "ok"}


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
        "latest_model_latency_model": "not measured",
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
                    "SELECT latency_ms, model FROM llm_attempts"
                    " WHERE latency_ms IS NOT NULL"
                    " ORDER BY created_at DESC, id DESC LIMIT 1"
                )
                row = cur.fetchone()
                latency: Any = int(row[0]) if row else "not measured"
                latency_model: Any = str(row[1]) if row else "not measured"
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
            "latest_model_latency_model": latency_model,
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
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    min_floor: int | None = Query(default=None, ge=1, le=6),
    verdict: str | None = Query(default=None),
    analyzed: bool | None = Query(default=None),
) -> Any:
    capped = min(limit, MAX_LIMIT)
    if verdict is not None and verdict not in ALLOWED_VERDICTS:
        return JSONResponse(status_code=422, content=dict(INVALID_QUERY))
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
                if verdict is not None:
                    where += (
                        " AND EXISTS(SELECT 1 FROM incident_analyses a"
                        " WHERE a.incident_id=i.id AND a.stage='analysis'"
                        " AND a.payload->>'verdict' = %s)"
                    )
                    params.append(verdict)
                if analyzed is True:
                    where += (
                        " AND EXISTS(SELECT 1 FROM incident_analyses a"
                        " WHERE a.incident_id=i.id AND a.stage='analysis')"
                    )
                elif analyzed is False:
                    where += (
                        " AND NOT EXISTS(SELECT 1 FROM incident_analyses a"
                        " WHERE a.incident_id=i.id AND a.stage='analysis')"
                    )
                cur.execute(f"SELECT COUNT(*) FROM incidents i {where}", params)
                count_row = cur.fetchone()
                total = int(count_row[0]) if count_row else 0
                cur.execute(
                    "SELECT i.id, i.title, i.severity_floor, i.severity_id,"
                    " i.ai_status,"
                    " i.verdict, i.first_seen, i.last_seen,"
                    " COALESCE(jsonb_array_length(i.event_uids),0),"
                    " EXISTS(SELECT 1 FROM incident_signals s WHERE"
                    " s.incident_id=i.id AND s.kind='injection'),"
                    " EXISTS(SELECT 1 FROM incident_analyses a"
                    " WHERE a.incident_id=i.id AND a.stage='analysis'),"
                    " EXISTS(SELECT 1 FROM llm_attempts t"
                    " WHERE t.incident_id=i.id AND t.purpose='triage'"
                    " AND t.outcome LIKE '%%quarantin%%'),"
                    " i.learned_rules"
                    f" FROM incidents i {where} ORDER BY 11 DESC,"
                    " i.severity_floor DESC, i.id DESC LIMIT %s OFFSET %s",
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
                        "analyzed": bool(r[10]),
                        "quarantined": bool(r[11]),
                        "learned_rules": list(r[12] or []),
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
                    " review_required, learned_rules FROM incidents WHERE id=%s AND"
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
                    if isinstance(a[11], str) and a[11].strip():
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
        "learned_rules": list(row[13] or []),
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


#: Stored rule lifecycle states; the only accepted ``status`` filter values.
ALLOWED_RULE_STATUSES = frozenset(
    {"candidate", "shadow", "active", "archived", "rolled_back"}
)

#: Deployment modes; the only accepted ``mode`` filter values. A rule is
#: deployed only while its status is ``shadow`` or ``active``.
ALLOWED_RULE_MODES = frozenset({"shadow", "active"})


def _rule_mode(status: str) -> str | None:
    """Return the deployment mode for a row status, or None when undeployed."""
    if status in ALLOWED_RULE_MODES:
        return status
    return None


def _sigma_summary(sigma_text: Any) -> tuple[str | None, list[str]]:
    """Return (level, technique tags) parsed from Sigma YAML, never raising.

    Anything unparseable yields ``(None, [])``: the API reports what the
    stored text says without validating it.
    """
    try:
        doc = yaml.safe_load(str(sigma_text or ""))
    except Exception:
        return None, []
    if not isinstance(doc, dict):
        return None, []
    raw_level = doc.get("level")
    level = str(raw_level) if isinstance(raw_level, str) and raw_level else None
    raw_tags = doc.get("tags")
    techniques: set[str] = set()
    if isinstance(raw_tags, list):
        for tag in raw_tags:
            if not isinstance(tag, str):
                continue
            lowered = tag.strip().lower()
            if not lowered.startswith("attack.t"):
                continue
            tid = lowered.removeprefix("attack.").upper()
            head = tid.split(".")[0]
            if len(head) == 5 and head[1:].isdigit():
                techniques.add(tid)
    return level, sorted(techniques)


def _rule_list_item(row: Any) -> dict[str, Any]:
    (
        rule_id,
        title,
        sigma_text,
        _native_text,
        _native_rule_id,
        version,
        status,
        _lineage,
        incident_id,
        hits,
        false_positives,
        created_at,
        _updated_at,
        _deployed_at,
    ) = row
    status_text = str(status)
    level, techniques = _sigma_summary(sigma_text)
    return {
        "id": int(rule_id),
        "title": str(title or ""),
        "status": status_text,
        "mode": _rule_mode(status_text),
        "version": int(version),
        "level": level,
        "techniques": techniques,
        "hits": int(hits or 0),
        "false_positives": int(false_positives or 0),
        "created_at": _iso(created_at),
        "source_incident_id": int(incident_id) if incident_id is not None else None,
    }


@app.get("/api/rules")
def list_rules(
    limit: int = Query(default=20, ge=1),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    status: str | None = Query(default=None),
    mode: str | None = Query(default=None),
) -> Any:
    capped = min(limit, MAX_LIMIT)
    if status is not None and status not in ALLOWED_RULE_STATUSES:
        return JSONResponse(status_code=422, content=dict(INVALID_QUERY))
    if mode is not None and mode not in ALLOWED_RULE_MODES:
        return JSONResponse(status_code=422, content=dict(INVALID_QUERY))
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                where = ""
                params: list[Any] = []
                if status is not None:
                    where += " WHERE status = %s"
                    params.append(status)
                if mode is not None:
                    where += " AND" if where else " WHERE"
                    where += " status = %s"
                    params.append(mode)
                cur.execute(f"SELECT COUNT(*) FROM rules{where}", params)
                count_row = cur.fetchone()
                total = int(count_row[0]) if count_row else 0
                cur.execute(
                    "SELECT id, title, sigma_text, native_text, native_rule_id,"
                    " version, status, lineage, incident_id, hits,"
                    " false_positives, created_at, updated_at, deployed_at"
                    f" FROM rules{where} ORDER BY id DESC LIMIT %s OFFSET %s",
                    [*params, capped, offset],
                )
                items = [_rule_list_item(r) for r in cur.fetchall()]
        return {"items": items, "total": total, "limit": capped, "offset": offset}
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})


def _lineage_dict(raw: Any) -> tuple[dict[str, Any], str | None]:
    """Return (lineage mapping, note); broken storage degrades to ``{}``."""
    if isinstance(raw, dict):
        if not raw:
            return {}, "no lineage recorded"
        return dict(raw), None
    return {}, "stored lineage is not an object; shown as empty"


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: int) -> Any:
    if rule_id < 1 or rule_id > MAX_RULE_ID:
        return JSONResponse(status_code=404, content={"detail": "rule not found"})
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, title, sigma_text, native_text, native_rule_id,"
                    " version, status, lineage, incident_id, hits,"
                    " false_positives, created_at, updated_at, deployed_at"
                    " FROM rules WHERE id = %s",
                    (rule_id,),
                )
                row = cur.fetchone()
                if row is None:
                    return JSONResponse(
                        status_code=404, content={"detail": "rule not found"}
                    )
                (
                    rid,
                    title,
                    sigma_text,
                    _native_text,
                    native_rule_id,
                    version,
                    status,
                    raw_lineage,
                    incident_id,
                    hits,
                    false_positives,
                    created_at,
                    updated_at,
                    deployed_at,
                ) = row
                lineage, lineage_note = _lineage_dict(raw_lineage)
                sigma_id_raw = lineage.get("sigma_rule_id")
                sigma_id = str(sigma_id_raw) if sigma_id_raw else None
                lineage_source = lineage.get("source_incident")
                source_id = (
                    int(lineage_source)
                    if isinstance(lineage_source, int)
                    and not isinstance(lineage_source, bool)
                    else int(incident_id)
                    if incident_id is not None
                    else None
                )
                source: dict[str, Any] | None = None
                if source_id is not None:
                    cur.execute(
                        "SELECT id, title FROM incidents WHERE id = %s", (source_id,)
                    )
                    srow = cur.fetchone()
                    source = {
                        "id": source_id,
                        "exists": srow is not None,
                        "title": str(srow[1] or "") if srow is not None else None,
                    }
                raw_backtest = lineage.get("backtest")
                backtest = (
                    dict(raw_backtest) if isinstance(raw_backtest, dict) else None
                )
                raw_history = lineage.get("history")
                history = list(raw_history) if isinstance(raw_history, list) else []
                raw_ledger = lineage.get("ledger_ids")
                ledger_ids = list(raw_ledger) if isinstance(raw_ledger, list) else []
                raw_cited = lineage.get("cited_uids")
                cited_uids = (
                    [str(u) for u in raw_cited] if isinstance(raw_cited, list) else []
                )
                cur.execute(
                    "SELECT id, title, learned_rules FROM incidents"
                    " WHERE learned_rules @> %s"
                    " AND correlation_key NOT LIKE 'adv-llm:%%'"
                    " ORDER BY id ASC",
                    (Jsonb([{"rule_db_id": int(rid)}]),),
                )
                findings = []
                for frow in cur.fetchall():
                    refs = frow[2] or []
                    for ref in refs if isinstance(refs, list) else []:
                        if isinstance(ref, dict) and ref.get("rule_db_id") == int(rid):
                            findings.append(
                                {
                                    "incident_id": int(frow[0]),
                                    "incident_title": str(frow[1] or ""),
                                    "mode": ref.get("mode"),
                                    "shadow": bool(ref.get("shadow", False)),
                                    "version": ref.get("version"),
                                    "findings": ref.get("findings"),
                                }
                            )
                            break
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})

    status_text = str(status)
    mode = _rule_mode(status_text)
    level, techniques = _sigma_summary(sigma_text)
    anchor = (
        int(native_rule_id)
        if isinstance(native_rule_id, int) and not isinstance(native_rule_id, bool)
        else None
    )
    rounds_raw = lineage.get("rounds_used")
    model_raw = lineage.get("model")
    prompt_raw = lineage.get("prompt_version")
    return {
        "id": int(rid),
        "title": str(title or ""),
        "status": status_text,
        "mode": mode,
        "version": int(version),
        "level": level,
        "techniques": techniques,
        "sigma_text": str(sigma_text or ""),
        "wazuh": {
            "native_rule_id": anchor,
            "native_rule_ids": [anchor] if anchor is not None else [],
            "group": f"corvus_{sigma_id}" if sigma_id else None,
            "mode": mode,
            "pair_note": (
                "Deployed as a sudo/auditd pair: the pair-secondary id is the"
                " next free id above the anchor at export time and is not stored."
            ),
        },
        "hits": int(hits or 0),
        "false_positives": int(false_positives or 0),
        "created_at": _iso(created_at),
        "updated_at": _iso(updated_at),
        "deployed_at": _iso(deployed_at),
        "source_incident_id": int(incident_id) if incident_id is not None else None,
        "lineage": {
            "sigma_rule_id": sigma_id,
            "source_incident": source,
            "cited_uids": cited_uids,
            "backtest": backtest,
            "rounds_used": int(rounds_raw)
            if isinstance(rounds_raw, int) and not isinstance(rounds_raw, bool)
            else None,
            "model": str(model_raw) if isinstance(model_raw, str) else None,
            "prompt_version": str(prompt_raw) if isinstance(prompt_raw, str) else None,
            "ledger_ids": ledger_ids,
            "lineage_note": lineage_note,
        },
        "transitions": history,
        "findings": findings,
    }


#: Verdicts that count as real verdicts (mirrors ``verdictKind`` in
#: ``ui/src/App.tsx``): anything else is triaged/failed/quarantined/pending.
_REAL_VERDICTS = frozenset(
    {"true_positive", "benign_authorized", "false_positive", "needs_human"}
)

#: Final severity (1..6) mapped to the four UI levels; 1 is counted
#: separately as informational.
_UI_LEVELS = {
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "critical",
}


def _verdict_kind(verdict: Any, ai_status: str, quarantined: bool) -> str:
    """Mirror the UI ``verdictKind``: failed and quarantined are not verdicts."""
    if isinstance(verdict, str) and verdict in _REAL_VERDICTS:
        return "verdict"
    if quarantined:
        return "quarantined"
    if ai_status == "failed":
        return "failed"
    if ai_status == "done":
        return "triaged"
    return "pending"


def _redacted_address(url: str | None) -> str | None:
    """Return ``scheme://host[:port]`` only, never userinfo/path/query/key."""
    if not url:
        return None
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if not parts.hostname:
            return None
        host = parts.hostname.lower()
        port = f":{parts.port}" if parts.port else ""
        scheme = (parts.scheme or "https").lower()
        return f"{scheme}://{host}{port}"
    except Exception:
        return None


def _connection_state(url: str | None, check: Mapping[str, Any]) -> str:
    """Map one check to a settings state; rejected credentials never pass."""
    if not url:
        return "not_configured"
    auth = check.get("auth")
    if auth == "missing":
        return "no_credentials"
    if auth == "rejected":
        return "auth_failed"
    return "connected" if check.get("reachable") is True else "unreachable"


def _sweep_tables_exist(cur: Any) -> bool:
    try:
        cur.execute("SELECT to_regclass('public.sweep_runs')")
        row = cur.fetchone()
        return bool(row and row[0])
    except Exception:
        return False


@app.get("/api/dashboard")
def get_dashboard() -> Any:
    """Totals, 24 hourly buckets (by ``first_seen``), sweep markers, recent.

    The 24 buckets normally cover the last 24 hours; when those hold
    no incidents the window anchors to the most recent ``first_seen``
    instead (``window.anchored_to`` reports ``now`` or
    ``latest_data``). Sweep markers use the same window.
    """
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                scope = "WHERE correlation_key NOT LIKE 'adv-llm:%%'"
                cur.execute(f"SELECT COUNT(*) FROM incidents {scope}")
                total_row = cur.fetchone()
                total = int(total_row[0]) if total_row else 0
                cur.execute(
                    "SELECT severity_id, COUNT(*) FROM incidents"
                    f" {scope} GROUP BY severity_id"
                )
                by_level = {
                    "informational": 0,
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                }
                for row in cur.fetchall():
                    by_level[_UI_LEVELS.get(int(row[0]), "informational")] += int(
                        row[1]
                    )
                cur.execute(
                    f"SELECT verdict, COUNT(*) FROM incidents {scope} GROUP BY verdict"
                )
                by_verdict: dict[str, int] = {}
                for row in cur.fetchall():
                    key = str(row[0]) if row[0] is not None else "none"
                    by_verdict[key] = int(row[1])
                cur.execute(
                    f"SELECT COUNT(*) FROM incidents {scope} AND ai_status = 'pending'"
                )
                pending_row = cur.fetchone()
                pending = int(pending_row[0]) if pending_row else 0
                cur.execute(
                    f"SELECT COUNT(*) FROM incidents {scope} AND ai_status = 'failed'"
                )
                failed_row = cur.fetchone()
                failed = int(failed_row[0]) if failed_row else 0
                cur.execute(
                    "SELECT COUNT(*) FROM incidents i"
                    f" {scope} AND EXISTS(SELECT 1 FROM incident_analyses a"
                    " WHERE a.incident_id = i.id AND a.stage = 'analysis'"
                    " AND a.status = 'resolved')"
                )
                analyzed_row = cur.fetchone()
                analyzed = int(analyzed_row[0]) if analyzed_row else 0
                cur.execute(
                    "SELECT COUNT(*) FROM incidents i"
                    f" {scope} AND EXISTS(SELECT 1 FROM llm_attempts t"
                    " WHERE t.incident_id = i.id AND t.purpose = 'triage'"
                    " AND t.outcome LIKE '%quarantin%')"
                )
                quarantined_row = cur.fetchone()
                quarantined = int(quarantined_row[0]) if quarantined_row else 0
                cur.execute(
                    "SELECT COUNT(*) FROM incidents i"
                    f" {scope} AND EXISTS(SELECT 1 FROM incident_signals s"
                    " WHERE s.incident_id = i.id AND s.kind = 'injection')"
                )
                injection_row = cur.fetchone()
                with_injection = int(injection_row[0]) if injection_row else 0
                cur.execute("SELECT COALESCE(SUM(usd), 0) FROM spend")
                spend_row = cur.fetchone()
                spend_total = float(spend_row[0]) if spend_row else 0.0
                try:
                    from corvus.llm.spend import get_spend_cap

                    cap: Any = get_spend_cap()
                except Exception:
                    cap = None
                cur.execute(f"SELECT MAX(first_seen) FROM incidents {scope}")
                latest_row = cur.fetchone()
                latest = latest_row[0] if latest_row else None
                if isinstance(latest, datetime) and latest.tzinfo is None:
                    latest = latest.replace(tzinfo=UTC)
                cur.execute(
                    f"SELECT COUNT(*) FROM incidents {scope}"
                    " AND first_seen >= NOW() - INTERVAL '24 hours'"
                )
                recent_count_row = cur.fetchone()
                recent_count = int(recent_count_row[0]) if recent_count_row else 0
                cur.execute("SELECT NOW()")
                now_row = cur.fetchone()
                now = now_row[0] if now_row else datetime.now(UTC)
                if now.tzinfo is None:
                    now = now.replace(tzinfo=UTC)
                if latest is None or recent_count > 0:
                    base = now.replace(minute=0, second=0, microsecond=0)
                    anchored_to = "now"
                else:
                    base = latest.replace(minute=0, second=0, microsecond=0)
                    anchored_to = "latest_data"
                window_start = base - timedelta(hours=23)
                window_end = base + timedelta(hours=1)
                cur.execute(
                    "SELECT date_trunc('hour', first_seen), COUNT(*)"
                    " FROM incidents"
                    f" {scope} AND first_seen >= %s AND first_seen < %s"
                    " GROUP BY 1",
                    (window_start, window_end),
                )
                bucket_counts: dict[str, int] = {}
                for r in cur.fetchall():
                    moment = r[0]
                    if isinstance(moment, datetime):
                        if moment.tzinfo is None:
                            moment = moment.replace(tzinfo=UTC)
                        bucket_counts[
                            moment.astimezone(UTC).strftime("%Y-%m-%dT%H:00:00Z")
                        ] = int(r[1])
                activity = []
                for back in range(23, -1, -1):
                    hour = base - timedelta(hours=back)
                    key = hour.strftime("%Y-%m-%dT%H:%M:%SZ")
                    activity.append(
                        {"hour": key, "incidents": bucket_counts.get(key, 0)}
                    )
                markers: list[dict[str, Any]] = []
                if _sweep_tables_exist(cur):
                    cur.execute(
                        "SELECT id, started_at, finished_at, status, analyzed,"
                        " failed_analyses, skipped_policy, skipped_budget"
                        " FROM sweep_runs"
                        " WHERE started_at >= %s AND started_at < %s"
                        " ORDER BY started_at ASC",
                        (window_start, window_end),
                    )
                    markers = [
                        {
                            "id": int(r[0]),
                            "started_at": _iso(r[1]),
                            "finished_at": _iso(r[2]),
                            "status": str(r[3]),
                            "analyzed": int(r[4] or 0),
                            "failed_analyses": int(r[5] or 0),
                            "skipped_policy": int(r[6] or 0),
                            "skipped_budget": int(r[7] or 0),
                        }
                        for r in cur.fetchall()
                    ]
                cur.execute(
                    "SELECT i.id, i.title, i.severity_id, i.ai_status, i.verdict,"
                    " a.created_at,"
                    " EXISTS(SELECT 1 FROM llm_attempts t"
                    " WHERE t.incident_id = i.id AND t.purpose = 'triage'"
                    " AND t.outcome LIKE '%quarantin%'),"
                    " a.payload->>'verdict'"
                    " FROM incidents i JOIN incident_analyses a"
                    " ON a.incident_id = i.id AND a.stage = 'analysis'"
                    " AND a.status = 'resolved'"
                    f" {scope} ORDER BY a.created_at DESC, i.id DESC LIMIT 5"
                )
                recent = [
                    {
                        "id": int(r[0]),
                        "title": str(r[1] or ""),
                        "final_severity": int(r[2]),
                        "verdict_kind": _verdict_kind(r[4], str(r[3]), bool(r[6])),
                        "verdict": str(r[7])
                        if isinstance(r[7], str) and r[7] in _REAL_VERDICTS
                        else None,
                        "analyzed_at": _iso(r[5]),
                    }
                    for r in cur.fetchall()
                ]
        return {
            "totals": {
                "incidents": total,
                "by_severity": by_level,
                "by_verdict": by_verdict,
                "pending": pending,
                "analyzed": analyzed,
                "failed": failed,
                "quarantined": quarantined,
                "with_injection": with_injection,
            },
            "spend": {"total_usd": spend_total, "cap_usd": cap},
            "activity": activity,
            "activity_bucket": "first_seen hour (UTC); empty hours are 0",
            "window": {
                "start": _iso(window_start),
                "end": _iso(window_end),
                "anchored_to": anchored_to,
            },
            "sweep_runs": markers,
            "recent": recent,
        }
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})


@app.get("/api/sweep/status")
def get_sweep_status() -> Any:
    """Last sweep run, next-run estimate, running flag, and its policy."""
    url = _database_url()
    if not url:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                if not _sweep_tables_exist(cur):
                    return {
                        "last": None,
                        "running": False,
                        "next_run_at": None,
                        "policy": None,
                    }
                cur.execute(
                    "SELECT s.id, s.poll_cycle_id, s.started_at, s.finished_at,"
                    " s.status, s.error_code, s.analyzed, s.failed_analyses,"
                    " s.skipped_policy, s.skipped_budget, s.policy,"
                    " s.interval_seconds,"
                    " p.alerts_seen, p.incidents_upserted, p.status"
                    " FROM sweep_runs s LEFT JOIN wazuh_poll_cycles p"
                    " ON p.id = s.poll_cycle_id"
                    " ORDER BY s.id DESC LIMIT 1"
                )
                row = cur.fetchone()
                if row is None:
                    return {
                        "last": None,
                        "running": False,
                        "next_run_at": None,
                        "policy": None,
                    }
                (
                    rid,
                    poll_id,
                    started,
                    finished,
                    status,
                    error_code,
                    analyzed,
                    failed_analyses,
                    skipped_policy,
                    skipped_budget,
                    policy,
                    interval,
                    alerts_seen,
                    incidents_upserted,
                    poll_status,
                ) = row
                try:
                    interval_s = float(interval or 300)
                except TypeError, ValueError:
                    interval_s = 300.0
                cur.execute("SELECT NOW()")
                now = (cur.fetchone() or [None])[0]
                running = False
                next_run_at = None
                if started is not None and now is not None:
                    age = (now - started).total_seconds()
                    if str(status) == "running" and age < 3 * interval_s:
                        running = True
                    if age < 3 * interval_s:
                        nxt = started + timedelta(seconds=interval_s)
                        next_run_at = _iso(nxt)
                last = {
                    "id": int(rid),
                    "poll_cycle_id": int(poll_id) if poll_id is not None else None,
                    "started_at": _iso(started),
                    "finished_at": _iso(finished),
                    "status": str(status),
                    "error_code": str(error_code or ""),
                    "analyzed": int(analyzed or 0),
                    "failed_analyses": int(failed_analyses or 0),
                    "skipped_policy": int(skipped_policy or 0),
                    "skipped_budget": int(skipped_budget or 0),
                    "new_alerts": int(alerts_seen or 0)
                    if alerts_seen is not None
                    else None,
                    "new_incidents": int(incidents_upserted or 0)
                    if incidents_upserted is not None
                    else None,
                    "poll_status": str(poll_status) if poll_status else None,
                    "interval_seconds": interval_s,
                }
        return {
            "last": last,
            "running": running,
            "next_run_at": next_run_at,
            "policy": dict(policy or {}),
        }
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})


def _llm_base_url(purpose: str) -> str | None:
    """Return the backend address from the same resolver backends use.

    Uses :func:`corvus.llm.config.get_backend` so defaults, the
    ``TRIAGE_``/``ANALYSIS_`` overrides and ``MODEL_PROFILE`` routing
    match what actually serves. Any resolver failure yields None
    (``not_configured``); only the redacted address ever leaves here.
    """
    try:
        from corvus.llm.config import get_backend

        return get_backend(purpose).base_url
    except Exception:
        return None


def _endpoint_entry(name: str, url: str | None, kind: str) -> dict[str, Any]:
    """One settings connection entry reusing the health checks."""
    if kind == "database":
        check = check_database(url)
        display = _redacted_address(url)
    elif kind == "wazuh":
        check = check_wazuh_indexer(
            url,
            os.environ.get("WAZUH_INDEXER_USER"),
            os.environ.get("WAZUH_INDEXER_PASSWORD"),
        )
        display = _redacted_address(url)
    else:
        check = check_endpoint(name, url)
        display = _redacted_address(url)
    return {
        "name": name,
        "address": display,
        "state": _connection_state(url, check),
    }


@app.get("/api/settings")
def get_settings_view() -> Any:
    """Effective sweep policy plus redacted connection settings (read-only)."""
    try:
        from corvus import __version__ as app_version
        from corvus.attack.build import ATTACK_VERSION
        from corvus.live.sweep import effective_policy
        from corvus.normalize.ocsf import OCSF_SCHEMA_VERSION
    except Exception:
        return JSONResponse(status_code=500, content={"detail": "internal error"})
    try:
        policy = effective_policy()
        policy_body: Any = {"source": "configured", "policy": policy.as_dict()}
    except ValueError as exc:
        policy_body = {"source": "configured", "policy": None, "error": str(exc)}
    wazuh_url = os.environ.get("WAZUH_INDEXER_URL")
    triage_url = _llm_base_url("triage")
    analysis_url = _llm_base_url("analysis")
    database_url = _database_url()
    entries = [
        _endpoint_entry("database", database_url, "database"),
        _endpoint_entry("wazuh_indexer", wazuh_url, "wazuh"),
        _endpoint_entry("triage_model", triage_url, "http"),
        _endpoint_entry("reasoning_model", analysis_url, "http"),
    ]
    try:
        from corvus.llm.spend import get_spend_cap

        cap: Any = get_spend_cap()
    except Exception:
        cap = None
    return {
        "sweep_policy": policy_body,
        "connections": entries,
        "spend_cap_usd": cap,
        "app_version": app_version,
        "attack_version": ATTACK_VERSION,
        "ocsf_version": OCSF_SCHEMA_VERSION,
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
