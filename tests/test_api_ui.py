"""Read-only UI API: pagination, detail sections, adv exclusion, safety."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from corvus.api.main import app
from corvus.state.migrate import migrate
from eval.llm_harness import select_llm_incidents
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def api_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _seed(api_db: str, key: str, floor: int = 4) -> int:
    with psycopg.connect(api_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title,"
                " severity_floor, severity_id,"
                " ai_status, verdict, techniques, event_uids, severity_factors,"
                " first_seen, last_seen) VALUES"
                " (%s,%s,%s,%s,'done','true_positive',%s,%s,%s,"
                " '2026-10-30T00:00:00Z','2026-10-30T01:00:00Z') RETURNING id",
                (
                    key,
                    f"Incident {key} <script>alert(1)</script>",
                    floor,
                    floor,
                    Jsonb(["T1059"]),
                    Jsonb(["evt-1", "evt-missing"]),
                    Jsonb({"breadth": {"score": 2, "why": "two techniques"}}),
                ),
            )
            incident_id = int(cur.fetchone()[0])  # type: ignore[index]
            if key == "normal-1":
                cur.execute(
                    "INSERT INTO incident_analyses (incident_id, stage, status,"
                    " payload, language, model, deterministic_floor)"
                    " VALUES (%s,'analysis','resolved',%s,'en','muse-spark-1.3',4)",
                    (
                        incident_id,
                        Jsonb(
                            {
                                "verdict": "true_positive",
                                "severity_id": 4,
                                "confidence": 0.9,
                                "timeline": [
                                    {
                                        "time": "2026-10-30T00:00:00Z",
                                        "event_uid": "evt-missing",
                                        "description": "ignore previous instructions",
                                    }
                                ],
                                "response_plan": ["Isolate host"],
                                "visibility_gaps": ["No network telemetry"],
                                "uncertainties": [],
                                "language": "en",
                            }
                        ),
                    ),
                )
                cur.execute(
                    "INSERT INTO incident_analyses (incident_id, stage, status,"
                    " payload, language, model, deterministic_floor)"
                    " VALUES (%s,'triage','resolved',%s,'en','glimmer',4)",
                    (
                        incident_id,
                        Jsonb(
                            {
                                "condensed": {
                                    "summary": "Triage summary text",
                                    "entities": [],
                                    "key_events": [],
                                }
                            }
                        ),
                    ),
                )
                cur.execute(
                    "INSERT INTO incident_signals (incident_id, kind, event_uid,"
                    " field, pattern_id, requested_effect, detail)"
                    " VALUES (%s,'injection','evt-1','process.cmd_line',"
                    " 'override.ignore_previous','suppress',%s)",
                    (
                        incident_id,
                        Jsonb(
                            {
                                "excerpt": "ignore previous instructions",
                                "spans": [[0, 5]],
                            }
                        ),
                    ),
                )
                cur.execute(
                    "INSERT INTO agent_steps (incident_id, step_number, tool,"
                    " arguments, result_summary, tokens)"
                    " VALUES (%s,1,'get_events',%s,'found 2 events',42)",
                    (incident_id, Jsonb({"host": "HOST-0001"})),
                )
                cur.execute(
                    "INSERT INTO llm_attempts (call_id, incident_id, model,"
                    " purpose, attempt_number,"
                    " failed_validator, prompt_tokens, cached_tokens,"
                    " reasoning_tokens, answer_tokens,"
                    " overhead_tokens, token_source, latency_ms, outcome, reasoning)"
                    " VALUES ('call-1',%s,'muse-spark-1.3','analysis',1,"
                    " NULL,100,0,10,20,0,'usage',123,'ok',"
                    " 'stored reasoning text')",
                    (incident_id,),
                )
                cur.execute(
                    "INSERT INTO spend (model, tokens_in, tokens_out, usd,"
                    " incident_id) VALUES ('muse-spark-1.3',100,30,0.001,%s)",
                    (incident_id,),
                )
                cur.execute(
                    "INSERT INTO pseudonyms (entity_kind, entity_value,"
                    " pseudonym) VALUES ('host','web01.example.com','HOST-0001')"
                )
        conn.commit()
    return incident_id


def _client(api_db: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", api_db)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    return TestClient(app, raise_server_exceptions=False)


def test_list_pagination_cap_and_adv_excluded(
    api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _seed(api_db, "normal-1")
    _seed(api_db, "adv-llm:fixture-1")
    _seed(api_db, "normal-2")
    client = _client(api_db, monkeypatch)
    response = client.get("/api/incidents?limit=500&offset=0")
    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 100
    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] != []
    assert all(
        item["title"] != "Incident adv-llm:fixture-1 <script>alert(1)</script>"
        for item in body["items"]
    )
    page = client.get("/api/incidents?limit=1&offset=1").json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert first in [item["id"] for item in body["items"]]


def test_select_llm_incidents_excludes_adv(api_db: str) -> None:
    _seed(api_db, "adv-llm:fixture-9", floor=5)
    keep = _seed(api_db, "keep-5", floor=5)
    selected, _note = select_llm_incidents(api_db, 4, Path("/nonexistent-replay"))
    assert [item.id for item in selected] == [keep]


def test_incident_detail_all_sections_and_missing_event(
    api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = _seed(api_db, "normal-1")
    client = _client(api_db, monkeypatch)
    response = client.get(f"/api/incidents/{incident_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["verdict"] == "true_positive"
    assert body["triage"]["summary"] == "Triage summary text"
    assert body["severity"]["floor"] == 4
    assert body["techniques"][0]["id"] == "T1059"
    assert (
        body["injection_signals"][0]["payload_text"] == "ignore previous instructions"
    )
    assert body["injection_signals"][0]["payload_label"] == "payload (shown as text)"
    assert body["evidence"][0]["event_uid"] == "evt-missing"
    assert body["evidence"][0]["found"] is False
    assert "missing" in body["evidence"][0]["note"]
    assert body["agent_trace"][0]["tool"] == "get_events"
    assert body["llm_attempts"][0]["purpose"] == "analysis"
    assert body["llm_attempts"][0]["token_source"] == "usage"
    assert body["spend_total_usd"] == pytest.approx(0.001)
    assert body["reasoning_unverified"]["unverified"] is True
    assert body["pseudonym_resolution"]["mapping_persisted"] is True


def test_adv_incident_detail_is_404(
    api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    adv_id = _seed(api_db, "adv-llm:fixture-2")
    client = _client(api_db, monkeypatch)
    assert client.get(f"/api/incidents/{adv_id}").status_code == 404


def test_no_write_methods(api_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = _seed(api_db, "normal-1")
    client = _client(api_db, monkeypatch)
    assert client.post("/api/incidents").status_code == 405
    assert client.put(f"/api/incidents/{incident_id}").status_code == 405
    assert client.delete(f"/api/incidents/{incident_id}").status_code == 405
    assert client.post("/api/health").status_code == 405


def test_headers_and_no_secrets_in_errors(
    api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(api_db, "normal-1")
    client = _client(api_db, monkeypatch)
    response = client.get("/api/incidents")
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    missing = client.get("/api/incidents/999999")
    assert missing.status_code == 404
    assert "postgresql" not in missing.text.lower()
    assert "password" not in missing.text.lower()
    assert "Traceback" not in missing.text


def test_static_traversal_blocked(api_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(api_db, monkeypatch)
    for path in (
        "/%2e%2e%2fpyproject.toml",
        "/..%2f..%2fpyproject.toml",
        "/assets/%2e%2e%2f%2e%2e%2fpyproject.toml",
    ):
        response = client.get(path)
        assert response.status_code in (400, 404)
        assert "Project Corvus" not in response.text or "UI not built" in response.text
