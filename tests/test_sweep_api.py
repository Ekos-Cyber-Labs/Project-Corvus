"""Read-only sweep API routes: shape, empty database, and redaction.

Covers ``/api/dashboard``, ``/api/sweep/status`` and ``/api/settings``.
No network and no model calls: the model and Wazuh endpoints point at
closed loopback ports and the security assertions scan every response
for secrets, passwords, userinfo ``@`` in URLs, and env secret values.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from corvus.api.main import app
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def sweep_api_db(monkeypatch: pytest.MonkeyPatch) -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _client(url: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("META_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("META_API_KEY", "test-key-value-that-must-not-leak")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.example.com:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "wazuh-user")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "wazuh-password-value")
    monkeypatch.setenv("SPEND_CAP_USD", "42.5")
    return TestClient(app, raise_server_exceptions=False)


def _seed_incident(
    url: str,
    key: str,
    floor: int,
    final: int,
    verdict: str | None,
    ai_status: str,
    title: str,
    analysed: bool = False,
) -> int:
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, ai_status, verdict, techniques, event_uids,"
                " first_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW()) RETURNING id",
                (
                    key,
                    title,
                    floor,
                    final,
                    ai_status,
                    verdict,
                    Jsonb(["T1059"]),
                    Jsonb(["evt-1"]),
                ),
            )
            incident_id = int(cur.fetchone()[0])  # type: ignore[index]
            if analysed:
                cur.execute(
                    "INSERT INTO incident_analyses (incident_id, stage, status,"
                    " payload, language, model, deterministic_floor)"
                    " VALUES (%s,'analysis','resolved',%s,'en','m',%s)",
                    (
                        incident_id,
                        Jsonb({"verdict": verdict or "true_positive"}),
                        floor,
                    ),
                )
        conn.commit()
    return incident_id


def test_empty_database_shapes(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sweep_api_db, monkeypatch)
    dash = client.get("/api/dashboard")
    assert dash.status_code == 200
    body = dash.json()
    assert body["totals"]["incidents"] == 0
    assert body["totals"]["by_severity"] == {
        "informational": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    assert body["totals"]["pending"] == 0
    assert body["spend"] == {"total_usd": 0.0, "cap_usd": 42.5}
    assert len(body["activity"]) == 24
    assert all(b["incidents"] == 0 for b in body["activity"])
    assert body["activity_bucket"].startswith("first_seen")
    assert body["sweep_runs"] == []
    assert body["recent"] == []

    status = client.get("/api/sweep/status")
    assert status.status_code == 200
    sbody = status.json()
    assert sbody["last"] is None
    assert sbody["running"] is False
    assert sbody["next_run_at"] is None
    assert sbody["policy"] is None

    settings = client.get("/api/settings")
    assert settings.status_code == 200
    stbody = settings.json()
    assert stbody["sweep_policy"]["source"] == "configured"
    assert stbody["sweep_policy"]["policy"]["min_floor"] == 4
    assert stbody["spend_cap_usd"] == 42.5
    assert stbody["app_version"]
    assert stbody["attack_version"]
    assert stbody["ocsf_version"]


def test_dashboard_aggregation_and_verdict_kinds(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_incident(
        sweep_api_db,
        "crit-1",
        5,
        5,
        "true_positive",
        "done",
        "Critical chain",
        analysed=True,
    )
    _seed_incident(sweep_api_db, "high-1", 4, 4, None, "pending", "High pending")
    failed_id = _seed_incident(
        sweep_api_db,
        "fail-1",
        3,
        3,
        None,
        "failed",
        "Failed one",
        analysed=True,
    )
    with psycopg.connect(sweep_api_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO llm_attempts (call_id, incident_id, model, purpose,"
                " attempt_number, outcome) VALUES"
                " ('c1', %s, 'glimmer', 'triage', 1, 'quarantined')",
                (failed_id,),
            )
            cur.execute(
                "INSERT INTO incident_signals (incident_id, kind, event_uid,"
                " field, pattern_id, requested_effect) VALUES"
                " (%s, 'injection', 'evt-1', 'command', 'exec-echo', 'suppress')",
                (failed_id,),
            )
            cur.execute(
                "INSERT INTO wazuh_poll_cycles (alerts_seen, incidents_upserted,"
                " status) VALUES (10, 2, 'ok')"
            )
            cur.execute(
                "INSERT INTO sweep_runs (poll_cycle_id, status, analyzed,"
                " failed_analyses, skipped_policy, skipped_budget, policy,"
                " interval_seconds) VALUES"
                " (1, 'ok', 1, 1, 0, 0, %s, 300)",
                (Jsonb({"min_floor": 4}),),
            )
        conn.commit()
    client = _client(sweep_api_db, monkeypatch)
    body = client.get("/api/dashboard").json()
    assert body["totals"]["incidents"] == 3
    assert body["totals"]["by_severity"]["critical"] == 1
    assert body["totals"]["by_severity"]["high"] == 1
    assert body["totals"]["by_severity"]["medium"] == 1
    assert body["totals"]["pending"] == 1
    assert body["totals"]["failed"] == 1
    assert body["totals"]["analyzed"] == 2
    assert body["totals"]["quarantined"] == 1
    assert body["totals"]["with_injection"] == 1
    assert sum(b["incidents"] for b in body["activity"]) == 3
    kinds = {r["id"]: r["verdict_kind"] for r in body["recent"]}
    assert set(kinds.values()) <= {"verdict", "failed", "quarantined", "pending"}
    assert len(body["recent"]) == 2
    assert len(body["sweep_runs"]) == 1

    status = client.get("/api/sweep/status").json()
    assert status["last"]["new_alerts"] == 10
    assert status["last"]["new_incidents"] == 2
    assert status["last"]["analyzed"] == 1
    assert status["policy"] == {"min_floor": 4}
    assert status["running"] is False


def test_hostile_titles_do_not_break_responses(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = (
        "x\x01\x02<script>alert(1)</script> $(rm -rf /) ${x}"
        ' "quoted" \\ backslash \n newline \U0001f4a5 end'
    )
    _seed_incident(
        sweep_api_db,
        "hostile-1",
        6,
        6,
        "needs_human",
        "done",
        hostile,
        analysed=True,
    )
    client = _client(sweep_api_db, monkeypatch)
    for path in ("/api/dashboard", "/api/sweep/status", "/api/settings"):
        response = client.get(path)
        assert response.status_code == 200, path
        response.json()
    recent = client.get("/api/dashboard").json()["recent"]
    assert recent and recent[0]["title"] == hostile
    assert recent[0]["verdict_kind"] == "verdict"


def test_no_secrets_or_userinfo_in_responses(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_incident(sweep_api_db, "s-1", 4, 4, None, "pending", "pending one")
    client = _client(sweep_api_db, monkeypatch)
    texts = []
    for path in ("/api/dashboard", "/api/sweep/status", "/api/settings"):
        response = client.get(path)
        assert response.status_code == 200
        body = response.json()
        assert response.headers["Content-Security-Policy"].startswith(
            "default-src 'self'"
        )
        texts.append(response.text)
        if path == "/api/settings":
            for entry in body["connections"]:
                address = entry.get("address")
                if address is not None:
                    assert "@" not in address
                    assert "?" not in address
                    assert "/" in address
                    assert address.count("/") == 2
    blob = "\n".join(texts)
    assert "password" not in blob.lower()
    assert "test-key-value-that-must-not-leak" not in blob
    assert "wazuh-password-value" not in blob
    assert "wazuh-user" not in blob
    settings = client.get("/api/settings").json()
    by_name = {e["name"]: e for e in settings["connections"]}
    assert by_name["wazuh_indexer"]["address"] == "https://wazuh.example.com:9200"
    assert by_name["database"]["state"] == "connected"


def test_only_get_routes_for_sweep_dashboard(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sweep_api_db, monkeypatch)
    for path in ("/api/dashboard", "/api/sweep/status", "/api/settings"):
        assert client.post(path).status_code in (404, 405)
        assert client.put(path).status_code in (404, 405)
        assert client.delete(path).status_code in (404, 405)


def test_dashboard_window_anchors_to_now_when_recent(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_incident(
        sweep_api_db,
        "now-1",
        4,
        4,
        "true_positive",
        "done",
        "Now one",
        analysed=True,
    )
    client = _client(sweep_api_db, monkeypatch)
    body = client.get("/api/dashboard").json()
    assert body["window"]["anchored_to"] == "now"
    assert body["window"]["start"] and body["window"]["end"]
    assert len(body["activity"]) == 24
    assert sum(b["incidents"] for b in body["activity"]) == 1


def test_dashboard_window_anchors_to_latest_data_when_old(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with psycopg.connect(sweep_api_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, ai_status, techniques, event_uids, first_seen)"
                " VALUES ('old-1', 'Old one', 4, 4, 'pending', %s, %s,"
                " NOW() - INTERVAL '5 days')",
                (Jsonb(["T1059"]), Jsonb(["evt-old"])),
            )
        conn.commit()
    client = _client(sweep_api_db, monkeypatch)
    body = client.get("/api/dashboard").json()
    assert body["window"]["anchored_to"] == "latest_data"
    assert sum(b["incidents"] for b in body["activity"]) == 1
    assert body["activity"][-1]["incidents"] == 1


def test_dashboard_window_empty_database(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sweep_api_db, monkeypatch)
    body = client.get("/api/dashboard").json()
    assert body["window"]["anchored_to"] == "now"
    assert body["window"]["start"] and body["window"]["end"]
    assert len(body["activity"]) == 24
    assert all(b["incidents"] == 0 for b in body["activity"])
    assert body["sweep_runs"] == []


def test_dashboard_analyzed_counts_only_resolved(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved_id = _seed_incident(
        sweep_api_db,
        "res-1",
        4,
        4,
        "true_positive",
        "done",
        "Resolved one",
        analysed=True,
    )
    with psycopg.connect(sweep_api_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, ai_status, techniques, event_uids, first_seen)"
                " VALUES ('fail-1', 'Failed one', 4, 4, 'failed', %s, %s, NOW())"
                " RETURNING id",
                (Jsonb(["T1059"]), Jsonb(["evt-f"])),
            )
            failed_row = cur.fetchone()
            failed_id = int(failed_row[0]) if failed_row else 0
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, ai_status, techniques, event_uids, first_seen)"
                " VALUES ('quar-1', 'Quarantined one', 4, 4, 'pending',"
                " %s, %s, NOW()) RETURNING id",
                (Jsonb(["T1059"]), Jsonb(["evt-q"])),
            )
            quar_row = cur.fetchone()
            quar_id = int(quar_row[0]) if quar_row else 0
            cur.execute(
                "INSERT INTO llm_attempts (call_id, incident_id, model, purpose,"
                " attempt_number, outcome) VALUES"
                " ('q1', %s, 'glimmer', 'triage', 1, 'quarantined')",
                (quar_id,),
            )
        conn.commit()
    assert resolved_id and failed_id and quar_id
    client = _client(sweep_api_db, monkeypatch)
    body = client.get("/api/dashboard").json()
    assert body["totals"]["incidents"] == 3
    assert body["totals"]["analyzed"] == 1
    assert body["totals"]["failed"] == 1
    assert body["totals"]["quarantined"] == 1
    assert len(body["recent"]) == 1


def test_settings_uses_backend_resolver(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sweep_api_db, monkeypatch)
    by_name = {e["name"]: e for e in client.get("/api/settings").json()["connections"]}
    assert by_name["triage_model"]["address"] == "http://127.0.0.1:9"
    assert by_name["reasoning_model"]["address"] == "http://127.0.0.1:9"
    assert by_name["triage_model"]["state"] != "not_configured"
    assert by_name["reasoning_model"]["state"] != "not_configured"


def test_settings_default_meta_url_without_env(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", sweep_api_db)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("META_API_KEY", "test-key-value-that-must-not-leak")
    monkeypatch.delenv("META_BASE_URL", raising=False)
    monkeypatch.delenv("ANALYSIS_BASE_URL", raising=False)
    monkeypatch.delenv("TRIAGE_BASE_URL", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.example.com:9200")
    from fastapi.testclient import TestClient as _TC

    from corvus.api.main import app as _app

    body = _TC(_app, raise_server_exceptions=False).get("/api/settings").json()
    by_name = {e["name"]: e for e in body["connections"]}
    assert by_name["reasoning_model"]["address"] == "https://api.meta.ai"
    assert by_name["reasoning_model"]["state"] != "not_configured"


def test_settings_all_local_routing_shares_triage_address(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", sweep_api_db)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("MODEL_PROFILE", "all-local")
    monkeypatch.delenv("META_BASE_URL", raising=False)
    monkeypatch.delenv("ANALYSIS_BASE_URL", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.delenv("ANALYSIS_API_KEY", raising=False)
    monkeypatch.delenv("TRIAGE_BASE_URL", raising=False)
    from fastapi.testclient import TestClient as _TC

    from corvus.api.main import app as _app

    body = _TC(_app, raise_server_exceptions=False).get("/api/settings").json()
    by_name = {e["name"]: e for e in body["connections"]}
    assert by_name["triage_model"]["address"] == "http://127.0.0.1:9"
    assert by_name["reasoning_model"]["address"] == "http://127.0.0.1:9"
