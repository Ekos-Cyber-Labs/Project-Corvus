"""Read-only learned-rules API: list, detail, filters, lineage gaps, safety."""

from __future__ import annotations

import itertools
import json
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from corvus.api.main import app
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def rules_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


SIGMA_MIN = """title: Quiet sudo probe
id: 11111111-2222-4333-8444-555555555555
status: experimental
logsource:
  product: linux
detection:
  sel:
    process.name: sudo
  condition: sel
level: medium
tags:
  - attack.t1059
  - attack.execution
"""


_NATIVE_IDS = itertools.count(100000)


def _seed_source_incident(rules_db: str, key: str = "rule-src-1") -> int:
    with psycopg.connect(rules_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title,"
                " severity_floor, severity_id,"
                " ai_status, verdict, techniques, event_uids, severity_factors,"
                " first_seen, last_seen) VALUES"
                " (%s,%s,4,4,'done','true_positive',%s,%s,%s,"
                " '2026-10-30T00:00:00Z','2026-10-30T01:00:00Z') RETURNING id",
                (
                    key,
                    f"Incident {key}",
                    Jsonb(["T1059"]),
                    Jsonb(["evt-1"]),
                    Jsonb({}),
                ),
            )
            incident_id = int(cur.fetchone()[0])  # type: ignore[index]
        conn.commit()
    return incident_id


def _full_lineage(source_incident: int) -> dict[str, Any]:
    return {
        "sigma_rule_id": "11111111-2222-4333-8444-555555555555",
        "version": 1,
        "supersedes": None,
        "producer": "spark-rule-proposal",
        "producer_version": "rule_proposal/v1",
        "source_incident": source_incident,
        "cited_uids": ["evt-1", "evt-2"],
        "backtest": {
            "codes": ["accepted"],
            "target_matched": ["evt-1", "evt-2"],
            "target_total": 2,
            "baseline_count": 0,
            "group": "corvus_11111111",
            "sigma_sha256": "abc123",
        },
        "rounds_used": 2,
        "model": "muse-spark-1.3",
        "prompt_version": "rule_proposal/v1",
        "ledger_ids": [11, 12],
        "history": [
            {
                "from": None,
                "to": "candidate",
                "approver": None,
                "reason": "stored as candidate",
                "at": "2026-10-30T12:00:00Z",
            },
            {
                "from": "candidate",
                "to": "shadow",
                "approver": "analyst",
                "reason": "backtest clean",
                "at": "2026-10-30T13:00:00Z",
            },
        ],
    }


def _seed_rule(
    rules_db: str,
    *,
    title: str = "Quiet sudo probe",
    status: str = "shadow",
    sigma_text: str = SIGMA_MIN,
    lineage: Any = None,
    incident_id: int | None = None,
    hits: int = 3,
    false_positives: int = 1,
    native_rule_id: int | None = None,
) -> int:
    if lineage is None:
        lineage = {}
    if native_rule_id is None:
        native_rule_id = next(_NATIVE_IDS)
    with psycopg.connect(rules_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rules (title, sigma_text, native_text, native_rule_id,"
                " version, status, lineage, incident_id, hits, false_positives)"
                " VALUES (%s,%s,%s,%s,1,%s,%s,%s,%s,%s) RETURNING id",
                (
                    title,
                    sigma_text,
                    "<group>secret-xml-bundle</group>",
                    native_rule_id,
                    status,
                    Jsonb(lineage),
                    incident_id,
                    hits,
                    false_positives,
                ),
            )
            rule_id = int(cur.fetchone()[0])  # type: ignore[index]
        conn.commit()
    return rule_id


def _seed_firing_incident(rules_db: str, rule_id: int, key: str = "fired-1") -> int:
    incident_id = _seed_source_incident(rules_db, key)
    with psycopg.connect(rules_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET learned_rules = %s WHERE id = %s",
                (
                    Jsonb(
                        [
                            {
                                "rule_db_id": rule_id,
                                "sigma_rule_id": "11111111-2222-4333-8444-555555555555",
                                "version": 1,
                                "mode": "shadow",
                                "lineage_id": "11111111-2222-4333-8444-555555555555",
                                "native_rule_id": 100000,
                                "shadow": True,
                                "unknown": False,
                                "findings": 2,
                            }
                        ]
                    ),
                    incident_id,
                ),
            )
        conn.commit()
    return incident_id


def _client(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", rules_db)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://127.0.0.1:9/v1")
    return TestClient(app, raise_server_exceptions=False)


def test_rules_list_contract(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _seed_source_incident(rules_db)
    shadow = _seed_rule(rules_db, status="shadow", incident_id=src)
    candidate = _seed_rule(
        rules_db, title="Candidate rule", status="candidate", incident_id=None
    )
    body = _client(rules_db, monkeypatch).get("/api/rules").json()
    assert body["total"] == 2
    by_id = {item["id"]: item for item in body["items"]}
    assert set(by_id) == {shadow, candidate}
    item = by_id[shadow]
    assert item["title"] == "Quiet sudo probe"
    assert item["status"] == "shadow"
    assert item["mode"] == "shadow"
    assert item["version"] == 1
    assert item["level"] == "medium"
    assert item["techniques"] == ["T1059"]
    assert item["hits"] == 3
    assert item["false_positives"] == 1
    assert item["source_incident_id"] == src
    assert isinstance(item["created_at"], str) and item["created_at"]
    cand = by_id[candidate]
    assert cand["status"] == "candidate"
    assert cand["mode"] is None
    assert cand["source_incident_id"] is None


def test_rules_list_filters_and_422(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_rule(rules_db, title="S1", status="shadow")
    _seed_rule(rules_db, title="A1", status="active")
    _seed_rule(rules_db, title="C1", status="candidate")
    client = _client(rules_db, monkeypatch)
    assert [
        i["title"] for i in client.get("/api/rules?status=shadow").json()["items"]
    ] == ["S1"]
    assert [
        i["title"] for i in client.get("/api/rules?mode=active").json()["items"]
    ] == ["A1"]
    combo = client.get("/api/rules?status=shadow&mode=shadow").json()
    assert [i["title"] for i in combo["items"]] == ["S1"]
    assert client.get("/api/rules?status=shadow&mode=active").json()["items"] == []
    for url in (
        "/api/rules?status=bogus",
        "/api/rules?status=",
        "/api/rules?status=SHADOW",
        "/api/rules?mode=bogus",
        "/api/rules?mode=",
        "/api/rules?mode=candidate",
        "/api/rules?limit=0",
        "/api/rules?offset=-1",
        "/api/rules?limit=abc",
    ):
        response = client.get(url)
        assert response.status_code == 422, url
        assert response.json() == {"detail": "invalid query parameters"}, url


def test_rules_list_pagination_cap(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for n in range(3):
        _seed_rule(rules_db, title=f"R{n}", status="shadow")
    client = _client(rules_db, monkeypatch)
    body = client.get("/api/rules?limit=500").json()
    assert body["limit"] == 100
    assert body["total"] == 3
    first = client.get("/api/rules?limit=2&offset=0").json()
    second = client.get("/api/rules?limit=2&offset=2").json()
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert first["items"][0]["id"] > first["items"][1]["id"]
    assert second["items"][0]["id"] not in {i["id"] for i in first["items"]}


def test_rule_detail_contract(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _seed_source_incident(rules_db)
    rule_id = _seed_rule(rules_db, lineage=_full_lineage(src), incident_id=src)
    fired = _seed_firing_incident(rules_db, rule_id)
    body = _client(rules_db, monkeypatch).get(f"/api/rules/{rule_id}").json()
    assert body["id"] == rule_id
    assert body["title"] == "Quiet sudo probe"
    assert body["status"] == "shadow"
    assert body["mode"] == "shadow"
    assert "sigma_text" in body and "sudo" in body["sigma_text"]
    assert body["level"] == "medium"
    assert body["techniques"] == ["T1059"]
    assert body["wazuh"]["native_rule_id"] is not None
    assert 100000 <= body["wazuh"]["native_rule_id"] <= 120000
    assert body["wazuh"]["native_rule_ids"] == [body["wazuh"]["native_rule_id"]]
    assert body["wazuh"]["mode"] == "shadow"
    lineage = body["lineage"]
    assert lineage["source_incident"]["id"] == src
    assert lineage["source_incident"]["exists"] is True
    assert lineage["cited_uids"] == ["evt-1", "evt-2"]
    backtest = lineage["backtest"]
    assert backtest["codes"] == ["accepted"]
    assert backtest["target_matched"] == ["evt-1", "evt-2"]
    assert backtest["target_total"] == 2
    assert backtest["baseline_count"] == 0
    assert lineage["rounds_used"] == 2
    assert lineage["model"] == "muse-spark-1.3"
    assert lineage["prompt_version"] == "rule_proposal/v1"
    assert lineage["ledger_ids"] == [11, 12]
    history = body["transitions"]
    assert [h["to"] for h in history] == ["candidate", "shadow"]
    assert history[1]["approver"] == "analyst"
    assert history[1]["reason"] == "backtest clean"
    assert body["hits"] == 3 and body["false_positives"] == 1
    assert [f["incident_id"] for f in body["findings"]] == [fired]
    assert body["findings"][0]["findings"] == 2
    dumped = json.dumps(body)
    assert "secret-xml-bundle" not in dumped
    assert "native_text" not in dumped
    assert "password" not in dumped.lower()


def test_rule_detail_no_lineage(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = _seed_rule(rules_db, lineage={})
    body = _client(rules_db, monkeypatch).get(f"/api/rules/{rule_id}").json()
    assert body["lineage"]["source_incident"] is None
    assert body["lineage"]["cited_uids"] == []
    assert body["lineage"]["backtest"] is None
    assert body["lineage"]["rounds_used"] is None
    assert body["lineage"]["model"] is None
    assert body["lineage"]["prompt_version"] is None
    assert body["lineage"]["ledger_ids"] == []
    assert body["transitions"] == []
    assert body["findings"] == []


def test_rule_detail_broken_lineage_stays_200(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(rules_db, monkeypatch)
    text_id = _seed_rule(rules_db, title="T", lineage="broken")
    numbered = _seed_rule(rules_db, title="N", lineage=42)
    listed = _seed_rule(rules_db, title="L", lineage=["x"])
    for rule_id in (text_id, numbered, listed):
        response = client.get(f"/api/rules/{rule_id}")
        assert response.status_code == 200, rule_id
        body = response.json()
        assert body["lineage"]["source_incident"] is None
        assert body["transitions"] == []
        assert "lineage_note" in body["lineage"]


def test_rule_detail_deleted_incident(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _seed_source_incident(rules_db)
    rule_id = _seed_rule(rules_db, lineage=_full_lineage(src), incident_id=src)
    with psycopg.connect(rules_db) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM incidents WHERE id = %s", (src,))
        conn.commit()
    body = _client(rules_db, monkeypatch).get(f"/api/rules/{rule_id}").json()
    assert body["source_incident_id"] is None
    assert body["lineage"]["source_incident"]["id"] == src
    assert body["lineage"]["source_incident"]["exists"] is False


def test_rules_empty_list(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    body = _client(rules_db, monkeypatch).get("/api/rules").json()
    assert body == {"items": [], "total": 0, "limit": 20, "offset": 0}


def test_rules_unknown_id_and_no_writes(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_rule(rules_db)
    client = _client(rules_db, monkeypatch)
    missing = client.get("/api/rules/999999")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "rule not found"}
    assert "postgresql" not in missing.text.lower()
    assert client.post("/api/rules").status_code == 405
    assert client.put("/api/rules/1").status_code == 405
    assert client.delete("/api/rules/1").status_code == 405
    assert client.get("/api/rules/abc").status_code == 422


def test_rules_headers(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_rule(rules_db)
    response = _client(rules_db, monkeypatch).get("/api/rules")
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_incidents_carry_learned_rule_refs(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _seed_source_incident(rules_db, "lr-src")
    rule_id = _seed_rule(rules_db, incident_id=src)
    fired = _seed_firing_incident(rules_db, rule_id, key="lr-fired")
    client = _client(rules_db, monkeypatch)
    listed = {item["id"]: item for item in client.get("/api/incidents").json()["items"]}
    assert listed[fired]["learned_rules"][0]["rule_db_id"] == rule_id
    assert listed[fired]["learned_rules"][0]["mode"] == "shadow"
    detail = client.get(f"/api/incidents/{fired}").json()
    assert detail["learned_rules"][0]["rule_db_id"] == rule_id
    assert detail["learned_rules"][0]["version"] == 1
    assert listed[src]["learned_rules"] == []
