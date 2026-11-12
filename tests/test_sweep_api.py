"""Read-only sweep API routes: shape, empty database, and redaction.

Covers ``/api/dashboard``, ``/api/sweep/status`` and ``/api/settings``.
No network and no model calls: the model and Wazuh endpoints point at
closed loopback ports and the security assertions scan every response
for secrets, passwords, userinfo ``@`` in URLs, and env secret values.
"""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from corvus.api.main import app, check_wazuh_indexer
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


def test_dashboard_recent_carries_stored_verdict(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key, verdict in (
        ("rv-tp", "true_positive"),
        ("rv-benign", "benign_authorized"),
        ("rv-fp", "false_positive"),
        ("rv-nh", "needs_human"),
    ):
        _seed_incident(
            sweep_api_db, key, 4, 4, verdict, "done", f"Row {key}", analysed=True
        )
    quar_id = _seed_incident(
        sweep_api_db, "rv-quar", 4, 4, None, "pending", "Row quar", analysed=True
    )
    with psycopg.connect(sweep_api_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incident_analyses SET payload = %s"
                " WHERE incident_id = %s AND stage = 'analysis'",
                (Jsonb({}), quar_id),
            )
            cur.execute(
                "INSERT INTO llm_attempts (call_id, incident_id, model, purpose,"
                " attempt_number, outcome) VALUES"
                " ('c-quar', %s, 'glimmer', 'triage', 1, 'quarantined')",
                (quar_id,),
            )
        conn.commit()
    client = _client(sweep_api_db, monkeypatch)
    recent = client.get("/api/dashboard").json()["recent"]
    assert len(recent) == 5
    by_title = {r["title"]: r for r in recent}
    for key, verdict in (
        ("rv-tp", "true_positive"),
        ("rv-benign", "benign_authorized"),
        ("rv-fp", "false_positive"),
        ("rv-nh", "needs_human"),
    ):
        row = by_title[f"Row {key}"]
        assert row["verdict"] == verdict
        assert row["verdict_kind"] == "verdict"
    quar = by_title["Row quar"]
    assert quar["verdict"] is None
    assert quar["verdict_kind"] == "quarantined"


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


WAZUH_TLS = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl CLI is missing"
)


def _wazuh_openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _wazuh_make_ca(workdir: Path) -> tuple[Path, Path]:
    key = workdir / "check-ca.key"
    crt = workdir / "check-ca.pem"
    _wazuh_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(crt),
        "-days",
        "2",
        "-nodes",
        "-subj",
        "/CN=check-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        cwd=workdir,
    )
    return key, crt


def _wazuh_issue_cert(workdir: Path, ca_key: Path, ca_crt: Path) -> tuple[Path, Path]:
    key = workdir / "check-srv.key"
    csr = workdir / "check-srv.csr"
    crt = workdir / "check-srv.pem"
    ext = workdir / "check-srv.ext"
    ext.write_text("subjectAltName=IP:127.0.0.1\n", encoding="utf-8")
    _wazuh_openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(csr),
        "-nodes",
        "-subj",
        "/CN=srv",
        cwd=workdir,
    )
    _wazuh_openssl(
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        "2",
        "-extfile",
        str(ext),
        cwd=workdir,
    )
    return key, crt


class _RootStatusStub:
    """Minimal TLS stub answering every request with a fixed status."""

    def __init__(self, certfile: str, keyfile: str, status: int) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        self._context = context
        self._status = status
        self.seen_auth = False
        self.seen_requests: list[tuple[str, str]] = []
        self.seen_bodies: list[bytes] = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self._socket.settimeout(0.5)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> _RootStatusStub:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with self._context.wrap_socket(conn, server_side=True) as tls:
                    self._handle(tls)
            except ssl.SSLError, OSError, ValueError:
                pass

    def _handle(self, tls: ssl.SSLSocket) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = tls.recv(4096)
            if not chunk:
                return
            request += chunk
        head, body = request.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        method, target = lines[0].split(" ", 2)[:2]
        length = 0
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length":
                length = int(value.strip())
        while len(body) < length:
            chunk = tls.recv(4096)
            if not chunk:
                break
            body += chunk
        self.seen_auth = self.seen_auth or any(
            line.lower().startswith("authorization:") for line in lines[1:]
        )
        self.seen_requests.append((method, target.split("?", 1)[0]))
        self.seen_bodies.append(body)
        reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden"}.get(
            self._status, "Error"
        )
        raw = b"{}"
        tls.sendall(
            f"HTTP/1.1 {self._status} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode()
            + raw
        )


def _wazuh_stub(tmp_path: Path, status: int) -> tuple[_RootStatusStub, Path]:
    ca_key, ca_crt = _wazuh_make_ca(tmp_path)
    srv_key, srv_crt = _wazuh_issue_cert(tmp_path, ca_key, ca_crt)
    return _RootStatusStub(str(srv_crt), str(srv_key), status).start(), ca_crt


@WAZUH_TLS
def test_wazuh_indexer_probe_reads_with_credentials(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub, ca_crt = _wazuh_stub(tmp_path, 200)
    try:
        client = _client(sweep_api_db, monkeypatch)
        monkeypatch.setenv(
            "WAZUH_INDEXER_URL", f"https://wzxu:wzpz9-secret@127.0.0.1:{stub.port}"
        )
        monkeypatch.setenv("WAZUH_INDEXER_USER", "corvus-reader")
        monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "reader-pw-must-not-leak")
        monkeypatch.setenv("WAZUH_INDEXER_CA", str(ca_crt))
        response = client.get("/api/settings")
        assert response.status_code == 200
        body = response.json()
        entry = {e["name"]: e for e in body["connections"]}["wazuh_indexer"]
        assert entry["state"] == "connected"
        assert entry["address"] == f"https://127.0.0.1:{stub.port}"
        assert stub.seen_auth
        # One zero-hit search on the alerts pattern the sweep reads.
        assert stub.seen_requests == [("POST", "/wazuh-alerts-4.x-*/_search")]
        assert json.loads(stub.seen_bodies[0])["size"] == 0
        for secret in ("wzpz9-secret", "wzxu", "corvus-reader", "reader-pw-must"):
            assert secret not in response.text
    finally:
        stub.stop()


@WAZUH_TLS
@pytest.mark.parametrize("status", [401, 403])
def test_wazuh_indexer_rejected_credentials_are_not_connected(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: int
) -> None:
    stub, ca_crt = _wazuh_stub(tmp_path, status)
    try:
        monkeypatch.setenv("WAZUH_INDEXER_CA", str(ca_crt))
        result = check_wazuh_indexer(
            f"https://127.0.0.1:{stub.port}", "corvus-reader", "wrong-pw"
        )
        assert result == {
            "reachable": True,
            "detail": f"HTTP {status}",
            "auth": "rejected",
        }
        assert stub.seen_auth
        client = _client(sweep_api_db, monkeypatch)
        monkeypatch.setenv("WAZUH_INDEXER_URL", f"https://127.0.0.1:{stub.port}")
        monkeypatch.setenv("WAZUH_INDEXER_USER", "corvus-reader")
        monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "wrong-pw")
        body = client.get("/api/settings").json()
        entry = {e["name"]: e for e in body["connections"]}["wazuh_indexer"]
        assert entry["state"] == "auth_failed"
    finally:
        stub.stop()


@WAZUH_TLS
def test_wazuh_indexer_without_credentials_sends_nothing(
    sweep_api_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub, ca_crt = _wazuh_stub(tmp_path, 200)
    try:
        client = _client(sweep_api_db, monkeypatch)
        monkeypatch.setenv("WAZUH_INDEXER_URL", f"https://127.0.0.1:{stub.port}")
        monkeypatch.setenv("WAZUH_INDEXER_CA", str(ca_crt))
        monkeypatch.delenv("WAZUH_INDEXER_USER", raising=False)
        monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "")
        body = client.get("/api/settings").json()
        entry = {e["name"]: e for e in body["connections"]}["wazuh_indexer"]
        assert entry["state"] == "no_credentials"
        assert stub.seen_requests == []
    finally:
        stub.stop()


@WAZUH_TLS
def test_wazuh_indexer_fails_closed_without_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub, _ca_crt = _wazuh_stub(tmp_path, 200)
    try:
        monkeypatch.delenv("WAZUH_INDEXER_CA", raising=False)
        url = f"https://wzxu:wzpz9-secret@127.0.0.1:{stub.port}"
        result = check_wazuh_indexer(url, "corvus-reader", "reader-pw")
        assert result["reachable"] is False
        assert "auth" not in result
        detail = str(result["detail"])
        assert detail and detail.isidentifier()
        assert "wzpz9-secret" not in detail
        assert "wzxu" not in detail
        assert not stub.seen_auth
    finally:
        stub.stop()


def test_wazuh_indexer_refused_and_missing_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    monkeypatch.delenv("WAZUH_INDEXER_CA", raising=False)
    refused = check_wazuh_indexer(f"https://127.0.0.1:{closed}", "u", "p")
    assert refused["reachable"] is False
    assert str(refused["detail"]) and str(refused["detail"]).isidentifier()
    monkeypatch.setenv("WAZUH_INDEXER_CA", str(tmp_path / "absent-ca.pem"))
    missing = check_wazuh_indexer(f"https://127.0.0.1:{closed}", "u", "p")
    assert missing == {"reachable": False, "detail": "FileNotFoundError"}
    assert check_wazuh_indexer(None)["reachable"] is False
    plain = check_wazuh_indexer(f"http://127.0.0.1:{closed}", "u", "p")
    assert plain == {"reachable": False, "detail": "wazuh_indexer URL must use https"}
    assert check_wazuh_indexer(f"https://127.0.0.1:{closed}") == {
        "reachable": False,
        "detail": "wazuh_indexer credentials are not set",
        "auth": "missing",
    }
