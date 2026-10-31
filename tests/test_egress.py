"""Adversarial tests for the egress filter and the secret redactor.

``check_url`` must refuse every SSRF-shaped URL below before anything
is sent; ``redact`` must catch a corpus of secret-bearing strings
while leaving ordinary text byte-identical, and must be idempotent.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from corvus.guardrails.egress import (
    EgressBlocked,
    EgressFilter,
    default_allowed_hosts,
    redact,
)
from corvus.llm.config import BackendConfig
from corvus.llm.transport import RateLimiter, TransportError, run_attempt

ALLOWED = EgressFilter(["allowed.example.com"])


def test_exact_host_allowed() -> None:
    ALLOWED.check_url("https://allowed.example.com/")
    ALLOWED.check_url("https://allowed.example.com/api/v1/chat/completions")
    ALLOWED.check_url("https://allowed.example.com:443/explicit")


def test_normalized_host_allowed() -> None:
    # Case and a trailing dot compare equal after normalization.
    ALLOWED.check_url("https://ALLOWED.example.com./")


def test_userinfo_at_allowed_host_refused() -> None:
    with pytest.raises(EgressBlocked):
        ALLOWED.check_url("https://user:pass@allowed.example.com/")


@pytest.mark.parametrize(
    "url",
    [
        "https://allowed.example.com@evil.example.net/",
        "https://evil.example.net/?u=allowed.example.com",
        "https://allowed.example.com.evil.example.net/",
        "https://allowed.example.com:8443/",
        "http://allowed.example.com/",
        "https://allowed.example.com%2Eevil.example.net/",
        "https://192.0.2.1/",
        "http://[::1]:8080/x",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https:///path",
        "https://allowed.example.com/\nX-Injected: 1",
        "https://allowed.example.com/\r\nX-Injected: 1",
        "https://allowed.example.com:abc/",
        "",
    ],
)
def test_mandatory_refusals(url: str) -> None:
    with pytest.raises(EgressBlocked):
        ALLOWED.check_url(url)


def test_wrong_types_refused() -> None:
    with pytest.raises(EgressBlocked):
        ALLOWED.check_url(None)  # type: ignore[arg-type]
    with pytest.raises(EgressBlocked):
        ALLOWED.check_url(443)  # type: ignore[arg-type]


def test_wildcard_matches_exactly_one_label() -> None:
    filt = EgressFilter(["*.example.com"])
    filt.check_url("https://a.example.com/")
    with pytest.raises(EgressBlocked):
        filt.check_url("https://example.com/")
    with pytest.raises(EgressBlocked):
        filt.check_url("https://a.b.example.com/")


def test_named_port() -> None:
    filt = EgressFilter(["allowed.example.com:8443"])
    filt.check_url("https://allowed.example.com:8443/")
    with pytest.raises(EgressBlocked):
        filt.check_url("https://allowed.example.com/")


def test_loopback_http_with_named_port() -> None:
    filt = EgressFilter(["127.0.0.1:8080"])
    filt.check_url("http://127.0.0.1:8080/v1/chat/completions")
    with pytest.raises(EgressBlocked):
        filt.check_url("http://127.0.0.1:9090/v1/chat/completions")
    with pytest.raises(EgressBlocked):
        filt.check_url("https://127.0.0.1:9090/v1/chat/completions")


def test_empty_allowlist_refused() -> None:
    with pytest.raises(ValueError):
        EgressFilter([])


def test_bad_entries_rejected() -> None:
    for entry in ["", "   ", "host:99999", "host:abc:def"]:
        with pytest.raises(ValueError):
            EgressFilter([entry])


def test_default_allowlist_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "TRIAGE_BASE_URL",
        "ANALYSIS_BASE_URL",
        "GLIMMER_BASE_URL",
        "META_BASE_URL",
        "WAZUH_INDEXER_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TRIAGE_BASE_URL", "https://glimmer.example.com:8443/v1")
    monkeypatch.setenv("ANALYSIS_BASE_URL", "https://spark.example.com/v1")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.example.com:55000")
    assert default_allowed_hosts() == [
        "glimmer.example.com:8443",
        "spark.example.com",
        "wazuh.example.com:55000",
    ]


def test_default_allowlist_empty_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in (
        "TRIAGE_BASE_URL",
        "ANALYSIS_BASE_URL",
        "GLIMMER_BASE_URL",
        "META_BASE_URL",
        "WAZUH_INDEXER_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    assert default_allowed_hosts() == []


def test_default_allowlist_fallback_bases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset META_BASE_URL still allowlists the settings default host.

    Regression: the backend resolves api.meta.ai from the settings
    default while the env-only allowlist refused it. DATABASE_URL is
    set so the resolved settings (not the ambient environment) decide.
    """
    for var in (
        "TRIAGE_BASE_URL",
        "ANALYSIS_BASE_URL",
        "GLIMMER_BASE_URL",
        "META_BASE_URL",
        "WAZUH_INDEXER_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://glimmer-lan.example.com:8080/v1")
    assert default_allowed_hosts() == [
        "glimmer-lan.example.com:8080",
        "api.meta.ai",
    ]


def test_default_allowlist_override_shadows_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A purpose override shadows the settings default (never both)."""
    for var in (
        "TRIAGE_BASE_URL",
        "ANALYSIS_BASE_URL",
        "GLIMMER_BASE_URL",
        "META_BASE_URL",
        "WAZUH_INDEXER_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANALYSIS_BASE_URL", "https://spark.example.com/v1")
    assert default_allowed_hosts() == ["spark.example.com"]


SAFE_STRINGS = [
    "User bob logged on at 14:03",
    "Process C:\\Windows\\System32\\svchost.exe started",
    "Connection from 192.0.2.10 to 198.51.100.7:443",
    "Scheduled task \\Microsoft\\Windows\\UpdateOrchestrator\\Reboot ran",
    "File C:\\Users\\bob\\Documents\\report.docx modified",
    "Service MSSQLSERVER started successfully",
    "Logon type 2 interactive session for EXAMPLE\\bob",
    "Registry value HKLM\\Software\\Vendor\\Enabled set to 1",
    "PowerShell script block id 42 executed",
    "Module C:\\Windows\\System32\\ntdll.dll loaded by pid 4",
    "GET https://example.com/api/health returned 200",
    "ssh -p 22 bob@example.com",
    "The bearer of bad news arrived",
    "Token Ring network adapter reset",
    "password policy requires 12 characters",
    "The secret ingredient is paprika",
    "GET /api/v1/users?page=2 HTTP/1.1",
    "Authorization pending approval by manager",
    "Paste nothing into the jwt.io debugger today",
    "The AKIA manual is on the shelf",
    "secret santa party",
    "token bucket algorithm",
    "the password policy was updated",
    "ssh user@host.example.com",
]

SECRET_STRINGS = [
    "Authorization: Bearer abcdefghijklmnop123456",
    "Authorization: Basic QWRtaW46czNjcml0dGVzdA==",
    "called with Bearer abcdefghijklmnop123456 header",
    "saw eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c end",
    "key AKIAIOSFODNN7EXAMPLE leaked",
    "token ghp_abcdefghijklmnopqrstu1234567890 in log",
    "slack xoxb-1234-abcdefghijklmnop here",
    "openai sk-abcdefghijklmnopqrstuvwx exposed",
    '"password": "hunter2-hunter"',
    "password=hunter2",
    "secret: s3cret-value",
    "access_token=ya29.abc123DEF456",  # gitleaks:allow
    "deploy --password s3cretPassw0rd now",
    "deploy --password=s3cretPassw0rd now",
    "mysqldump -p s3cretPassw0rd --host db",
    "mysql -ps3cretPassw0rd -h db",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
    "fetch https://admin:s3cret@example.com/api",
    "passwd: old-secret-1",
    "client_secret=abc123XYZ789 in config",  # gitleaks:allow
    "authorization=Basic dXNlcjpwYXNz",
    "curl -u admin:S3cret http://x",  # gitleaks:allow
    "curl --user admin:S3cret http://x",  # gitleaks:allow
    "net use \\\\h\\s /user:corp\\a S3cretPass",
    "set AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Cookie: session=abcdef0123456789abcdef",
    "ConvertTo-SecureString 'S3cretPass' -AsPlainText -Force",
    "mimikatz sekurlsa::pth /user:a /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0",
]


def test_safe_strings_untouched() -> None:
    assert len(SAFE_STRINGS) == 24
    for text in SAFE_STRINGS:
        assert redact(text) == text, text


def test_secret_strings_redacted() -> None:
    assert len(SECRET_STRINGS) == 28
    for text in SECRET_STRINGS:
        assert "[REDACTED:" in redact(text), text


def test_secret_fragments_gone() -> None:
    fragments = [
        "abcdefghijklmnop123456",
        "QWRtaW46czNjcml0dGVzdA==",
        "hunter2-hunter",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstu1234567890",
        "xoxb-1234-abcdefghijklmnop",
        "sk-abcdefghijklmnopqrstuvwx",
        "s3cretPassw0rd",
        "s3cret-value",
        "ya29.abc123DEF456",
        "abc123XYZ789",
        "old-secret-1",
        "admin:s3cret@",
        "dXNlcjpwYXNz",
        "admin:S3cret",
        "S3cretPass",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "abcdef0123456789abcdef",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
    ]
    for text in SECRET_STRINGS:
        redacted = redact(text)
        for fragment in fragments:
            if fragment in text:
                assert fragment not in redacted, (text, fragment)


def test_redact_idempotent() -> None:
    for text in SAFE_STRINGS + SECRET_STRINGS:
        once = redact(text)
        assert redact(once) == once, text


def test_redact_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        redact(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        redact(42)  # type: ignore[arg-type]
    assert redact("") == ""


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _cloud_backend(port: int) -> BackendConfig:
    return BackendConfig(
        purpose="analysis",
        model="muse-spark-1.3",
        base_url=f"https://example.com:{port}/v1",
        trust="cloud",
        concurrency=4,
        requests_per_minute=30,
        max_input_tokens=65536,
        max_output_tokens=6000,
        api_key="TEST-API-KEY-VALUE-7",
    )


def test_cloud_request_blocked_before_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-allowlisted cloud URL raises before any socket opens."""
    for var in (
        "TRIAGE_BASE_URL",
        "ANALYSIS_BASE_URL",
        "GLIMMER_BASE_URL",
        "WAZUH_INDEXER_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("META_BASE_URL", "https://models.example.net/v1")
    with pytest.raises(EgressBlocked):
        run_attempt(
            _cloud_backend(443),
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=64,
            limiter=RateLimiter(100, 100000),
        )


def test_cloud_request_with_allowing_filter_proceeds() -> None:
    """An injected filter for the target lets the attempt reach send."""
    port = _closed_port()
    backend = BackendConfig(
        purpose="analysis",
        model="muse-spark-1.3",
        base_url=f"http://127.0.0.1:{port}/v1",
        trust="cloud",
        concurrency=4,
        requests_per_minute=30,
        max_input_tokens=65536,
        max_output_tokens=6000,
        api_key="TEST-API-KEY-VALUE-7",
    )
    # Connection refused proves the egress check passed: the refusal
    # comes from the send, not from the allowlist.
    with pytest.raises(TransportError):
        run_attempt(
            backend,
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=64,
            limiter=RateLimiter(100, 100000),
            egress_filter=EgressFilter([f"127.0.0.1:{port}"]),
        )


def test_onprem_request_skips_egress() -> None:
    """On-prem trust never consults the allowlist."""
    port = _closed_port()
    backend = BackendConfig(
        purpose="triage",
        model="glimmer",
        base_url=f"http://127.0.0.1:{port}/v1",
        trust="onprem",
        concurrency=16,
        requests_per_minute=120,
        max_input_tokens=32768,
        max_output_tokens=4200,
    )
    with pytest.raises(TransportError):
        run_attempt(
            backend,
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=64,
            limiter=RateLimiter(100, 100000),
        )


class _RedirectState:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.lock = threading.Lock()


def _redirect_server() -> tuple[ThreadingHTTPServer, _RedirectState]:
    state = _RedirectState()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            with state.lock:
                state.paths.append(self.path)
            if self.path == "/v1/chat/completions":
                body = json.dumps({"moved": True}).encode()
                self.send_response(302)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                port = self.server.server_address[1]
                self.send_header("Location", f"http://127.0.0.1:{port}/elsewhere")
                self.end_headers()
                self.wfile.write(body)
            else:
                body = json.dumps({}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


def test_redirect_target_never_requested() -> None:
    """The transport reports a 3xx and never follows the Location."""
    server, state = _redirect_server()
    try:
        backend = BackendConfig(
            purpose="triage",
            model="glimmer",
            base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
            trust="onprem",
            concurrency=16,
            requests_per_minute=120,
            max_input_tokens=32768,
            max_output_tokens=4200,
        )
        attempt = run_attempt(
            backend,
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=64,
            limiter=RateLimiter(100, 100000),
        )
    finally:
        server.shutdown()
        server.server_close()
    assert attempt.http_status == 302
    assert attempt.error is not None
    assert "redirect" in attempt.error.message
    with state.lock:
        assert state.paths == ["/v1/chat/completions"]
