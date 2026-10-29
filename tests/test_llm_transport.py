"""Single-attempt transport: fixture-driven parsing, retries, limiter.

Every recorded file under ``tests/fixtures_llm/`` drives at least one
test here. End-to-end tests run against a local stub HTTP server on
127.0.0.1 (no real network). Tool-call payloads and the generic Spark
success body have no recorded fixture; those tests build synthetic
bodies and are labelled as such.
"""

from __future__ import annotations

import json
import socket
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from corvus.llm.config import BackendConfig
from corvus.llm.transport import (
    EOM_TOKEN,
    EOT_TOKEN,
    MESSAGE_TOKEN,
    START_TOKEN,
    LimiterTimeoutError,
    RateLimiter,
    TransportError,
    clear_header_cache,
    estimate_completion_split,
    get_limiter,
    parse_api_error,
    parse_tool_calls,
    reset_limiters,
    run_attempt,
    split_glimmer_token_ids,
)

FIXTURES = Path(__file__).parent / "fixtures_llm"
TEST_API_KEY = "TEST-API-KEY-VALUE-7"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _detok_map() -> dict[tuple[int, ...], str]:
    recorded = _load("glimmer_detokenize_headers.json")
    return {
        tuple(segment["header_ids"]): segment["detokenize_response"]["prompt"]
        for segment in recorded["segments_headers"]
    }


class _StubState:
    """Scripted chat responses plus recorded-header detokenize answers."""

    def __init__(self) -> None:
        self.chat_scripts: deque[tuple[int, Any, dict[str, str]]] = deque()
        self.detok_map: dict[tuple[int, ...], str] = {}
        self.requests: list[dict[str, Any]] = []
        self.detok_hits = 0
        self.lock = threading.Lock()


def _make_handler(state: _StubState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw) if raw else None
            except ValueError:
                body = None
            with state.lock:
                state.requests.append(
                    {
                        "path": self.path,
                        "body": body,
                        "headers": dict(self.headers),
                    }
                )
                if self.path == "/detokenize":
                    state.detok_hits += 1
                    key: tuple[int, ...] = ()
                    if isinstance(body, dict) and isinstance(body.get("tokens"), list):
                        key = tuple(body["tokens"])
                    text = state.detok_map.get(key)
                    if text is None:
                        status, payload, extra = 404, {"detail": "unknown"}, {}
                    else:
                        status, payload, extra = 200, {"prompt": text}, {}
                else:
                    if state.chat_scripts:
                        status, payload, extra = state.chat_scripts.popleft()
                    else:
                        status, payload, extra = 500, {"error": "no script"}, {}
            encoded = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)

    return Handler


@pytest.fixture
def stub() -> Any:
    state = _StubState()
    state.detok_map = _detok_map()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


@pytest.fixture(autouse=True)
def _clean_transport_state() -> Any:
    clear_header_cache()
    reset_limiters()
    yield
    clear_header_cache()
    reset_limiters()


def _backend(
    port: int,
    *,
    model: str = "glimmer",
    trust: str = "onprem",
    api_key: str | None = None,
) -> BackendConfig:
    return BackendConfig(
        purpose="triage",
        model=model,
        base_url=f"http://127.0.0.1:{port}/v1",
        trust=trust,
        concurrency=16,
        requests_per_minute=120,
        max_input_tokens=32768,
        max_output_tokens=4200,
        api_key=api_key,
    )


def _fresh_limiter() -> RateLimiter:
    return RateLimiter(100, 100000)


def _chat_bodies(state: _StubState) -> list[Any]:
    with state.lock:
        return [
            entry["body"]
            for entry in state.requests
            if entry["path"] == "/v1/chat/completions"
        ]


def _spark_ok_body() -> dict[str, Any]:
    """Synthetic generic success body (no recorded Spark success fixture)."""
    return {
        "id": "chatcmpl-synthetic-1",
        "object": "chat.completion",
        "created": 1793284583,
        "model": "muse-spark-1.3",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "total_tokens": 15,
            "completion_tokens": 5,
            "completion_tokens_details": {"reasoning_tokens": 2},
        },
    }


def test_glimmer_ok_end_to_end(stub: Any) -> None:
    """Recorded ok fixture: exact split, audited reasoning, exact_ids."""
    server, state = stub
    recorded = _load("glimmer_ok_medium.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    attempt = run_attempt(
        _backend(server.server_port),
        recorded["request"]["messages"],
        temperature=recorded["request"]["temperature"],
        max_tokens=recorded["request"]["max_tokens"],
        reasoning_strength="medium",
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    response = recorded["response"]
    choice = response["choices"][0]
    token_ids = choice["token_ids"]
    assert attempt.http_status == 200
    assert attempt.error is None
    assert attempt.finish_reason == "stop"
    assert attempt.content == choice["message"]["content"]
    assert attempt.reasoning == choice["message"]["reasoning"]
    assert attempt.reasoning is not None
    assert attempt.prompt_tokens == 240
    assert attempt.cached_tokens == 0
    # Verified against the fixture: first segment header (2 ids) holds a
    # 267-token reasoning body, second segment header (3 ids) a 88-token
    # answer body, 10 structural tokens of overhead.
    assert (attempt.reasoning_tokens, attempt.answer_tokens) == (267, 88)
    assert attempt.overhead_tokens == 10
    assert attempt.token_source == "exact_ids"
    assert (
        (attempt.reasoning_tokens + attempt.answer_tokens + attempt.overhead_tokens)
        == len(token_ids)
        == response["usage"]["completion_tokens"]
    )
    assert attempt.latency_ms >= 0
    bodies = _chat_bodies(state)
    assert len(bodies) == 1
    assert bodies[0]["return_token_ids"] is True
    assert bodies[0]["model"] == "glimmer"
    first = bodies[0]["messages"][0]
    assert first["role"] == "system"
    assert first["content"].startswith("Reasoning strength: medium\n\n")
    with state.lock:
        assert state.detok_hits == 2


def test_glimmer_truncated_max_tokens(stub: Any) -> None:
    """Recorded truncated fixture: null content, reasoning-only segment."""
    server, state = stub
    recorded = _load("glimmer_truncated_max_tokens.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    attempt = run_attempt(
        _backend(server.server_port),
        recorded["request"]["messages"],
        temperature=recorded["request"]["temperature"],
        max_tokens=recorded["request"]["max_tokens"],
        reasoning_strength="medium",
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    token_ids = recorded["response"]["choices"][0]["token_ids"]
    assert attempt.http_status == 200
    assert attempt.error is None
    assert attempt.finish_reason == "length"
    assert attempt.content is None
    recorded_reasoning = recorded["response"]["choices"][0]["message"]["reasoning"]
    assert attempt.reasoning == recorded_reasoning
    # Single reasoning segment: 64 ids = 2 header + MESSAGE + 61 body.
    assert (attempt.reasoning_tokens, attempt.answer_tokens) == (61, 0)
    assert attempt.overhead_tokens == 3
    assert attempt.token_source == "exact_ids"
    assert (
        (attempt.reasoning_tokens + attempt.answer_tokens + attempt.overhead_tokens)
        == len(token_ids)
        == recorded["response"]["usage"]["completion_tokens"]
    )


def test_glimmer_reasoning_only_segment(stub: Any) -> None:
    """Reasoning-only split with no answer segment.

    Derived in test code from the ok fixture (first segment only);
    uses ``tests/fixtures_llm/glimmer_empty_final.json`` when that
    real recording exists instead.
    """
    server, state = stub
    empty_path = FIXTURES / "glimmer_empty_final.json"
    if empty_path.exists():
        recorded = json.loads(empty_path.read_text(encoding="utf-8"))
        response = recorded["response"]
        token_ids: list[int] = response["choices"][0]["token_ids"]
        messages = recorded["request"]["messages"]
        max_tokens = recorded["request"]["max_tokens"]
        temperature = recorded["request"]["temperature"]
    else:
        recorded = _load("glimmer_ok_medium.json")
        response = dict(recorded["response"])
        full_ids: list[int] = recorded["response"]["choices"][0]["token_ids"]
        first_end = full_ids.index(200007) + 1
        token_ids = full_ids[:first_end]
        assert 200022 not in token_ids  # derived: single segment, no START
        choice = dict(recorded["response"]["choices"][0])
        message = dict(choice["message"])
        message["content"] = None
        message["tool_calls"] = None
        choice["message"] = message
        choice["token_ids"] = token_ids
        choice["finish_reason"] = "length"
        response["choices"] = [choice]
        messages = recorded["request"]["messages"]
        max_tokens = recorded["request"]["max_tokens"]
        temperature = recorded["request"]["temperature"]
    state.chat_scripts.append((200, response, {}))
    attempt = run_attempt(
        _backend(server.server_port),
        messages,
        temperature=temperature,
        max_tokens=max_tokens,
        reasoning_strength="medium",
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    assert attempt.token_source == "exact_ids"
    assert attempt.answer_tokens == 0
    assert attempt.content is None
    assert (
        attempt.reasoning_tokens + attempt.answer_tokens + attempt.overhead_tokens
    ) == len(token_ids)
    if not empty_path.exists():
        # Derived shape: 271 ids = 2 header + MESSAGE + 267 body + EOM.
        assert (attempt.reasoning_tokens, attempt.overhead_tokens) == (267, 4)


def test_glimmer_headers_cached_across_calls(stub: Any) -> None:
    """At most one detokenize per distinct header across calls."""
    server, state = stub
    recorded = _load("glimmer_ok_medium.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    backend = _backend(server.server_port)
    first = run_attempt(
        backend,
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=4200,
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    second = run_attempt(
        backend,
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=4200,
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    assert (first.reasoning_tokens, first.answer_tokens) == (267, 88)
    assert (second.reasoning_tokens, second.answer_tokens) == (267, 88)
    with state.lock:
        assert state.detok_hits == 2


def test_glimmer_detokenize_failure_estimated(stub: Any) -> None:
    """Detokenize failure falls back to usage totals, never silent exact."""
    server, state = stub
    state.detok_map = {}
    recorded = _load("glimmer_ok_medium.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    attempt = run_attempt(
        _backend(server.server_port),
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=4200,
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    assert attempt.token_source == "estimated"
    assert attempt.overhead_tokens == 0
    assert (
        (attempt.reasoning_tokens + attempt.answer_tokens)
        == recorded["response"]["usage"]["completion_tokens"]
        == 365
    )
    assert attempt.reasoning_tokens > 0
    assert attempt.answer_tokens > 0
    # The reasoning text is still returned for audit.
    recorded_reasoning = recorded["response"]["choices"][0]["message"]["reasoning"]
    assert attempt.reasoning == recorded_reasoning


def test_glimmer_missing_token_ids_estimated(stub: Any) -> None:
    """Absent token_ids fall back to the estimated usage split."""
    server, state = stub
    recorded = _load("glimmer_ok_medium.json")
    response = json.loads(json.dumps(recorded["response"]))
    del response["choices"][0]["token_ids"]
    state.chat_scripts.append((recorded["status"], response, {}))
    attempt = run_attempt(
        _backend(server.server_port),
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=4200,
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    assert attempt.token_source == "estimated"
    assert (attempt.reasoning_tokens + attempt.answer_tokens) == response["usage"][
        "completion_tokens"
    ]


def test_spark_error_body_401_no_retry(stub: Any) -> None:
    """Recorded Meta 401 body: typed error, exactly one request."""
    server, state = stub
    recorded = _load("spark_error_invalid_key.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    backend = _backend(
        server.server_port,
        model="muse-spark-1.3",
        trust="cloud",
        api_key=TEST_API_KEY,
    )
    attempt = run_attempt(
        backend,
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=3000,
        limiter=_fresh_limiter(),
    )
    assert attempt.http_status == 401
    assert attempt.error is not None
    assert attempt.error.code == "invalid_api_key"
    assert attempt.error.message == "Unauthorized"
    assert attempt.error.error_type == "authentication_error"
    assert attempt.content is None
    assert (
        attempt.prompt_tokens,
        attempt.reasoning_tokens,
        attempt.answer_tokens,
        attempt.overhead_tokens,
    ) == (0, 0, 0, 0)
    assert len(_chat_bodies(state)) == 1


def test_retry_429_then_ok_with_capped_retry_after(stub: Any) -> None:
    """429 with Retry-After sleeps the capped value plus jitter, then wins."""
    server, state = stub
    error = _load("spark_error_invalid_key.json")["response"]
    state.chat_scripts.append((429, error, {"Retry-After": "2"}))
    state.chat_scripts.append((200, _spark_ok_body(), {}))
    sleeps: list[float] = []
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
        sleep=sleeps.append,
        rng=lambda: 0.5,
    )
    assert attempt.http_status == 200
    assert attempt.error is None
    assert attempt.content == "hello"
    assert sleeps == [2.0 + 0.5 * 0.5]
    assert len(_chat_bodies(state)) == 2


def test_retry_503_exp_backoff(stub: Any) -> None:
    """Two 503s sleep base then doubled base (deterministic jitter)."""
    server, state = stub
    state.chat_scripts.append((503, {"error": "down"}, {}))
    state.chat_scripts.append((503, {"error": "down"}, {}))
    state.chat_scripts.append((200, _spark_ok_body(), {}))
    sleeps: list[float] = []
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
        sleep=sleeps.append,
        rng=lambda: 0.5,
    )
    assert attempt.http_status == 200
    assert sleeps == [0.5, 1.0]
    assert len(_chat_bodies(state)) == 3


def test_retry_exhausted_returns_error(stub: Any) -> None:
    """Retries stop at max_retries and the last error is returned."""
    server, state = stub
    state.chat_scripts.append((503, {"error": "down"}, {}))
    state.chat_scripts.append((503, {"error": "down"}, {}))
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        max_retries=1,
        limiter=_fresh_limiter(),
        sleep=lambda _: None,
        rng=lambda: 0.5,
    )
    assert attempt.http_status == 503
    assert attempt.error is not None
    assert len(_chat_bodies(state)) == 2


def test_no_retry_on_400(stub: Any) -> None:
    """A 400 is returned after exactly one request."""
    server, state = stub
    state.chat_scripts.append((400, {"error": {"message": "bad"}}, {}))
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
        sleep=lambda _: None,
    )
    assert attempt.http_status == 400
    assert attempt.error is not None
    assert attempt.error.message == "bad"
    assert len(_chat_bodies(state)) == 1


def test_redirect_never_followed(stub: Any) -> None:
    """A 3xx becomes an error attempt; the target is never requested."""
    server, state = stub
    other = f"http://127.0.0.1:{server.server_port}/elsewhere"
    state.chat_scripts.append((302, {"moved": True}, {"Location": other}))
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
    )
    assert attempt.http_status == 302
    assert attempt.error is not None
    assert "redirect" in attempt.error.message
    assert len(_chat_bodies(state)) == 1


def test_transport_error_fails_fast_without_secret() -> None:
    """Connection refusal raises at once; the key appears nowhere."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(TransportError) as excinfo:
        run_attempt(
            _backend(port, model="muse-spark-1.3", api_key=TEST_API_KEY),
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=3000,
            max_retries=3,
            limiter=_fresh_limiter(),
        )
    assert TEST_API_KEY not in str(excinfo.value)


def test_secrets_absent_from_errors_and_repr(stub: Any) -> None:
    """API keys never surface in errors, attempts or backend reprs."""
    server, state = stub
    recorded = _load("spark_error_invalid_key.json")
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    backend = _backend(
        server.server_port, model="muse-spark-1.3", trust="cloud", api_key=TEST_API_KEY
    )
    assert TEST_API_KEY not in repr(backend)
    attempt = run_attempt(
        backend,
        recorded["request"]["messages"],
        temperature=0.2,
        max_tokens=3000,
        limiter=_fresh_limiter(),
    )
    assert attempt.error is not None
    assert TEST_API_KEY not in str(attempt.error)
    assert TEST_API_KEY not in repr(attempt)
    with state.lock:
        assert TEST_API_KEY not in json.dumps(state.requests[0]["body"])


def test_spark_usage_split(stub: Any) -> None:
    """Synthetic generic success: usage counts used as reported."""
    server, state = stub
    state.chat_scripts.append((200, _spark_ok_body(), {}))
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
    )
    assert attempt.token_source == "usage"
    assert attempt.prompt_tokens == 10
    # No fixture records a cached-token field, so cached stays 0.
    assert attempt.cached_tokens == 0
    assert (attempt.reasoning_tokens, attempt.answer_tokens) == (2, 3)
    assert attempt.overhead_tokens == 0
    assert attempt.finish_reason == "stop"


def _tool_body(tool_calls: Any) -> dict[str, Any]:
    """Synthetic assistant message carrying tool_calls (no fixture)."""
    body = _spark_ok_body()
    body["choices"][0]["message"] = {
        "role": "assistant",
        "content": None,
        "tool_calls": tool_calls,
    }
    return body


def test_tool_calls_valid_and_malformed(stub: Any) -> None:
    """Synthetic: one good call parses, bad ones become typed errors."""
    server, state = stub
    state.chat_scripts.append(
        (
            200,
            _tool_body(
                [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {
                            "name": "get_events",
                            "arguments": '{"uid": "e1"}',
                        },
                    },
                    {
                        "id": "c2",
                        "type": "function",
                        "function": {"name": "get_events", "arguments": "{bad"},
                    },
                    {
                        "type": "function",
                        "function": {"name": "get_events", "arguments": "{}"},
                    },
                ]
            ),
            {},
        )
    )
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=_fresh_limiter(),
    )
    assert attempt.error is None
    assert len(attempt.tool_calls) == 1
    call = attempt.tool_calls[0]
    assert (call.call_id, call.name) == ("c1", "get_events")
    assert call.arguments == {"uid": "e1"}
    assert call.arguments_raw == '{"uid": "e1"}'
    assert len(attempt.tool_call_errors) == 2
    by_index = {error.index: error for error in attempt.tool_call_errors}
    assert by_index[1].call_id == "c2"
    assert "JSON" in by_index[1].error
    assert by_index[2].call_id is None


def test_tool_calls_wrong_type_is_typed_error() -> None:
    """A non-list tool_calls field never raises out of the parser."""
    calls, errors = parse_tool_calls({"id": "c1"})
    assert calls == ()
    assert len(errors) == 1
    assert errors[0].index == -1


def test_parse_api_error_shapes() -> None:
    """Recorded Meta body parses; unknown shapes degrade gracefully."""
    recorded = _load("spark_error_invalid_key.json")["response"]
    error = parse_api_error(401, recorded)
    assert (error.code, error.message, error.error_type) == (
        "invalid_api_key",
        "Unauthorized",
        "authentication_error",
    )
    generic = parse_api_error(500, {"unexpected": 1})
    assert generic.code is None
    assert generic.message == "HTTP 500"
    assert parse_api_error(502, None).message == "HTTP 502"
    assert parse_api_error(503, "<html>down</html>").message == "HTTP 503"


def test_estimate_completion_split_math() -> None:
    """The estimate is deterministic and always sums to the total."""
    assert estimate_completion_split(0, "reasoning", "answer") == (0, 0)
    assert estimate_completion_split(5, "", "") == (0, 5)
    assert estimate_completion_split(10, "r", "aaa") == (3, 7)
    assert estimate_completion_split(365, None, None) == (0, 365)
    reasoning, answer = estimate_completion_split(365, "r" * 100, "a" * 50)
    assert reasoning + answer == 365
    assert reasoning > answer


def test_split_glimmer_token_ids_exact_and_fallback() -> None:
    """Pure split: exact on known headers, None when one fails to decode."""
    recorded = _load("glimmer_ok_medium.json")
    token_ids: list[int] = recorded["response"]["choices"][0]["token_ids"]
    decoded = _detok_map()
    split = split_glimmer_token_ids(token_ids, decoded.get)
    assert split is not None
    assert split[:3] == (267, 88, 10)
    assert split[3] == "exact_ids"
    assert sum(split[:3]) == len(token_ids)
    assert split_glimmer_token_ids(token_ids, lambda _: None) is None
    with pytest.raises(TransportError):
        split_glimmer_token_ids([1, -2, 3], decoded.get)


def test_glimmer_rejects_tools_and_prefixes_system(stub: Any) -> None:
    """Glimmer takes no tools; strength prefixes (or inserts) system text."""
    server, state = stub
    recorded = _load("glimmer_ok_medium.json")
    backend = _backend(server.server_port)
    with pytest.raises(ValueError, match="no tools"):
        run_attempt(
            backend,
            recorded["request"]["messages"],
            temperature=0.2,
            max_tokens=4200,
            glimmer=True,
            tools=[{"type": "function"}],
            limiter=_fresh_limiter(),
        )
    state.chat_scripts.append((recorded["status"], recorded["response"], {}))
    attempt = run_attempt(
        backend,
        [{"role": "user", "content": "hi"}],
        temperature=0.2,
        max_tokens=4200,
        reasoning_strength="low",
        glimmer=True,
        limiter=_fresh_limiter(),
    )
    assert attempt.token_source == "exact_ids"
    bodies = _chat_bodies(state)
    assert bodies[0]["messages"][0] == {
        "role": "system",
        "content": "Reasoning strength: low\n\n",
    }


def test_response_format_passthrough(stub: Any) -> None:
    """Schema name (undocumented by fixtures) is sent as response_format."""
    server, state = stub
    state.chat_scripts.append((200, _spark_ok_body(), {}))
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        response_schema_name="triage",
        response_schema={"type": "object"},
        limiter=_fresh_limiter(),
    )
    assert attempt.error is None
    bodies = _chat_bodies(state)
    assert bodies[0]["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "triage", "strict": True, "schema": {"type": "object"}},
    }


def test_invalid_inputs_rejected_before_http(stub: Any) -> None:
    """Bad inputs raise ValueError without touching the network."""
    server, state = stub
    backend = _backend(server.server_port)
    good = [{"role": "user", "content": "hi"}]
    cases = [
        {"temperature": float("nan")},
        {"temperature": -0.5},
        {"temperature": True},
        {"max_tokens": 0},
        {"max_tokens": True},
        {"reasoning_strength": "extreme"},
        {"max_retries": -1},
        {"connect_timeout": 0.0},
    ]
    for kwargs in cases:
        params: dict[str, Any] = {
            "temperature": 0.0,
            "max_tokens": 100,
            "limiter": _fresh_limiter(),
        }
        params.update(kwargs)
        with pytest.raises(ValueError):
            run_attempt(backend, good, **params)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        run_attempt(backend, [], temperature=0.0, max_tokens=100)
    with pytest.raises(ValueError):
        run_attempt(
            backend,
            [{"role": "hacker", "content": "hi"}],
            temperature=0.0,
            max_tokens=100,
        )
    with pytest.raises(ValueError):
        run_attempt(
            backend,
            [{"role": "user", "content": None}],  # type: ignore[dict-item]
            temperature=0.0,
            max_tokens=100,
        )
    assert len(_chat_bodies(state)) == 0


def test_malformed_success_body_raises_without_secret(stub: Any) -> None:
    """A 200 that is not a chat completion raises TransportError."""
    server, state = stub
    state.chat_scripts.append((200, {"choices": []}, {}))
    with pytest.raises(TransportError) as excinfo:
        run_attempt(
            _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
            [{"role": "user", "content": "hi"}],
            temperature=0.0,
            max_tokens=100,
            limiter=_fresh_limiter(),
        )
    assert TEST_API_KEY not in str(excinfo.value)


class _FakeClock:
    def __init__(self) -> None:
        self.now_t = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.now_t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now_t += seconds


def test_limiter_rpm_window_with_fake_clock() -> None:
    """Two admissions pass, the third waits exactly one window."""
    fake = _FakeClock()
    limiter = RateLimiter(100, 2, clock=fake.now, sleep=fake.sleep)
    limiter.acquire()
    limiter.acquire()
    assert fake.sleeps == []
    limiter.acquire()
    assert fake.sleeps == [60.0]
    limiter.acquire()
    assert fake.sleeps == [60.0]
    limiter.release()
    limiter.release()
    limiter.release()
    limiter.release()


def test_limiter_concurrency_timeout_with_fake_clock() -> None:
    """A full concurrency slot raises LimiterTimeoutError on deadline."""
    fake = _FakeClock()
    limiter = RateLimiter(1, 1000, clock=fake.now, sleep=fake.sleep)
    limiter.acquire()
    with pytest.raises(LimiterTimeoutError):
        limiter.acquire(timeout=5.0)
    assert fake.now_t >= 5.0
    before = list(fake.sleeps)
    with pytest.raises(LimiterTimeoutError):
        limiter.acquire(timeout=0)
    assert fake.sleeps == before
    limiter.release()
    limiter.acquire(timeout=0)
    limiter.release()
    with pytest.raises(RuntimeError):
        limiter.release()


def test_limiter_thread_handoff() -> None:
    """A blocked acquirer proceeds once the holder releases."""
    limiter = RateLimiter(1, 100000)
    limiter.acquire()
    started = threading.Event()
    acquired = threading.Event()

    def waiter() -> None:
        started.set()
        limiter.acquire(timeout=10)
        try:
            acquired.set()
        finally:
            limiter.release()

    thread = threading.Thread(target=waiter, daemon=True)
    thread.start()
    assert started.wait(timeout=10)
    limiter.release()
    thread.join(timeout=10)
    assert acquired.is_set()


def test_channel_marker_classification_derived() -> None:
    """Derived: channels follow the =self/=user marker, not exact text."""
    token_ids = [
        1,
        MESSAGE_TOKEN,
        5,
        6,
        EOM_TOKEN,
        START_TOKEN,
        2,
        MESSAGE_TOKEN,
        7,
        8,
        EOT_TOKEN,
    ]
    texts = {(1,): "note=self-x", (2,): " to=user"}
    split = split_glimmer_token_ids(token_ids, texts.get)
    assert split is not None
    reasoning, answer, overhead, source = split
    assert source == "exact_ids"
    # " to=user" carries no "assistant" prefix yet counts as answer.
    assert (reasoning, answer) == (2, 2)
    assert overhead == 7
    assert reasoning + answer + overhead == len(token_ids)
    unknown = split_glimmer_token_ids(token_ids, lambda _: "tool chatter")
    assert unknown is not None
    assert unknown[:3] == (0, 0, len(token_ids))


def test_header_cache_keyed_by_root_and_model(stub: Any) -> None:
    """Same header ids on two server roots decode independently."""
    server_a, state_a = stub
    token_ids = [7, 8, MESSAGE_TOKEN, 10, 11, EOT_TOKEN]

    def glimmer_body() -> dict[str, Any]:
        return {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "x",
                        "reasoning": "r",
                    },
                    "finish_reason": "stop",
                    "token_ids": list(token_ids),
                }
            ],
            "usage": {
                "prompt_tokens": 5,
                "total_tokens": 11,
                "completion_tokens": 6,
            },
        }

    state_a.detok_map = {(7, 8): " to=self"}
    state_a.chat_scripts.append((200, glimmer_body(), {}))
    state_b = _StubState()
    state_b.detok_map = {(7, 8): "assistant to=user"}
    state_b.chat_scripts.append((200, glimmer_body(), {}))
    server_b = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state_b))
    thread_b = threading.Thread(target=server_b.serve_forever, daemon=True)
    thread_b.start()
    try:
        attempt_a = run_attempt(
            _backend(server_a.server_port),
            [{"role": "user", "content": "hi"}],
            temperature=0.2,
            max_tokens=4200,
            glimmer=True,
            limiter=_fresh_limiter(),
        )
        attempt_b = run_attempt(
            _backend(server_b.server_port),
            [{"role": "user", "content": "hi"}],
            temperature=0.2,
            max_tokens=4200,
            glimmer=True,
            limiter=_fresh_limiter(),
        )
    finally:
        server_b.shutdown()
        server_b.server_close()
        thread_b.join(timeout=10)
    assert (attempt_a.reasoning_tokens, attempt_a.answer_tokens) == (2, 0)
    assert (attempt_b.reasoning_tokens, attempt_b.answer_tokens) == (0, 2)
    assert attempt_a.token_source == attempt_b.token_source == "exact_ids"
    with state_a.lock:
        assert state_a.detok_hits == 1
    with state_b.lock:
        assert state_b.detok_hits == 1


def test_latency_excludes_limiter_wait(stub: Any) -> None:
    """A 60 s limiter wait (injected clock) leaves latency_ms at 0."""
    server, state = stub
    state.chat_scripts.append((200, _spark_ok_body(), {}))
    fake = _FakeClock()
    limiter = RateLimiter(100, 1, clock=fake.now, sleep=fake.sleep)
    limiter.acquire()
    limiter.release()
    attempt = run_attempt(
        _backend(server.server_port, model="muse-spark-1.3", api_key=TEST_API_KEY),
        [{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=3000,
        limiter=limiter,
        clock=fake.now,
        sleep=fake.sleep,
    )
    assert fake.sleeps == [60.0]
    assert attempt.latency_ms == 0
    assert attempt.error is None


def test_get_limiter_shared_per_backend() -> None:
    """The registry shares one limiter per backend; reset clears it."""
    backend = _backend(1)
    first = get_limiter(backend)
    assert get_limiter(backend) is first
    other = _backend(2)
    assert get_limiter(other) is not first
    reset_limiters()
    assert get_limiter(backend) is not first
