"""One-attempt transport for a single OpenAI-compatible backend call.

:func:`run_attempt` sends one chat-completions request over ``httpx2``
(no OpenAI SDK) and returns an :class:`Attempt` with exact token
accounting. There is no validator and no retry loop here (later
prompts): this module only performs the attempt and records how the
tokens split.

Two response paths exist, chosen by the ``glimmer`` flag:

- Glimmer (on-prem vLLM): the request carries the reasoning-strength
  line in the system message plus ``"return_token_ids": true``. The
  generated ``token_ids`` are split on the START token (200022) into
  ``header, MESSAGE (200023), body, optional end (EOM 200007 / EOT
  200008)`` segments; the decoded header decides the channel by its
  channel marker (contains ``"=self"`` is reasoning, contains
  ``"=user"`` is the answer, anything else is overhead). Headers are
  decoded through ``POST {server_root}/detokenize`` (server root,
  outside ``/v1``; the request body is ``{"tokens": [...]}`` and the
  decoded text lives under the ``"prompt"`` response key) and cached
  per (server root, model, header) process-wide, so one call costs at
  most one detokenize request per distinct header. When
  ``token_ids`` are absent or a header fails to decode, the completion
  total from ``usage`` is split by reasoning/answer text length and
  the source is ``"estimated"`` — never silently exact.
- Spark / generic backends: ``usage`` is used as reported
  (``prompt_tokens``, ``completion_tokens``, ``reasoning_tokens``
  inside ``completion_tokens_details`` when present). No fixture
  records a cached-token field, so ``cached_tokens`` is always 0 on
  this path and the source is ``"usage"``.

Safety: bounded connect/read timeouts, ``follow_redirects=False``
(redirects are reported, never followed), retries only on 429/5xx
with exponential backoff, jitter and a capped ``Retry-After``,
immediate failure on transport errors, one non-streaming request per
try inside a client context manager so every stream is closed.
Secrets (API keys, request bodies) never appear in errors, reprs or
logs — this module does not log at all. Concurrency and
requests-per-minute limits come from the backend config and are
enforced through :class:`RateLimiter`.
"""

from __future__ import annotations

import json
import math
import random
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx2

from corvus.guardrails.egress import EgressFilter, default_allowed_hosts
from corvus.llm.config import BackendConfig

TokenSource = Literal["exact_ids", "usage", "estimated"]

#: vLLM channel framing tokens (recorded ``special_tokens`` fixture).
START_TOKEN = 200022
MESSAGE_TOKEN = 200023
EOM_TOKEN = 200007
EOT_TOKEN = 200008
END_TOKENS = frozenset({EOM_TOKEN, EOT_TOKEN})

#: Channel markers inside a decoded header: ``"=self"`` is reasoning,
#: ``"=user"`` is the answer (both recorded headers carry one).
CHANNEL_REASONING = "=self"
CHANNEL_ANSWER = "=user"

REASONING_STRENGTHS = ("low", "medium", "high")

REQUEST_ROLES = frozenset({"system", "user", "assistant", "tool"})

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 180.0
_WRITE_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5
DEFAULT_BACKOFF_CAP = 8.0
DEFAULT_RETRY_AFTER_CAP = 30.0
DEFAULT_POLL_INTERVAL = 0.05
_RPM_WINDOW_SECONDS = 60.0


class TransportError(RuntimeError):
    """The attempt itself failed (no HTTP answer or an unparsable one)."""


class AttemptTimeoutError(TransportError, TimeoutError):
    """A transport try that timed out waiting for the server.

    Subclasses :class:`TransportError` so existing handlers keep
    working; the extra :class:`TimeoutError` parent lets callers
    classify timeouts by type alone, without storing message text.
    """


class LimiterTimeoutError(TimeoutError):
    """A limiter slot did not free up within the requested timeout."""


@dataclass(frozen=True)
class ToolCall:
    """One assistant tool call with strictly validated transport shape."""

    call_id: str
    name: str
    arguments_raw: str
    arguments: Any


@dataclass(frozen=True)
class ToolCallError:
    """A typed tool-call parse failure; never raised out of transport.

    ``index`` is the position inside ``message.tool_calls``; ``-1``
    means the ``tool_calls`` field itself was not a list.
    """

    index: int
    call_id: str | None
    error: str


@dataclass(frozen=True)
class AttemptError:
    """An API-side failure: the server answered with a non-2xx status."""

    http_status: int
    code: str | None
    message: str
    error_type: str | None


@dataclass(frozen=True)
class Attempt:
    """The outcome of one backend attempt with exact token accounting."""

    http_status: int
    content: str | None
    reasoning: str | None
    finish_reason: str | None
    tool_calls: tuple[ToolCall, ...]
    tool_call_errors: tuple[ToolCallError, ...]
    prompt_tokens: int
    cached_tokens: int
    reasoning_tokens: int
    answer_tokens: int
    overhead_tokens: int
    token_source: TokenSource
    latency_ms: int
    error: AttemptError | None


class RateLimiter:
    """Bounded, thread-safe concurrency + requests-per-minute gate.

    Concurrency is a counter guarded by a lock; the RPM window is a
    bounded deque of recent admission timestamps. Waiting threads
    sleep for computed durations (never spin), so the limiter does
    not busy-wait. ``clock`` and ``sleep`` are injected for
    deterministic tests; ``poll_interval`` bounds the sleep quantum
    while waiting for a concurrency slot to free.
    """

    def __init__(
        self,
        max_concurrent: int,
        requests_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        for name, value in (
            ("max_concurrent", max_concurrent),
            ("requests_per_minute", requests_per_minute),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an int, got {value!r}")
            if value < 1:
                raise ValueError(f"{name} must be >= 1, got {value!r}")
        if not callable(clock) or not callable(sleep):
            raise ValueError("clock and sleep must be callables")
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not poll_interval > 0
        ):
            raise ValueError(
                f"poll_interval must be a number > 0, got {poll_interval!r}"
            )
        self._max_concurrent = max_concurrent
        self._per_minute = requests_per_minute
        self._clock = clock
        self._sleep = sleep
        self._poll = float(poll_interval)
        self._lock = threading.Lock()
        self._active = 0
        self._starts: deque[float] = deque()

    def acquire(self, timeout: float | None = None) -> None:
        """Take one concurrency slot plus one RPM window entry.

        Raises :class:`LimiterTimeoutError` when ``timeout`` (seconds)
        passes without admission; ``None`` waits indefinitely.
        """
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ValueError(f"timeout must be a number or None, got {timeout!r}")
            if timeout < 0:
                raise ValueError(f"timeout must not be negative, got {timeout!r}")
        deadline = None if timeout is None else self._clock() + float(timeout)
        while True:
            now = self._clock()
            with self._lock:
                while self._starts and self._starts[0] <= now - _RPM_WINDOW_SECONDS:
                    self._starts.popleft()
                rpm_full = len(self._starts) >= self._per_minute
                conc_full = self._active >= self._max_concurrent
                if not rpm_full and not conc_full:
                    self._active += 1
                    self._starts.append(now)
                    if len(self._starts) > self._per_minute:
                        self._starts.popleft()
                    return
                if deadline is not None and now >= deadline:
                    raise LimiterTimeoutError(
                        f"no limiter slot within {timeout} seconds "
                        f"(active {self._active}/{self._max_concurrent}, "
                        f"{len(self._starts)}/{self._per_minute} per minute)"
                    )
                if rpm_full:
                    wait = max(
                        self._poll, (self._starts[0] + _RPM_WINDOW_SECONDS) - now
                    )
                else:
                    wait = self._poll
                if deadline is not None:
                    wait = min(wait, max(0.0, deadline - now))
            self._sleep(wait)

    def release(self) -> None:
        """Free one concurrency slot; RPM entries expire on their own."""
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("RateLimiter.release without a matching acquire")
            self._active -= 1

    @contextmanager
    def guarded(self, timeout: float | None = None):
        """Acquire on entry, release on exit (even on error)."""
        self.acquire(timeout)
        try:
            yield None
        finally:
            self.release()


_LIMITERS: dict[tuple[str, str, int, int], RateLimiter] = {}
_LIMITERS_LOCK = threading.Lock()


def get_limiter(
    backend: BackendConfig,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> RateLimiter:
    """Return the shared limiter for a backend (created on first use).

    Keyed by base URL, model and the configured limits. Injected
    ``clock``/``sleep`` apply only when the limiter is created.
    """

    key = (
        backend.base_url,
        backend.model,
        backend.concurrency,
        backend.requests_per_minute,
    )
    with _LIMITERS_LOCK:
        limiter = _LIMITERS.get(key)
        if limiter is None:
            limiter = RateLimiter(
                backend.concurrency,
                backend.requests_per_minute,
                clock=clock,
                sleep=sleep,
            )
            _LIMITERS[key] = limiter
        return limiter


def reset_limiters() -> None:
    """Drop every shared limiter (tests only)."""
    with _LIMITERS_LOCK:
        _LIMITERS.clear()


def parse_api_error(http_status: int, body: Any) -> AttemptError:
    """Parse an API-side error body (recorded Meta shape).

    The recorded shape is ``{"error": {"code", "message", "param",
    "type"}}``; anything else yields ``code``/``error_type`` None and
    a generic ``HTTP <status>`` message. Never raises.
    """
    if isinstance(body, Mapping):
        error = body.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            message = error.get("message")
            error_type = error.get("type")
            return AttemptError(
                http_status=http_status,
                code=code if isinstance(code, str) else None,
                message=message
                if isinstance(message, str) and message
                else f"HTTP {http_status}",
                error_type=error_type if isinstance(error_type, str) else None,
            )
    return AttemptError(
        http_status=http_status,
        code=None,
        message=f"HTTP {http_status}",
        error_type=None,
    )


def parse_tool_calls(
    raw: Any,
) -> tuple[tuple[ToolCall, ...], tuple[ToolCallError, ...]]:
    """Strictly parse ``message.tool_calls``; never raises.

    Malformed entries (wrong shape, missing fields, non-JSON
    ``arguments`` strings) become :class:`ToolCallError` values.
    """
    if raw is None:
        return (), ()
    if not isinstance(raw, list):
        return (), (
            ToolCallError(index=-1, call_id=None, error="tool_calls must be a list"),
        )
    calls: list[ToolCall] = []
    errors: list[ToolCallError] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            errors.append(
                ToolCallError(
                    index=index, call_id=None, error="entry must be an object"
                )
            )
            continue
        raw_id = entry.get("id")
        if not isinstance(raw_id, str) or not raw_id:
            errors.append(
                ToolCallError(index=index, call_id=None, error="id must be a string")
            )
            continue
        call_id = raw_id
        if entry.get("type") != "function":
            errors.append(
                ToolCallError(
                    index=index, call_id=call_id, error="type must be 'function'"
                )
            )
            continue
        function = entry.get("function")
        if not isinstance(function, Mapping):
            errors.append(
                ToolCallError(
                    index=index, call_id=call_id, error="function must be an object"
                )
            )
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name:
            errors.append(
                ToolCallError(
                    index=index, call_id=call_id, error="function.name must be a string"
                )
            )
            continue
        arguments_raw = function.get("arguments")
        if not isinstance(arguments_raw, str):
            errors.append(
                ToolCallError(
                    index=index,
                    call_id=call_id,
                    error="function.arguments must be a JSON string",
                )
            )
            continue
        try:
            arguments = json.loads(arguments_raw)
        except ValueError as exc:
            errors.append(
                ToolCallError(
                    index=index,
                    call_id=call_id,
                    error=f"function.arguments is not valid JSON: {exc}",
                )
            )
            continue
        calls.append(
            ToolCall(
                call_id=call_id,
                name=name,
                arguments_raw=arguments_raw,
                arguments=arguments,
            )
        )
    return tuple(calls), tuple(errors)


def estimate_completion_split(
    completion_tokens: int, reasoning_text: str | None, content_text: str | None
) -> tuple[int, int]:
    """Split a completion total by reasoning/answer text length.

    Deterministic estimate used only when exact token ids are
    unavailable (``token_source`` ``"estimated"``). The reasoning
    share is ``total * len(reasoning) / (len(reasoning) +
    len(answer))`` rounded half up; the answer takes the remainder so
    the two always sum to ``total``. Overhead is 0.
    """
    total = max(0, completion_tokens)
    if total == 0:
        return 0, 0
    reasoning_len = len(reasoning_text or "")
    answer_len = len(content_text or "")
    denom = reasoning_len + answer_len
    if denom == 0:
        return 0, total
    reasoning = int(total * reasoning_len / denom + 0.5)
    reasoning = min(max(reasoning, 0), total)
    return reasoning, total - reasoning


def split_glimmer_token_ids(
    token_ids: Sequence[int],
    decode_header: Callable[[tuple[int, ...]], str | None],
) -> tuple[int, int, int, TokenSource] | None:
    """Split Glimmer ``token_ids`` into (reasoning, answer, overhead).

    Segments are split on START; each segment is ``header, MESSAGE,
    body, optional end token``. The decoded header decides the
    channel by its channel marker: contains ``"=self"`` is reasoning,
    contains ``"=user"`` is the answer, anything else (including a
    segment with no MESSAGE token) is overhead. Structural tokens
    (headers, MESSAGE, START separators, end tokens) count as
    overhead, so the three numbers always sum to ``len(token_ids)``.
    Returns ``None`` when any header fails to decode — the caller
    then falls back to the estimated split.
    """
    for token in token_ids:
        if isinstance(token, bool) or not isinstance(token, int) or token < 0:
            raise TransportError("invalid chat completion: token_ids must be uints")
    ids = list(token_ids)
    segments: list[list[int]] = [[]]
    for token in ids:
        if token == START_TOKEN:
            segments.append([])
        else:
            segments[-1].append(token)
    reasoning = 0
    answer = 0
    overhead = 0
    for segment in segments:
        if not segment:
            continue
        try:
            message_at = segment.index(MESSAGE_TOKEN)
        except ValueError:
            overhead += len(segment)
            continue
        header = tuple(segment[:message_at])
        body = segment[message_at + 1 :]
        end = 0
        if body and body[-1] in END_TOKENS:
            body = body[:-1]
            end = 1
        channel = decode_header(header)
        if channel is None:
            return None
        if CHANNEL_REASONING in channel:
            reasoning += len(body)
        elif CHANNEL_ANSWER in channel:
            answer += len(body)
        else:
            overhead += len(body)
        overhead += len(header) + 1 + end
    overhead += sum(1 for token in ids if token == START_TOKEN)
    return reasoning, answer, overhead, "exact_ids"


_HEADER_CACHE: dict[tuple[str, str, tuple[int, ...]], str] = {}
_HEADER_CACHE_LOCK = threading.Lock()


def clear_header_cache() -> None:
    """Drop every cached header decoding (tests only)."""
    with _HEADER_CACHE_LOCK:
        _HEADER_CACHE.clear()


def _server_root(base_url: str) -> str:
    """Return the server root by stripping one trailing ``/v1`` segment."""
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")].rstrip("/")
    return root


def _auth_headers(api_key: str | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _detokenize(
    client: httpx2.Client,
    server_root: str,
    header_ids: tuple[int, ...],
    api_key: str | None,
) -> str | None:
    """Decode one header through ``POST {server_root}/detokenize``.

    Returns the ``"prompt"`` text, or ``None`` on any failure (HTTP
    error, redirect, transport error, missing/non-string key). The
    request body ``{"tokens": [...]}`` is not covered by a recorded
    fixture; it is the minimal shape this server family documents.
    """
    try:
        response = client.post(
            f"{server_root}/detokenize",
            json={"tokens": list(header_ids)},
            headers=_auth_headers(api_key),
            follow_redirects=False,
        )
    except httpx2.TransportError:
        return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, Mapping):
        return None
    prompt = body.get("prompt")
    return prompt if isinstance(prompt, str) else None


def _safe_host(url: str) -> str:
    return urlsplit(url).hostname or "unknown-host"


def _require_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TransportError(f"invalid chat completion: {field} must be a string")
    return value


def _require_count(value: Any, field: str, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TransportError(f"invalid chat completion: {field} must be a uint")
    return value


def _attempt_from_response(
    http_status: int,
    body: Any,
    *,
    glimmer: bool,
    decode_header: Callable[[tuple[int, ...]], str | None],
    latency_ms: int,
) -> Attempt:
    """Build an :class:`Attempt` from a decoded 2xx response body."""
    if not isinstance(body, Mapping):
        raise TransportError("invalid chat completion: body must be an object")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise TransportError(
            "invalid chat completion: choices must be a non-empty list"
        )
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise TransportError("invalid chat completion: choice must be an object")
    message = choice.get("message")
    if not isinstance(message, Mapping):
        raise TransportError("invalid chat completion: message must be an object")
    content = _require_text(message.get("content"), "message.content")
    reasoning_text = _require_text(message.get("reasoning"), "message.reasoning")
    finish_reason = _require_text(choice.get("finish_reason"), "finish_reason")
    tool_calls, tool_call_errors = parse_tool_calls(message.get("tool_calls"))
    usage = body.get("usage")
    if usage is not None and not isinstance(usage, Mapping):
        raise TransportError("invalid chat completion: usage must be an object")
    usage_map: Mapping[str, Any] = usage if isinstance(usage, Mapping) else {}
    prompt_tokens = _require_count(usage_map.get("prompt_tokens"), "prompt_tokens")
    if glimmer:
        raw_ids = choice.get("token_ids")
        split: tuple[int, int, int, TokenSource] | None = None
        if isinstance(raw_ids, list) and raw_ids:
            split = split_glimmer_token_ids(raw_ids, decode_header)
        if split is None:
            completion = _require_count(
                usage_map.get("completion_tokens"), "completion_tokens"
            )
            estimated_reasoning, estimated_answer = estimate_completion_split(
                completion, reasoning_text, content
            )
            return Attempt(
                http_status=http_status,
                content=content,
                reasoning=reasoning_text,
                finish_reason=finish_reason,
                tool_calls=tool_calls,
                tool_call_errors=tool_call_errors,
                prompt_tokens=prompt_tokens,
                cached_tokens=0,
                reasoning_tokens=estimated_reasoning,
                answer_tokens=estimated_answer,
                overhead_tokens=0,
                token_source="estimated",
                latency_ms=latency_ms,
                error=None,
            )
        reasoning_count, answer_count, overhead_count, _ = split
        return Attempt(
            http_status=http_status,
            content=content,
            reasoning=reasoning_text,
            finish_reason=finish_reason,
            tool_calls=tool_calls,
            tool_call_errors=tool_call_errors,
            prompt_tokens=prompt_tokens,
            cached_tokens=0,
            reasoning_tokens=reasoning_count,
            answer_tokens=answer_count,
            overhead_tokens=overhead_count,
            token_source="exact_ids",
            latency_ms=latency_ms,
            error=None,
        )
    completion_tokens = _require_count(
        usage_map.get("completion_tokens"), "completion_tokens"
    )
    details = usage_map.get("completion_tokens_details")
    reasoning_count = 0
    if isinstance(details, Mapping):
        reasoning_count = _require_count(
            details.get("reasoning_tokens"), "reasoning_tokens"
        )
    answer_count = completion_tokens - reasoning_count
    overhead_count = 0
    if answer_count < 0:
        overhead_count = -answer_count
        answer_count = 0
    return Attempt(
        http_status=http_status,
        content=content,
        reasoning=reasoning_text,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
        tool_call_errors=tool_call_errors,
        prompt_tokens=prompt_tokens,
        cached_tokens=0,
        reasoning_tokens=reasoning_count,
        answer_tokens=answer_count,
        overhead_tokens=overhead_count,
        token_source="usage",
        latency_ms=latency_ms,
        error=None,
    )


def _error_attempt(http_status: int, body: Any, latency_ms: int) -> Attempt:
    """Build an :class:`Attempt` for a non-2xx status (never retried here)."""
    parsed: Any = None
    if isinstance(body, (str, bytes)):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
    else:
        parsed = body
    error = parse_api_error(http_status, parsed)
    return Attempt(
        http_status=http_status,
        content=None,
        reasoning=None,
        finish_reason=None,
        tool_calls=(),
        tool_call_errors=(),
        prompt_tokens=0,
        cached_tokens=0,
        reasoning_tokens=0,
        answer_tokens=0,
        overhead_tokens=0,
        token_source="usage",
        latency_ms=latency_ms,
        error=error,
    )


def run_attempt(
    backend: BackendConfig,
    messages: Sequence[Mapping[str, str]],
    *,
    temperature: float,
    max_tokens: int,
    reasoning_strength: str = "medium",
    response_schema_name: str | None = None,
    response_schema: Mapping[str, Any] | None = None,
    tools: Sequence[Mapping[str, Any]] | None = None,
    glimmer: bool = False,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
    backoff_cap: float = DEFAULT_BACKOFF_CAP,
    retry_after_cap: float = DEFAULT_RETRY_AFTER_CAP,
    limiter: RateLimiter | None = None,
    limiter_timeout: float | None = None,
    egress_filter: EgressFilter | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    rng: Callable[[], float] = random.random,
    header_decoder: Callable[[tuple[int, ...]], str | None] | None = None,
) -> Attempt:
    """Send one chat-completions request and return its :class:`Attempt`.

    ``latency_ms`` covers the HTTP exchanges after the limiter slot is
    acquired (retries and header decoding included), not the limiter
    wait. Backends with cloud trust pass the egress allowlist
    (``EgressFilter.check_url`` over the configured model endpoints
    plus ``WAZUH_INDEXER_URL``) before anything is sent; a refusal
    raises ``EgressBlocked`` with no request made. Retries happen
    only on 429/5xx; any other HTTP status
    (including redirects, which are never followed) returns an
    :class:`Attempt` with ``error`` set. Transport errors and
    unparsable 2xx bodies raise :class:`TransportError` immediately
    with no secret content. No recorded fixture covers
    ``response_schema_name``/``response_schema``; when given, the
    name (plus schema) is sent as an OpenAI ``response_format`` block.
    """
    if not isinstance(messages, Sequence) or not messages:
        raise ValueError("messages must be a non-empty sequence")
    outgoing: list[dict[str, str]] = []
    for position, item in enumerate(messages):
        if not isinstance(item, Mapping):
            raise ValueError(f"messages[{position}] must be a mapping")
        role = item.get("role")
        item_content = item.get("content")
        if role not in REQUEST_ROLES:
            raise ValueError(f"messages[{position}].role must be a known role")
        if not isinstance(item_content, str):
            raise ValueError(f"messages[{position}].content must be a string")
        outgoing.append({"role": role, "content": item_content})
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(temperature)
        or temperature < 0
    ):
        raise ValueError(
            f"temperature must be a finite number >= 0, got {temperature!r}"
        )
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise ValueError(f"max_tokens must be an int, got {max_tokens!r}")
    if max_tokens < 1:
        raise ValueError(f"max_tokens must be >= 1, got {max_tokens!r}")
    if reasoning_strength not in REASONING_STRENGTHS:
        raise ValueError(
            f"reasoning_strength must be one of {REASONING_STRENGTHS}, "
            f"got {reasoning_strength!r}"
        )
    if glimmer and tools:
        raise ValueError("glimmer takes no tools: it makes one structured call")
    if tools is not None and not isinstance(tools, Sequence):
        raise ValueError("tools must be a sequence of mappings or None")
    if isinstance(max_retries, bool) or not isinstance(max_retries, int):
        raise ValueError(f"max_retries must be an int, got {max_retries!r}")
    if max_retries < 0:
        raise ValueError(f"max_retries must be >= 0, got {max_retries!r}")
    for name, value in (
        ("connect_timeout", connect_timeout),
        ("read_timeout", read_timeout),
        ("backoff_base", backoff_base),
        ("backoff_cap", backoff_cap),
        ("retry_after_cap", retry_after_cap),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a number, got {value!r}")
        if value <= 0:
            raise ValueError(f"{name} must be > 0, got {value!r}")
    if not callable(clock) or not callable(sleep) or not callable(rng):
        raise ValueError("clock, sleep and rng must be callables")
    if glimmer:
        prefix = f"Reasoning strength: {reasoning_strength}\n\n"
        if outgoing[0]["role"] == "system":
            outgoing[0] = {
                "role": "system",
                "content": prefix + outgoing[0]["content"],
            }
        else:
            outgoing.insert(0, {"role": "system", "content": prefix})
    body: dict[str, Any] = {
        "model": backend.model,
        "messages": outgoing,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if glimmer:
        body["return_token_ids"] = True
    if tools:
        body["tools"] = [dict(tool) for tool in tools]
    if response_schema_name is not None:
        if not isinstance(response_schema_name, str) or not response_schema_name:
            raise ValueError("response_schema_name must be a non-empty string")
        schema_block: dict[str, Any] = {"name": response_schema_name, "strict": True}
        if response_schema is not None:
            schema_block["schema"] = dict(response_schema)
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": schema_block,
        }
    chat_url = f"{backend.base_url.rstrip('/')}/chat/completions"
    if backend.trust == "cloud":
        # Every cloud request passes the egress allowlist before
        # anything is sent; tests inject a stub-scoped filter here.
        if egress_filter is None:
            active_filter = EgressFilter(default_allowed_hosts())
        else:
            active_filter = egress_filter
        active_filter.check_url(chat_url)
    server_root = _server_root(backend.base_url)
    headers = _auth_headers(backend.api_key)
    active_limiter = (
        limiter
        if limiter is not None
        else get_limiter(backend, clock=clock, sleep=sleep)
    )
    timeout = httpx2.Timeout(
        connect=float(connect_timeout),
        read=float(read_timeout),
        write=_WRITE_TIMEOUT,
        pool=float(connect_timeout),
    )

    def decode_header(header_ids: tuple[int, ...]) -> str | None:
        if header_decoder is not None:
            return header_decoder(header_ids)
        key = (server_root, backend.model, header_ids)
        with _HEADER_CACHE_LOCK:
            cached = _HEADER_CACHE.get(key)
        if cached is not None:
            return cached
        text = _detokenize(client, server_root, header_ids, backend.api_key)
        if text is not None:
            with _HEADER_CACHE_LOCK:
                _HEADER_CACHE.setdefault(key, text)
        return text

    with active_limiter.guarded(limiter_timeout):
        start = clock()

        def elapsed_ms() -> int:
            return int((clock() - start) * 1000)

        with httpx2.Client(timeout=timeout, follow_redirects=False) as client:
            last_status = 0
            for retry in range(max_retries + 1):
                try:
                    response = client.post(
                        chat_url,
                        json=body,
                        headers=headers,
                        follow_redirects=False,
                    )
                except httpx2.TransportError as exc:
                    if isinstance(exc, httpx2.TimeoutException):
                        raise AttemptTimeoutError(
                            f"POST {_safe_host(chat_url)}/chat/completions "
                            f"for model {backend.model!r} failed "
                            f"({type(exc).__name__})"
                        ) from None
                    raise TransportError(
                        f"POST {_safe_host(chat_url)}/chat/completions "
                        f"for model {backend.model!r} failed "
                        f"({type(exc).__name__})"
                    ) from None
                last_status = response.status_code
                raw_text = response.text
                try:
                    parsed_body = json.loads(raw_text) if raw_text else None
                except ValueError:
                    parsed_body = None
                if last_status == 429 or 500 <= last_status <= 599:
                    if retry >= max_retries:
                        return _error_attempt(last_status, parsed_body, elapsed_ms())
                    retry_after = response.headers.get("retry-after")
                    delay: float | None = None
                    if retry_after is not None:
                        try:
                            delay = min(max(0.0, float(retry_after)), retry_after_cap)
                        except ValueError:
                            delay = None
                    if delay is None:
                        backoff = min(backoff_cap, backoff_base * (2**retry))
                        delay = backoff * (0.5 + rng())
                    else:
                        delay = delay + rng() * backoff_base
                    sleep(delay)
                    continue
                if 200 <= last_status <= 299:
                    if parsed_body is None:
                        raise TransportError(
                            f"invalid chat completion from model {backend.model!r}: "
                            "empty or non-JSON 2xx body"
                        )
                    return _attempt_from_response(
                        last_status,
                        parsed_body,
                        glimmer=glimmer,
                        decode_header=decode_header,
                        latency_ms=elapsed_ms(),
                    )
                if 300 <= last_status <= 399:
                    return Attempt(
                        http_status=last_status,
                        content=None,
                        reasoning=None,
                        finish_reason=None,
                        tool_calls=(),
                        tool_call_errors=(),
                        prompt_tokens=0,
                        cached_tokens=0,
                        reasoning_tokens=0,
                        answer_tokens=0,
                        overhead_tokens=0,
                        token_source="usage",
                        latency_ms=elapsed_ms(),
                        error=AttemptError(
                            http_status=last_status,
                            code=None,
                            message=(
                                f"HTTP {last_status} redirect refused "
                                "(redirects are never followed)"
                            ),
                            error_type=None,
                        ),
                    )
                return _error_attempt(last_status, parsed_body, elapsed_ms())
            raise TransportError(  # pragma: no cover - loop always returns
                f"POST {_safe_host(chat_url)}/chat/completions "
                f"for model {backend.model!r} ended without an attempt "
                f"(last status {last_status})"
            )
