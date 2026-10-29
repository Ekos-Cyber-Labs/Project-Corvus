"""Read-only HTTP client for the Wazuh indexer (OpenSearch REST API).

The Wazuh 4.14 indexer tracks OpenSearch 2.19, so the query DSL here
follows the OpenSearch 2.19 ``paginate`` and ``point in time`` docs:
paging uses ``search_after`` on an explicit ``sort`` whose last key is
unique, and deep reads run inside a point in time (``POST
/<index>/_search/point_in_time?keep_alive=..`` to open, ``"pit"`` in
the ``POST /_search`` body to read, ``DELETE /_search/point_in_time``
to close).

Safety, by construction:

- The client only sends ``search`` (``GET``/``POST`` on
  ``wazuh-alerts-4.x-*`` / ``wazuh-archives-4.x-*`` plus ``_search``),
  point-in-time open, PIT search, and point-in-time delete. Any other
  method or path raises before anything is sent.
- TLS verification is always on: ``verify`` is an ``ssl.SSLContext``
  built from the ``WAZUH_INDEXER_CA`` bundle when set (else the
  platform trust store). A stock Wazuh CA carries no Key Usage
  extension, which Python 3.14 rejects by default
  (``ssl.VERIFY_X509_STRICT``); the context clears only that flag, so
  chain and hostname verification stay on. There is no flag to
  disable verification, and only ``https`` URLs are accepted.
- Credentials travel as HTTP basic auth and never appear in errors,
  reprs, or logs (this module does not log at all).
- Retries happen on HTTP 429 and 5xx only, bounded
  (``max_retries``), with exponential backoff, jitter, and a capped
  ``Retry-After`` honor on 429. Other 4xx and transport errors fail
  fast. Every response body is closed after reading.
"""

from __future__ import annotations

import random
import re
import ssl
import time
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import urlparse

import httpx2

__all__ = ["IndexerError", "ReadOnlyIndexerClient"]

#: Strict allowlist for the index segment of a request path. Only the
#: alerts and archives patterns match; commas, percent-escapes, plus
#: signs and other index names (``wazuh-states-*``, ...) are refused
#: before anything is sent.
_INDEX_RE = re.compile(r"wazuh-(alerts|archives)-4\.x-[A-Za-z0-9._*-]*\Z")

#: PIT search endpoint (OpenSearch 2.19 point-in-time API).
_PIT_SEARCH_PATH = "_search"

#: PIT delete endpoint (OpenSearch 2.19 point-in-time API).
_PIT_DELETE_PATH = "_search/point_in_time"

#: Largest ``Retry-After`` wait honored on 429 (seconds).
_MAX_RETRY_AFTER_S = 30.0

#: Cap for one backoff sleep (seconds).
_MAX_BACKOFF_S = 30.0


def _tls_context(ca_path: str) -> ssl.SSLContext:
    """Build the verifying TLS context for a Wazuh CA bundle.

    Chain building and hostname checks stay exactly as
    :func:`ssl.create_default_context` configures them; only
    ``ssl.VERIFY_X509_STRICT`` is cleared, because a stock Wazuh root
    CA carries no Key Usage extension and Python 3.14 rejects such
    chains by default.
    """
    context = ssl.create_default_context(cafile=ca_path)
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


class IndexerError(Exception):
    """A failed indexer call (HTTP status or transport failure).

    Messages name only the operation, the index pattern or endpoint
    kind, and the HTTP status: never credentials, never request bodies
    (they can carry entity values), never response bodies.
    """


#: Read operations the client may perform (anything else is refused).
_Operation = Literal["search", "pit_search", "pit_create", "pit_delete"]


class ReadOnlyIndexerClient:
    """Minimal read-only client over the Wazuh indexer REST API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        ca_path: str | None = None,
        timeout: httpx2.Timeout | None = None,
        max_retries: int = 3,
        backoff_base_s: float = 0.2,
        sleeper: Callable[[float], None] = time.sleep,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        """Build the client; TLS is always verified.

        ``base_url`` must be ``https``; ``ca_path`` (when set) must be
        an existing file, else ``FileNotFoundError``. ``max_retries``
        bounds the 429/5xx retries after the first attempt.
        """
        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            raise ValueError(
                f"wazuh indexer URL must use https, got {parsed.scheme or '(none)'}"
            )
        if not parsed.hostname:
            raise ValueError("wazuh indexer URL has no host")
        if max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {max_retries}")
        verify: ssl.SSLContext | bool = True
        if ca_path is not None:
            from pathlib import Path

            if not Path(ca_path).is_file():
                raise FileNotFoundError(f"wazuh indexer CA bundle not found: {ca_path}")
            verify = _tls_context(ca_path)
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._sleeper = sleeper
        self._client = httpx2.Client(
            base_url=self._base_url,
            auth=(username, password),
            verify=verify,
            timeout=(
                timeout or httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
            ),
            transport=transport,
        )

    def __repr__(self) -> str:
        return (
            f"ReadOnlyIndexerClient(base_url={self._base_url!r}, "
            f"username={self._username!r}, password='***')"
        )

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def __enter__(self) -> ReadOnlyIndexerClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _check(self, method: str, path: str, operation: _Operation) -> str:
        """Allowlist one outgoing request; return its index pattern.

        Returns ``""`` for the index-less PIT search/delete endpoints.
        Raises ``ValueError`` before anything is sent otherwise.
        """
        clean = path.lstrip("/")
        if operation in ("search", "pit_create"):
            parts = clean.split("/")
            if operation == "search":
                tail = ["_search"]
            else:
                tail = ["_search", "point_in_time"]
            if (
                len(parts) == len(tail) + 1
                and method in ("GET", "POST")
                and parts[1:] == tail
                and _INDEX_RE.match(parts[0])
            ):
                return parts[0]
        elif operation == "pit_search":
            if clean == _PIT_SEARCH_PATH and method in ("GET", "POST"):
                return ""
        elif operation == "pit_delete":
            if clean == _PIT_DELETE_PATH and method == "DELETE":
                return ""
        raise ValueError(
            f"refusing {method} {clean or '/'}: not a read-only indexer endpoint"
        )

    def _send(
        self,
        method: str,
        path: str,
        *,
        operation: _Operation,
        label: str,
        body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send one allowlisted request with bounded 429/5xx retries."""
        target = self._check(method, path, operation)
        attempts = self._max_retries + 1
        last_status: int | None = None
        for attempt in range(attempts):
            try:
                if method in ("GET", "POST", "DELETE"):
                    response = self._client.request(
                        method, path, params=params, json=body
                    )
                else:
                    raise ValueError(
                        f"refusing {method} {path}: not a read-only indexer endpoint"
                    )
            except httpx2.TransportError as exc:
                raise IndexerError(
                    f"wazuh indexer {label} failed on {target or 'point in time'}: "
                    f"transport error ({type(exc).__name__})"
                ) from None
            try:
                status = response.status_code
                if status == 429 or 500 <= status < 600:
                    last_status = status
                    if attempt < attempts - 1:
                        self._sleeper(self._backoff_s(status, response, attempt))
                        continue
                    raise IndexerError(
                        f"wazuh indexer {label} failed on "
                        f"{target or 'point in time'}: HTTP {status} "
                        f"(retry limit reached)"
                    )
                if status >= 400:
                    raise IndexerError(
                        f"wazuh indexer {label} failed on "
                        f"{target or 'point in time'}: HTTP {status}"
                    )
                parsed = response.json()
            except IndexerError:
                raise
            except Exception as exc:
                raise IndexerError(
                    f"wazuh indexer {label} failed on "
                    f"{target or 'point in time'}: unreadable response "
                    f"({type(exc).__name__})"
                ) from None
            finally:
                response.close()
            if not isinstance(parsed, dict):
                raise IndexerError(
                    f"wazuh indexer {label} failed on "
                    f"{target or 'point in time'}: unexpected response shape"
                )
            return parsed
        raise IndexerError(
            f"wazuh indexer {label} failed on {target or 'point in time'}: "
            f"HTTP {last_status} (retry limit reached)"
        )

    def _backoff_s(self, status: int, response: httpx2.Response, attempt: int) -> float:
        """Return the sleep before the next retry (jittered, capped)."""
        if status == 429:
            retry_after = response.headers.get("retry-after")
            if retry_after is not None and retry_after.strip().isdigit():
                return min(float(retry_after.strip()), _MAX_RETRY_AFTER_S)
        return float(
            min(
                self._backoff_base_s * (2**attempt)
                + random.uniform(0, self._backoff_base_s),
                _MAX_BACKOFF_S,
            )
        )

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        """Run one ``_search`` body against an allowlisted index."""
        return self._send(
            "POST", f"/{index}/_search", operation="search", label="search", body=body
        )

    def create_pit(self, index: str, keep_alive: str = "1m") -> str:
        """Open a point in time; return its id (2.19 PIT API)."""
        parsed = self._send(
            "POST",
            f"/{index}/_search/point_in_time",
            operation="pit_create",
            label="point-in-time open",
            params={"keep_alive": keep_alive},
        )
        pit_id = parsed.get("pit_id")
        if not isinstance(pit_id, str) or not pit_id:
            raise IndexerError(
                "wazuh indexer point-in-time open failed: missing pit_id"
            )
        return pit_id

    def search_pit(self, pit_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Run one ``_search`` body against an open point in time."""
        payload = {**body, "pit": {"id": pit_id, "keep_alive": "1m"}}
        return self._send(
            "POST",
            f"/{_PIT_SEARCH_PATH}",
            operation="pit_search",
            label="point-in-time search",
            body=payload,
        )

    def delete_pit(self, pit_id: str) -> None:
        """Close a point in time (best effort; never raises secrets)."""
        try:
            self._send(
                "DELETE",
                f"/{_PIT_DELETE_PATH}",
                operation="pit_delete",
                label="point-in-time close",
                body={"pit_id": [pit_id]},
            )
        except IndexerError, ValueError:
            pass
