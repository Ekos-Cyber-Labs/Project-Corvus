"""Egress controls for every model call that leaves the deployment.

Two pieces live here:

- :class:`EgressFilter`: a host allowlist checked by :meth:`check_url`
  before anything is sent. Only the configured model endpoints plus
  ``WAZUH_INDEXER_URL`` may receive cloud traffic (see
  :func:`default_allowed_hosts`); network-level egress stays the
  operator's firewall (``docs/threat-model.md``).
- :func:`redact`: a secret-pattern redactor applied to model-bound
  payloads (tokens, passwords in command lines).

Matching rules (also documented in :meth:`EgressFilter.check_url`):

- Scheme must be ``https``, except on a loopback host (``localhost``,
  ``127.0.0.0/8``, ``::1``), where ``http`` is allowed for on-prem
  endpoints reached over the loopback interface.
- Hosts compare case-insensitively after IDNA/punycode normalization
  and trailing-dot removal.
- Exact host match only. An entry starting with ``*.`` additionally
  matches exactly one extra left label (``*.example.com`` matches
  ``a.example.com`` but not ``example.com`` itself and not
  ``a.b.example.com``).
- The URL port must be 443 unless the allowlist entry names a port
  (``host:port``), in which case the URL must use exactly that port.
- No userinfo (``user@host``), no percent-encoded bytes in the host,
  no empty host, no whitespace or control characters anywhere.
- Redirects are never followed: the transport builds its client with
  ``follow_redirects=False`` (asserted by
  ``tests/test_llm_transport.py::test_redirect_never_followed`` and
  ``tests/test_egress.py::test_redirect_target_never_requested``).
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

__all__ = [
    "EgressBlocked",
    "EgressFilter",
    "default_allowed_hosts",
    "redact",
]

#: Marker inserted for every redacted secret; no redactor pattern
#: matches inside it, so :func:`redact` is a fixpoint (idempotent).
REDACTED_TEMPLATE = "[REDACTED:{kind}]"

_LOOPBACK_NAMES = frozenset({"localhost"})

_ENV_URL_VARS = (
    "TRIAGE_BASE_URL",
    "ANALYSIS_BASE_URL",
    "GLIMMER_BASE_URL",
    "META_BASE_URL",
    "WAZUH_INDEXER_URL",
)


class EgressBlocked(ValueError):
    """A URL failed the egress allowlist; nothing was sent."""


def _normalize_host(host: str) -> str:
    """Lowercase, strip one trailing dot, IDNA-encode to punycode."""
    cleaned = host.strip().lower().rstrip(".")
    try:
        return cleaned.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise EgressBlocked(f"refusing unparseable host {host!r}: {exc}") from None


def _is_loopback(normalized_host: str) -> bool:
    """True for ``localhost`` and loopback IP literals."""
    if normalized_host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(normalized_host).is_loopback
    except ValueError:
        return False


#: Conservative hostname shape after IDNA normalization (ASCII
#: letters, digits, dots, hyphens, underscores; at least one char).
_HOST_PATTERN = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?")


def _parse_entry(entry: str) -> tuple[str, int | None]:
    """Split an allowlist entry into (normalized host, port or None).

    Accepts bare hostnames, ``host:port``, bare IP literals, and
    bracketed IPv6 literals (``[::1]`` with an optional ``:port``).
    Anything else (empty text, a non-numeric or out-of-range port, a
    second colon outside brackets, a malformed hostname) raises
    :class:`ValueError` instead of guessing.
    """
    text = entry.strip()
    if not text:
        raise ValueError("allowlist entries must not be empty")
    if text.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", text)
        if match is None:
            raise ValueError(f"bad allowlist entry {entry!r}")
        try:
            ipaddress.ip_address(match.group(1))
        except ValueError:
            raise ValueError(f"bad IP literal in allowlist entry {entry!r}") from None
        return _normalize_host(match.group(1)), _checked_port(entry, match.group(2))
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return _normalize_host(text), None
    host_part, sep, port_part = text.rpartition(":")
    port: int | None = None
    if sep:
        if text.count(":") > 1:
            raise ValueError(
                f"bad allowlist entry {entry!r} (bracket an IPv6 literal: [::1]:port)"
            )
        port = _checked_port(entry, port_part)
        text = host_part
    normalized = _normalize_host(text)
    if _HOST_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"bad hostname in allowlist entry {entry!r}")
    return normalized, port


def _checked_port(entry: str, raw: str | None) -> int | None:
    """Validate a port suffix; ``None`` stays ``None``."""
    if raw is None:
        return None
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise ValueError(f"bad port in allowlist entry {entry!r}")
    return int(raw)


def default_allowed_hosts() -> list[str]:
    """Build the allowlist from the configured endpoints, nothing else.

    Reads the model base URLs (``TRIAGE_BASE_URL``,
    ``ANALYSIS_BASE_URL``, falling back to ``GLIMMER_BASE_URL`` /
    ``META_BASE_URL``) plus ``WAZUH_INDEXER_URL`` and returns one entry
    per URL host (``host`` or ``host:port`` when the URL names a
    non-default port). Entries for unset variables are skipped; when
    nothing is configured the list is empty and every cloud URL is
    refused (fail closed).
    """
    urls: list[str] = []
    for var in ("TRIAGE_BASE_URL", "ANALYSIS_BASE_URL"):
        value = os.environ.get(var, "").strip()
        if value:
            urls.append(value)
    if not any(os.environ.get(v, "").strip() for v in ("TRIAGE_BASE_URL",)):
        fallback = os.environ.get("GLIMMER_BASE_URL", "").strip()
        if fallback:
            urls.append(fallback)
    if not any(os.environ.get(v, "").strip() for v in ("ANALYSIS_BASE_URL",)):
        fallback = os.environ.get("META_BASE_URL", "").strip()
        if fallback:
            urls.append(fallback)
    wazuh = os.environ.get("WAZUH_INDEXER_URL", "").strip()
    if wazuh:
        urls.append(wazuh)
    entries: list[str] = []
    for url in urls:
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            if not host:
                continue
            normalized = _normalize_host(host)
        except EgressBlocked:
            continue
        try:
            port = parts.port
        except ValueError:
            continue
        default_port = 443 if (parts.scheme or "").lower() == "https" else 80
        if port is not None and port != default_port:
            entries.append(f"{normalized}:{port}")
        else:
            entries.append(normalized)
    return entries


class EgressFilter:
    """Host allowlist; call :meth:`check_url` before sending anything."""

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        entries = list(allowed_hosts)
        if not entries:
            raise ValueError("EgressFilter needs at least one allowed host")
        self._entries: list[tuple[str, int | None, bool]] = []
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"bad allowlist entry {entry!r}")
            text = entry.strip()
            wildcard = text.startswith("*.")
            host, port = _parse_entry(text[2:] if wildcard else text)
            if not host:
                raise ValueError(f"bad allowlist entry {entry!r}")
            self._entries.append((host, port, wildcard))

    def _match_host(self, normalized: str) -> bool:
        for host, _, wildcard in self._entries:
            if wildcard:
                if (
                    normalized.endswith("." + host)
                    and normalized.count(".") == host.count(".") + 1
                ):
                    return True
            elif normalized == host:
                return True
        return False

    def _match_port(self, normalized: str, port: int) -> bool:
        wanted: set[int] = set()
        for host, entry_port, wildcard in self._entries:
            hit = (
                normalized == host
                if not wildcard
                else (
                    normalized.endswith("." + host)
                    and normalized.count(".") == host.count(".") + 1
                )
            )
            if hit:
                wanted.add(entry_port if entry_port is not None else 443)
        return port in wanted

    def check_url(self, url: str) -> None:
        """Raise :class:`EgressBlocked` unless ``url`` may be requested.

        Rules: ``url`` must be a string with no whitespace or control
        characters; the scheme must be ``https`` (``http`` only on a
        loopback host); the host must be non-empty, free of
        percent-encoding and userinfo, and match the allowlist after
        IDNA/trailing-dot normalization (exact match, or exactly one
        extra label under a ``*.`` entry); the port must be 443 unless
        the matching entry names a port. Nothing is sent on failure.
        """
        if not isinstance(url, str) or not url:
            raise EgressBlocked(f"refusing empty or non-string URL {url!r}")
        if re.search(r"[\s\x00-\x1f\x7f]", url):
            raise EgressBlocked("refusing URL with whitespace/control characters")
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise EgressBlocked(f"refusing unparseable URL: {exc}") from None
        scheme = (parts.scheme or "").lower()
        raw_host = parts.hostname or ""
        if not raw_host:
            raise EgressBlocked("refusing URL with an empty host")
        netloc = parts.netloc
        host_label = netloc.rsplit("@", 1)[-1].rsplit(":", 1)[0]
        if "%" in host_label or "%" in raw_host:
            raise EgressBlocked("refusing URL with percent-encoding in the host")
        if "@" in netloc:
            raise EgressBlocked("refusing URL with embedded userinfo")
        normalized = _normalize_host(raw_host)
        if not self._match_host(normalized):
            raise EgressBlocked(f"refusing non-allowlisted host {raw_host!r}")
        loopback = _is_loopback(normalized)
        if scheme == "http":
            if not loopback:
                raise EgressBlocked("refusing non-https URL for a non-loopback host")
        elif scheme != "https":
            raise EgressBlocked(f"refusing non-http(s) scheme {scheme!r}")
        try:
            port = parts.port
        except ValueError:
            raise EgressBlocked("refusing URL with an invalid port") from None
        if port is None:
            port = 80 if scheme == "http" else 443
        if not self._match_port(normalized, port):
            raise EgressBlocked(
                f"refusing port {port} for host {raw_host!r} "
                "(allowlist entry names no such port)"
            )


#: Real bearer tokens are long; the minimum keeps ordinary prose such
#: as "the bearer of bad news" untouched.
_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/=]{8,}", re.IGNORECASE)
_AUTH_HEADER = re.compile(
    r"(?im)^(authorization\s*[:=]\s*|authorization\s+)(?:Bearer|Basic)\s+\S+",
)
#: Cookie and Set-Cookie header values are opaque session secrets.
_COOKIE = re.compile(r"(?im)^((?:Set-)?Cookie\s*:\s*)\S+")
#: ``curl -u user:pass`` / ``curl --user user:pass`` pairs.
_CURL_USER = re.compile(
    r"((?:^|\s)(?:--user|-u)\s+)[^\s:\"']+:[^\s\"']+",
    re.IGNORECASE,
)
#: The literal argument of ``ConvertTo-SecureString`` (quoted or bare,
#: but never a flag).
_SECURE_STRING = re.compile(
    r"(?i)(ConvertTo-SecureString\s+)(?:\"([^\"]*)\"|'([^']*)'|([^\s-][^\s]*))"
)
#: NTLM/RC4/AES hash material after its keyword (32 or 64 hex chars).
_NTLM_HASH = re.compile(
    r"(?i)((?:/)?(?:ntlm|rc4|aes128|aes256|hash):)"
    r"([0-9a-f]{32}(?:[0-9a-f]{32})?)(?![0-9a-f])"
)
#: The trailing password argument of ``net use`` (the last token when
#: it is not a flag).
_NET_USE_TRAILING = re.compile(
    r"(?i)(\bnet\s+use\s+\S+(?:\s+\S+)*?\s+)([^\s/][^\s]*)(?=\s|$)",
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_API_KEY = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|"
    r"xox[bpras]-[A-Za-z0-9-]+|sk-[A-Za-z0-9]{8,}|sk-ant-[A-Za-z0-9-]+)\b"
)
#: Any ``key = value`` pair is examined; :func:`_is_credential_key`
#: decides whether the key names a credential. The optional quote
#: after the key covers the JSON form (``"password": "…"``) as well
#: as the bare form (``password=…``).
_CREDENTIAL_KV = re.compile(
    r"(?i)([A-Za-z][A-Za-z0-9_.-]*)([\"']?)"
    r"(\s*[:=]\s*)(?:\"([^\"]*)\"|'([^']*)'|([^\s,;\"']+))"
)

#: Key segments (split on ``_`` and ``-``, any case) that mark a
#: credential: ``AWS_SECRET_ACCESS_KEY`` hits on ``secret`` where the
#: old ``\bsecret\b`` failed on the underscores.
_KEY_SEGMENTS = frozenset({"secret", "token", "password", "passwd", "pwd"})


def _is_credential_key(key: str) -> bool:
    """True when ``key`` names a credential (segment match)."""
    parts = re.split(r"[_-]+", key.lower())
    if any(part in _KEY_SEGMENTS for part in parts):
        return True
    if "api_key" in key.lower().split("-"):
        return True
    return ("api" in parts and "key" in parts) or "apikey" in parts


_CLI_FLAG = re.compile(
    r"(?P<eq>(?:--password(?:[_-]?[A-Za-z]+)?|--passwd|-p\b)\s*=\s*[^\s\"']+)"
    r"|(?P<sp>(?:--password(?:[_-]?[A-Za-z]+)?|--passwd|--token|--secret)"
    r"\s+[^\s-][^\s]*)"
    r"|(?P<att>(?<![A-Za-z0-9])-p[^\s\"'\d][^\s\"']*)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
_URL_USERINFO = re.compile(r"(?i)\b(https?://)([^/\s@?#]+)@")
_SHORT_FLAG_VALUE = re.compile(r"(?<![A-Za-z0-9])-p\s+(\S+)")


def _redact_kv(match: re.Match[str]) -> str:
    key, quote, sep = match.group(1), match.group(2), match.group(3)
    if not _is_credential_key(key):
        return match.group(0)
    if match.group(4) is not None:
        return f'{key}{quote}{sep}"{REDACTED_TEMPLATE.format(kind="credential")}"'
    if match.group(5) is not None:
        return f"{key}{quote}{sep}'{REDACTED_TEMPLATE.format(kind='credential')}'"
    return f"{key}{quote}{sep}{REDACTED_TEMPLATE.format(kind='credential')}"


def _redact_secret_literal(match: re.Match[str]) -> str:
    """Replace a ``ConvertTo-SecureString`` literal, keeping its quotes."""
    prefix = match.group(1)
    quoted = match.group(2) if match.group(2) is not None else match.group(3)
    marker = REDACTED_TEMPLATE.format(kind="credential")
    if quoted is not None:
        quote = '"' if match.group(2) is not None else "'"
        return f"{prefix}{quote}{marker}{quote}"
    return f"{prefix}{marker}"


def redact(text: str) -> str:
    """Replace tokens and credentials in ``text`` with ``[REDACTED:kind]``.

    Covers bearer tokens (8+ characters, so ordinary prose such as
    "the bearer of bad news" is left alone), ``Authorization``
    headers, JWTs, common cloud key prefixes (``AKIA…``,
    ``ghp_…``/``gho_…``/``ghu_…``/``ghs_…``/``ghr_…``, ``xox…``,
    ``sk-…``), key=value pairs whose key holds ``secret``,
    ``token``, ``password``, ``passwd``, ``pwd`` or ``api_key`` as an
    underscore/dash segment (quoted or bare), ``curl -u`` / ``--user``
    user:password pairs, the trailing password argument of
    ``net use``, the ``ConvertTo-SecureString`` literal, 32/64-hex
    NTLM/RC4/AES hashes, ``Cookie``/``Set-Cookie`` values, ``-p`` /
    ``--password`` style command-line arguments, private key blocks,
    and URLs with embedded userinfo. A
    bare ``-p`` followed by only digits is left alone (it is almost
    always a port, e.g. ``ssh -p 22``). Prose disclosures without a
    key (``my password is hunter2``) are NOT redacted: the pattern set
    covers structured and command-line forms only. Host names and
    e-mail addresses are NOT redacted either (``ssh
    user@host.example.com`` passes through): the entity scanner in
    :mod:`corvus.guardrails.pseudonymizer` is what hides them. The
    markers never match any pattern, so redacting twice changes
    nothing (idempotent). Non-string input raises :class:`TypeError`.
    """
    if not isinstance(text, str):
        raise TypeError(f"redact needs a string, got {type(text).__name__}")
    if not text:
        return text
    redacted = _PRIVATE_KEY.sub(REDACTED_TEMPLATE.format(kind="private_key"), text)
    redacted = _URL_USERINFO.sub(
        r"\1" + REDACTED_TEMPLATE.format(kind="userinfo") + "@", redacted
    )
    redacted = _AUTH_HEADER.sub(
        r"\1" + REDACTED_TEMPLATE.format(kind="authorization"), redacted
    )
    redacted = _COOKIE.sub(r"\1" + REDACTED_TEMPLATE.format(kind="cookie"), redacted)
    redacted = _BEARER.sub(REDACTED_TEMPLATE.format(kind="bearer"), redacted)
    redacted = _JWT.sub(REDACTED_TEMPLATE.format(kind="jwt"), redacted)
    redacted = _API_KEY.sub(REDACTED_TEMPLATE.format(kind="api_key"), redacted)
    redacted = _CURL_USER.sub(
        r"\1" + REDACTED_TEMPLATE.format(kind="credential"), redacted
    )
    redacted = _SECURE_STRING.sub(_redact_secret_literal, redacted)
    redacted = _NTLM_HASH.sub(r"\1" + REDACTED_TEMPLATE.format(kind="hash"), redacted)
    redacted = _CREDENTIAL_KV.sub(_redact_kv, redacted)
    redacted = _NET_USE_TRAILING.sub(
        r"\1" + REDACTED_TEMPLATE.format(kind="credential"), redacted
    )

    def _cli(match: re.Match[str]) -> str:
        marker = REDACTED_TEMPLATE.format(kind="credential")
        eq = match.group("eq")
        if eq is not None:
            return f"{eq.split('=', 1)[0].rstrip()}={marker}"
        sp = match.group("sp")
        if sp is not None:
            return f"{sp.split(None, 1)[0]} {marker}"
        return f"-p{marker}"

    redacted = _CLI_FLAG.sub(_cli, redacted)

    def _short(match: re.Match[str]) -> str:
        value = match.group(1)
        if value.isdigit():
            return match.group(0)
        return "-p " + REDACTED_TEMPLATE.format(kind="credential")

    return _SHORT_FLAG_VALUE.sub(_short, redacted)
