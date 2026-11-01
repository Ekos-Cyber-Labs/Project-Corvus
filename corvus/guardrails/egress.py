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
from typing import Any
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


def _resolved_settings() -> Any | None:
    """Return the resolved settings, or None when nothing resolves.

    ``None`` (missing required variables such as ``DATABASE_URL`` or
    ``GLIMMER_BASE_URL``) means the backends cannot resolve either,
    so the allowlist stays empty for the resolved side (fail closed).
    """
    try:
        from corvus.settings import get_settings

        return get_settings()
    except Exception:
        return None


def default_allowed_hosts() -> list[str]:
    """Build the allowlist from the configured endpoints, nothing else.

    Purpose overrides (``TRIAGE_BASE_URL`` / ``ANALYSIS_BASE_URL``)
    come first, exactly as the backends prefer them; the fallbacks
    come from the same resolved settings the backends use
    (``Settings``, so the ``META_BASE_URL`` default counts when the
    variable is unset), then ``WAZUH_INDEXER_URL``. An override
    shadows its fallback default. Returns one entry per URL host
    (``host`` or ``host:port`` when the URL names a non-default
    port). When nothing resolves the list is empty and every cloud
    URL is refused (fail closed).
    """
    urls: list[str] = []
    for var in ("TRIAGE_BASE_URL", "ANALYSIS_BASE_URL"):
        value = os.environ.get(var, "").strip()
        if value:
            urls.append(value)
    settings = _resolved_settings()
    if settings is not None:
        if not any(os.environ.get(v, "").strip() for v in ("TRIAGE_BASE_URL",)):
            urls.append(settings.glimmer_base_url)
        if not any(os.environ.get(v, "").strip() for v in ("ANALYSIS_BASE_URL",)):
            urls.append(settings.meta_base_url)
        if settings.wazuh_indexer_url:
            urls.append(settings.wazuh_indexer_url)
    else:
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
#: ``curl -u user:pass`` / ``curl --user user:pass`` pairs. The user
#: part excludes ``%`` so an already-redacted ``smbclient -U
#: user%[REDACTED:credential]`` pair (whose marker holds a colon) is
#: not eaten on a second pass (idempotency); curl user names with a
#: literal ``%`` are vanishingly rare.
_CURL_USER = re.compile(
    r"((?:^|\s)(?:--user|-u)\s+)[^\s:%\"']+:[^\s\"']+",
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
#: ``net user <name> <password>``: the token after the account name,
#: unless it is a flag, ``*`` (prompt for the password) or ``help``.
_NET_USER_CMD = re.compile(
    r"(?i)(?P<head>\bnet\s+user\b\s+(?:\"[^\"]+\"|[^\s/\"']+))"
    r"(?P<gap>\s+)(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
)

#: ``net use``: handled by :func:`_redact_net_use`, which classifies each
#: token (flags, ``\\\\share`` paths and ``X:`` drives are never secrets)
#: instead of blindly taking the last token. Quoted tokens (a share
#: holding a space, a quoted password) stay one token.
_NET_USE_CMD = re.compile(
    r"(?i)(?P<head>\bnet\s+use\b)"
    r"(?P<tail>(?:\s+(?:\"[^\"]*\"|'[^']*'|[^\s|;&]+))*)"
)

#: Tail splitter mirroring :data:`_NET_USE_CMD`: whitespace separators
#: plus quoted or bare tokens, so ``"\\\\srv\\sh are"`` classifies as
#: one share instead of two secrets.
_NET_USE_TOKEN = re.compile(r"\s+|\"[^\"]*\"|'[^']*'|[^\s|;&]+")


def _strip_quotes(token: str) -> str:
    """Remove one pair of surrounding single or double quotes."""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


#: Drive-letter device (``Z:``): never a password.
_NET_USE_DRIVE = re.compile(r"^[A-Za-z]:$")

#: ``schtasks ... /RP <password>`` (the run-as password; ``/RU`` names
#: the user and is never touched).
_SCHTASKS_RP = re.compile(
    r"(?i)(?<![\w])(?P<flag>/RP\s+)(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
)

#: ``sqlcmd ... -P <password>`` (space, ``=`` or glued): scoped to the
#: sqlcmd command segment so ``scp -P <port>`` and ``wget -P <dir>``
#: stay untouched. Case-sensitive: the flag is uppercase ``-P`` and the
#: replacement keeps the original flag text.
_SQLCMD_CMD = re.compile(r"(?i)\bsqlcmd\b[^\n;|&]*")
_SQLCMD_P = re.compile(
    r"(?P<flag>(?<![\w-])-P(?:\s*=\s*|\s+)?)"
    r"(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)"
)

#: ``ldapsearch ... -w <password>`` (space, ``=`` or glued) and
#: ``--bindpw <password>`` / ``--bindpw=<password>``: scoped to the
#: ldapsearch command segment so ``curl -w <format>`` stays untouched.
#: Case-sensitive: uppercase ``-W`` prompts for the password and takes
#: no value, so it never matches.
_LDAPSEARCH_CMD = re.compile(r"(?i)\bldapsearch\b[^\n;|&]*")
_LDAPSEARCH_W = re.compile(
    r"(?P<flag>(?<![\w-])(?:-w|--bindpw)(?:\s*=\s*|\s+)?)"
    r"(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)"
)

#: ``xfreerdp ... /p:<password>`` (``/pth:`` is a different flag and is
#: never matched: the colon must follow ``/p`` directly).
_XFREERDP_P = re.compile(
    r"(?i)(?<![\w/])(?P<flag>/p:)(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
)

#: ``smbclient ... -U <user>%<password>``: the ``%`` is what makes this
#: the password form, so a bare ``-U <user>`` never matches.
_SMBCLIENT_U = re.compile(
    r"(?i)(?<![\w-])(?P<flag>(?:-U|--user(?:name)?)(?:\s+|=))"
    r"(?P<user>[^\s%\"'=]+)%(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
)

#: ``echo '<user>:<password>' | chpasswd`` (quoted or bare): only text
#: piped into ``chpasswd`` counts.
_CHPASSWD = re.compile(
    r"(?i)\becho\s+(?P<q>['\"]?)(?P<user>[\w.+-]+):(?P<pw>[^\s\"'|]+)(?P=q)"
    r"(?=\s*\|\s*chpasswd\b)",
)

#: ``openssl ... -passin pass:<password>`` (and ``-passout``): the
#: ``pass:`` prefix is what makes this the password form, so
#: ``-passin file:...`` never matches.
_OPENSSL_PASS = re.compile(
    r"(?i)(?P<flag>(?<![\w-])-(?:passin|passout)\s+pass:)"
    r"(?P<pw>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
)

#: Bare NTLM ``LM:NT`` hash pairs (32 hex, colon, 32 hex).
_NTLM_PAIR = re.compile(r"(?i)\b[0-9a-f]{32}:[0-9a-f]{32}\b")
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
    # PowerShell ``-Password`` / ``-Pass`` / ``-Pwd`` (space, ``:`` or
    # ``=`` separated, quoted or bare): the value after the flag is the
    # secret and the flag name is kept. First so the generic ``-p``
    # attached rule below cannot eat the flag name. ``-passin`` /
    # ``-passout`` never match (``\b`` fails inside the longer word;
    # the openssl pattern owns them anyway, see redact() order), and
    # ``--password`` never matches (the leading ``(?<![\w-])-`` takes
    # exactly one dash).
    r"(?P<ps>(?P<flag>(?<![\w-])-(?:password|passwd|pass|pwd)\b\s*[:=]?\s*)"
    r'(?P<pw>"[^"]*"|\'[^\']*\'|[^\s"\']+))'
    r"|(?P<eq>(?:--password(?:[_-]?[A-Za-z]+)?|--passwd|-p\b)\s*=\s*[^\s\"']+)"
    r"|(?P<sp>(?:--password(?:[_-]?[A-Za-z]+)?|--passwd|--token|--secret)"
    r"\s+[^\s-][^\s]*)"
    # ``-passin``/``-passout`` are openssl flags, not ``-p`` with an
    # attached value: the openssl pattern owns them (see redact() order).
    # The value never starts with ``[``: earlier stages emit their
    # markers glued to the flag (``-P[REDACTED:credential]``,
    # ``-Password[REDACTED:credential]``) and this rule must not eat
    # them on the same pass (which also lowercased ``-P`` to ``-p``).
    r"|(?P<att>(?<![A-Za-z0-9])-p(?!assin\b|assout\b)[^\s\"'\d\[][^\s\"']*)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
#: Any ``scheme://`` URL (RFC 3986: ALPHA *( ALPHA / DIGIT / "+" /
#: "-" / "." )) carrying userinfo (``user:password@`` or bare
#: ``user@``). Database, directory, file-transfer, cache, queue and
#: SMB URLs embed credentials this way (``mongodb+srv://``,
#: ``amqps://``, ``ldaps://``, ``rediss://``, ``postgres://``,
#: ``mysql+pymysql://`` ...), so the scheme matches generically
#: instead of a fixed list. A URL without userinfo never matches: an
#: ``@`` past the scheme is required.
_URL_SCHEME = re.compile(r"(?i)\b([A-Za-z][A-Za-z0-9+.\-]*://)([^\s\x00-\x1f\x7f]*)")

#: User names that can be kept verbatim next to the marker: no
#: slashes, whitespace, ``@``, ``?``, ``#`` or ``:`` of their own.
_URL_USER = re.compile(r"[^/\s@?#:]+")


def _redact_url_userinfo(match: re.Match[str]) -> str:
    """Redact URL userinfo, keeping a separable user name and the host.

    Userinfo ends at the LAST ``@`` in the authority run (a password
    may itself hold ``@``); candidates are tried last-first so an ``@``
    inside the path (``https://example.com/a@b``) does not match: a
    userinfo holding ``/`` without a ``:`` is a path, not credentials.
    ``#``, ``?`` and ``/`` inside the password stay inside the
    redaction. With a separable ``user:`` prefix the output keeps the
    user (``scheme://user:[REDACTED:credential]@host``); otherwise the
    whole userinfo goes (``scheme://[REDACTED:userinfo]@host``, as
    before). Text already holding a marker is left alone (idempotency).
    """
    scheme, rest = match.group(1), match.group(2)
    if "[REDACTED:" in rest:
        return match.group(0)
    credential = REDACTED_TEMPLATE.format(kind="credential")
    whole = REDACTED_TEMPLATE.format(kind="userinfo")
    for at in [m.start() for m in re.finditer(r"@", rest)][::-1]:
        userinfo, after = rest[:at], rest[at + 1 :]
        if not userinfo or not after:
            continue
        if ":" in userinfo:
            user, _, _ = userinfo.partition(":")
            if user and _URL_USER.fullmatch(user) is not None:
                return f"{scheme}{user}:{credential}@{after}"
            return f"{scheme}{whole}@{after}"
        if "/" in userinfo or "@" in userinfo:
            continue
        return f"{scheme}{whole}@{after}"
    return match.group(0)


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


def _mask_value(prefix: str, value: str) -> str:
    """Replace ``value`` with the marker, keeping surrounding quotes."""
    marker = REDACTED_TEMPLATE.format(kind="credential")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return f"{prefix}{value[0]}{marker}{value[0]}"
    return f"{prefix}{marker}"


def _redact_password_token(match: re.Match[str]) -> str:
    """Replace a ``net user`` password unless the token is not one."""
    head, gap, password = match.group("head"), match.group("gap"), match.group("pw")
    if password.startswith("/") or password.startswith("-") or password == "*":
        return match.group(0)
    if password.strip("'\"").lower() in ("help", "/?"):
        return match.group(0)
    return f"{head}{gap}{_mask_value('', password)}"


def _redact_net_use(match: re.Match[str]) -> str:
    """Replace ``net use`` password tokens, keeping targets and flags."""
    head, tail = match.group("head"), match.group("tail")
    parts = _NET_USE_TOKEN.findall(tail)
    tokens = [part for part in parts if not part[0].isspace()]
    bare = [_strip_quotes(token) for token in tokens]
    has_target = any(
        token.startswith("\\")
        or _NET_USE_DRIVE.fullmatch(token) is not None
        or token[:6].lower() == "/user:"
        for token in bare
    )
    if not has_target:
        return match.group(0)
    rebuilt: list[str] = []
    for part in parts:
        if part[0].isspace():
            rebuilt.append(part)
            continue
        token = _strip_quotes(part)
        if token.startswith("/") or token == "*":
            rebuilt.append(part)
        elif token.startswith("\\"):
            rebuilt.append(part)
        elif _NET_USE_DRIVE.fullmatch(token) is not None:
            rebuilt.append(part)
        else:
            rebuilt.append(_mask_value("", part))
    return head + "".join(rebuilt)


def _redact_flag_value(match: re.Match[str]) -> str:
    """Replace a flag value unless it is a missing value (next flag)."""
    flag, value = match.group("flag"), match.group("pw")
    if value.startswith("/") or value.startswith("-"):
        return match.group(0)
    if flag and not flag[-1].isspace() and not flag.endswith(("=", ":")):
        # Glued form (``-P<password>``, ``-w<password>``): keep the
        # flag readable by separating it from the marker.
        flag += " "
    return _mask_value(flag, value)


def _redact_chpasswd(match: re.Match[str]) -> str:
    """Replace the password of a ``user:password | chpasswd`` pair."""
    quote, user = match.group("q"), match.group("user")
    return f"echo {quote}{user}:{_mask_value('', match.group('pw'))}{quote}"


def _redact_in_command(
    text: str, command: re.Pattern[str], flag: re.Pattern[str]
) -> str:
    """Apply the ``flag`` password pattern inside ``command`` segments."""

    def _segment(match: re.Match[str]) -> str:
        return flag.sub(_redact_flag_value, match.group(0))

    return command.sub(_segment, text)


def redact(text: str) -> str:
    """Replace tokens and credentials in ``text`` with ``[REDACTED:kind]``.

    Covers bearer tokens (8+ characters, so ordinary prose such as
    "the bearer of bad news" is left alone), ``Authorization``
    headers, JWTs, common cloud key prefixes (``AKIA…``,
    ``ghp_…``/``gho_…``/``ghu_…``/``ghs_…``/``ghr_…``, ``xox…``,
    ``sk-…``), key=value pairs whose key holds ``secret``,
    ``token``, ``password``, ``passwd``, ``pwd`` or ``api_key`` as an
    underscore/dash segment (quoted or bare), ``curl -u`` / ``--user``
    user:password pairs, command-line password forms (``net user``,
    ``net use`` with its share/drive/user targets kept (quoted shares
    holding a space stay one token), ``schtasks
    /RP``, ``sqlcmd -P`` (space, ``=`` or glued, flag text kept) and
    ``ldapsearch -w`` (space, ``=`` or glued) / ``--bindpw`` (space or
    ``=``) scoped to their own
    command so ``scp -P``/``wget -P``/``curl -w`` stay untouched,
    ``xfreerdp /p:``, ``smbclient -U user%pass``, ``user:pass |
    chpasswd``, ``openssl -passin/-passout pass:``), the
    ``ConvertTo-SecureString`` literal, 32/64-hex NTLM/RC4/AES hashes
    and bare NTLM ``LM:NT`` (32 hex : 32 hex) pairs,
    ``Cookie``/``Set-Cookie`` values, ``-p`` / ``--password`` style
    command-line arguments (including PowerShell ``-Password`` /
    ``-Pass`` / ``-Pwd`` with the flag name kept), private key blocks,
    and URLs with embedded userinfo (any ``scheme://`` à la RFC 3986,
    so ``mongodb+srv://``, ``amqps://``, ``rediss://`` and
    ``mysql+pymysql://`` match too; a separable ``user:`` keeps the
    user as ``scheme://user:[REDACTED:credential]@host``, otherwise the
    whole userinfo goes; passwords may hold ``#``, ``?``, ``/``, ``!``
    and ``@``). A
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
    redacted = _URL_SCHEME.sub(_redact_url_userinfo, redacted)
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
    # Command-line password forms (each keeps every non-password token:
    # account and share targets, user flags, hosts and flag names).
    redacted = _NET_USER_CMD.sub(_redact_password_token, redacted)
    redacted = _NET_USE_CMD.sub(_redact_net_use, redacted)
    redacted = _SCHTASKS_RP.sub(_redact_flag_value, redacted)
    redacted = _redact_in_command(redacted, _SQLCMD_CMD, _SQLCMD_P)
    redacted = _redact_in_command(redacted, _LDAPSEARCH_CMD, _LDAPSEARCH_W)
    redacted = _XFREERDP_P.sub(_redact_flag_value, redacted)
    redacted = _SMBCLIENT_U.sub(
        lambda match: _mask_value(
            match.group("flag") + match.group("user") + "%", match.group("pw")
        ),
        redacted,
    )
    redacted = _CHPASSWD.sub(_redact_chpasswd, redacted)
    redacted = _OPENSSL_PASS.sub(_redact_flag_value, redacted)
    redacted = _SECURE_STRING.sub(_redact_secret_literal, redacted)
    redacted = _NTLM_HASH.sub(r"\1" + REDACTED_TEMPLATE.format(kind="hash"), redacted)
    redacted = _NTLM_PAIR.sub(REDACTED_TEMPLATE.format(kind="hash"), redacted)
    redacted = _CREDENTIAL_KV.sub(_redact_kv, redacted)

    def _cli(match: re.Match[str]) -> str:
        marker = REDACTED_TEMPLATE.format(kind="credential")
        if match.group("ps") is not None:
            return _redact_flag_value(match)
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
