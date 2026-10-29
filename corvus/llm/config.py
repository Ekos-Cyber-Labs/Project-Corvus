"""Per-purpose model backend configuration, read from the environment only.

Two purposes exist:

- ``triage``: condenses raw evidence on-prem. Default backend is Glimmer
  (``model="glimmer"``, trust ``"onprem"``); the base URL defaults to
  ``GLIMMER_BASE_URL``.
- ``analysis``: reasons over pseudonymized incidents. Default backend is
  Muse Spark (``model="muse-spark-1.3"``, trust ``"cloud"``); the base URL
  defaults to ``META_BASE_URL`` and the key defaults to ``META_API_KEY``.

Per purpose, every field below is configurable through a ``TRIAGE_`` /
``ANALYSIS_`` environment variable, which takes precedence over the
shared default:

- model name: ``TRIAGE_MODEL`` / ``ANALYSIS_MODEL``
- base URL: ``TRIAGE_BASE_URL`` / ``ANALYSIS_BASE_URL``
- API key value: ``TRIAGE_API_KEY`` / ``ANALYSIS_API_KEY``
- trust level (``onprem`` or ``cloud``): ``TRIAGE_TRUST`` / ``ANALYSIS_TRUST``
- operational limits: ``TRIAGE_CONCURRENCY`` / ``ANALYSIS_CONCURRENCY``
  (default 16 / 4), ``TRIAGE_REQUESTS_PER_MINUTE`` /
  ``ANALYSIS_REQUESTS_PER_MINUTE`` (default 120 / 30),
  ``TRIAGE_MAX_INPUT_TOKENS`` / ``ANALYSIS_MAX_INPUT_TOKENS`` (default
  32768 / 65536), ``TRIAGE_MAX_OUTPUT_TOKENS`` /
  ``ANALYSIS_MAX_OUTPUT_TOKENS`` (default 4200 / 6000).

``MODEL_PROFILE`` decides which backend serves which purpose:

- ``hybrid`` (default): triage uses the triage backend, analysis uses
  the analysis backend.
- ``all-local``: Glimmer serves both purposes. The analysis purpose
  keeps its own operational limits but takes model, base URL, API key
  and trust from the triage backend, so no cloud key is required.
- ``all-cloud``: Muse Spark serves both purposes. The triage purpose
  keeps its own operational limits but takes model, base URL, API key
  and trust from the analysis backend.

Every backend is resolved and validated by :func:`load_llm_config` at
startup. An unknown purpose, a missing/invalid required value, a model
with no price-book row, or an on-prem backend pointing at a public
address raises :class:`LlmConfigError` there, never at first call. API
key values never appear in ``repr``, ``str``, error messages or logs;
only the variable names are mentioned.

Startup also requires every configured model to have a row in the
price book (``config/price_book.yaml`` by default, ``PRICE_BOOK_PATH``
to point elsewhere, or the ``price_book_path`` argument in tests): a
model served on-prem with trust ``"onprem"`` may be declared at price
0 only by an explicit row; there is no implicit zero.

Trust must match the endpoint: a backend with trust ``"onprem"`` whose
base URL host is a public address is refused unless the operator sets
``<PURPOSE>_ALLOW_PUBLIC_ONPREM=1`` for the served purpose (e.g.
``TRIAGE_ALLOW_PUBLIC_ONPREM``). Public means an IP literal that is
not loopback, private (RFC 1918), link-local or unique-local, or a
hostname that resolves (``getaddrinfo``, short timeout, any answer) to
such an address; a name that does not resolve is refused, not accepted.
Cloud trust on a private address is allowed.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal, TypedDict
from urllib.parse import urlsplit

from pydantic import ValidationError

from corvus.llm.price_book import (
    DEFAULT_PRICE_BOOK_PATH,
    PriceBookError,
    load_price_book,
)
from corvus.settings import Settings, get_settings

Purpose = Literal["triage", "analysis"]
TrustLevel = Literal["onprem", "cloud"]

PURPOSES: tuple[str, str] = ("triage", "analysis")
TRUST_LEVELS: tuple[str, str] = ("onprem", "cloud")


class _PurposeDefaults(TypedDict):
    model: str
    trust: str
    concurrency: int
    requests_per_minute: int
    max_input_tokens: int
    max_output_tokens: int


_DEFAULTS: dict[str, _PurposeDefaults] = {
    "triage": {
        "model": "glimmer",
        "trust": "onprem",
        "concurrency": 16,
        "requests_per_minute": 120,
        "max_input_tokens": 32768,
        "max_output_tokens": 4200,
    },
    "analysis": {
        "model": "muse-spark-1.3",
        "trust": "cloud",
        "concurrency": 4,
        "requests_per_minute": 30,
        "max_input_tokens": 65536,
        "max_output_tokens": 6000,
    },
}


PRICE_BOOK_PATH_VAR = "PRICE_BOOK_PATH"
DNS_TIMEOUT_SECONDS = 2.0

_V4_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_V6_UNIQUE_LOCAL = ipaddress.ip_network("fc00::/7")

# Signature of the hostname resolver used by the on-prem endpoint check.
# The default runs getaddrinfo with a short timeout; tests inject a stub.
ResolveHost = Callable[[str], list[str]]


class LlmConfigError(ValueError):
    """Raised when LLM backend configuration is unknown, missing or invalid."""


def _shared_settings() -> Settings:
    """Load shared settings, rewording validation errors as config errors."""
    try:
        return get_settings()
    except ValidationError as exc:
        raise LlmConfigError(
            f"invalid shared LLM settings: {exc.errors(include_url=False)}"
        ) from None


@dataclass(frozen=True)
class BackendConfig:
    """Connection parameters plus operational limits for one purpose."""

    purpose: str
    model: str
    base_url: str
    trust: str
    concurrency: int
    requests_per_minute: int
    max_input_tokens: int
    max_output_tokens: int
    api_key: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            f"BackendConfig(purpose={self.purpose!r}, model={self.model!r}, "
            f"base_url={self.base_url!r}, trust={self.trust!r}, "
            f"concurrency={self.concurrency!r}, "
            f"requests_per_minute={self.requests_per_minute!r}, "
            f"max_input_tokens={self.max_input_tokens!r}, "
            f"max_output_tokens={self.max_output_tokens!r}, "
            f"api_key_set={self.api_key is not None!r})"
        )


def _non_empty(name: str) -> str | None:
    """Return the env value, treating missing/blank as unset."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    return value


def _positive_int(var_name: str, raw: str | None, default: int) -> int:
    if raw is None:
        return default
    try:
        parsed = int(raw.strip())
    except ValueError:
        raise LlmConfigError(
            f"{var_name} must be a positive integer, got {raw.strip()!r}"
        ) from None
    if parsed <= 0:
        raise LlmConfigError(
            f"{var_name} must be a positive integer, got {raw.strip()!r}"
        )
    return parsed


def _resolve_group(purpose: str) -> BackendConfig:
    """Resolve one purpose from its own env group plus shared defaults.

    Performs no API-key enforcement; :func:`get_backend` enforces it on
    the serving backend after profile routing.
    """
    prefix = purpose.upper()
    defaults = _DEFAULTS[purpose]
    settings = _shared_settings()

    model = _non_empty(f"{prefix}_MODEL") or str(defaults["model"])

    if purpose == "triage":
        base_url = _non_empty("TRIAGE_BASE_URL") or settings.glimmer_base_url
        api_key = _non_empty("TRIAGE_API_KEY")
    else:
        base_url = _non_empty("ANALYSIS_BASE_URL") or settings.meta_base_url
        api_key = _non_empty("ANALYSIS_API_KEY") or settings.meta_api_key

    if not base_url or not base_url.strip():
        missing = f"{prefix}_BASE_URL"
        fallback = "GLIMMER_BASE_URL" if purpose == "triage" else "META_BASE_URL"
        raise LlmConfigError(
            f"missing base URL for purpose {purpose!r}: set {missing} or {fallback}"
        )

    trust = _non_empty(f"{prefix}_TRUST") or str(defaults["trust"])
    if trust not in TRUST_LEVELS:
        raise LlmConfigError(
            f"{prefix}_TRUST must be one of 'onprem', 'cloud', got {trust!r}"
        )

    # Key requirement is enforced by get_backend after profile routing:
    # a purpose served with cloud trust needs a key, on-prem needs none.
    return BackendConfig(
        purpose=purpose,
        model=model,
        base_url=base_url.strip(),
        trust=trust,
        concurrency=_positive_int(
            f"{prefix}_CONCURRENCY",
            os.environ.get(f"{prefix}_CONCURRENCY"),
            int(defaults["concurrency"]),
        ),
        requests_per_minute=_positive_int(
            f"{prefix}_REQUESTS_PER_MINUTE",
            os.environ.get(f"{prefix}_REQUESTS_PER_MINUTE"),
            int(defaults["requests_per_minute"]),
        ),
        max_input_tokens=_positive_int(
            f"{prefix}_MAX_INPUT_TOKENS",
            os.environ.get(f"{prefix}_MAX_INPUT_TOKENS"),
            int(defaults["max_input_tokens"]),
        ),
        max_output_tokens=_positive_int(
            f"{prefix}_MAX_OUTPUT_TOKENS",
            os.environ.get(f"{prefix}_MAX_OUTPUT_TOKENS"),
            int(defaults["max_output_tokens"]),
        ),
        api_key=api_key,
    )


def _price_book_path(explicit: str | Path | None) -> Path:
    """Resolve the price-book file: argument, env, then the default."""
    if explicit is None:
        candidate: str | Path = os.environ.get(PRICE_BOOK_PATH_VAR, "")
    else:
        candidate = explicit
    if str(candidate).strip() == "":
        return DEFAULT_PRICE_BOOK_PATH
    return Path(candidate)


def _require_price_row(
    config: BackendConfig, purpose: str, price_book_path: str | Path | None
) -> None:
    """Require a price-book row for the served model; on-prem needs one too."""
    path = _price_book_path(price_book_path)
    try:
        prices = load_price_book(path)
    except PriceBookError as exc:
        raise LlmConfigError(
            f"cannot price purpose {purpose!r} from price book at {path}: {exc}"
        ) from None
    if config.model not in prices:
        raise LlmConfigError(
            f"model {config.model!r} for purpose {purpose!r} has no row "
            f"in the price book: add it to {path}"
        )


def _ip_is_public(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """True unless the literal is loopback, RFC 1918, link-local or unique-local."""
    if address.is_loopback:
        return False
    if address.version == 4:
        assert isinstance(address, ipaddress.IPv4Address)
        return all(address not in net for net in _V4_RFC1918) and (
            not address.is_link_local
        )
    assert isinstance(address, ipaddress.IPv6Address)
    return not address.is_link_local and address not in _V6_UNIQUE_LOCAL


def _default_resolve_host(host: str) -> list[str]:
    """Resolve ``host`` via getaddrinfo, bounded by a short timeout."""
    answers: list[str] = []

    def _lookup() -> None:
        try:
            for _, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                address = sockaddr[0]
                if isinstance(address, str):
                    answers.append(address)
        except OSError:
            pass

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout=DNS_TIMEOUT_SECONDS)
    return answers


def _check_onprem_endpoint(
    config: BackendConfig, purpose: str, resolve_host: ResolveHost | None
) -> None:
    """Refuse an on-prem backend whose base URL host is a public address."""
    if config.trust != "onprem":
        return
    hostname = urlsplit(config.base_url).hostname
    opt_in_var = f"{purpose.upper()}_ALLOW_PUBLIC_ONPREM"
    allowed = os.environ.get(opt_in_var) == "1"
    if hostname is None or hostname.strip() == "":
        raise LlmConfigError(
            f"purpose {purpose!r} uses on-prem trust but its base URL "
            f"{config.base_url!r} has no host; refusing so raw evidence "
            f"never leaves the network"
        )
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_is_public(literal) and not allowed:
            raise LlmConfigError(
                f"purpose {purpose!r} uses on-prem trust but its base URL "
                f"host {hostname!r} is a public address; refusing so raw "
                f"evidence never leaves the network — set {opt_in_var}=1 "
                "to allow it"
            )
        return
    resolver = resolve_host or _default_resolve_host
    answers = resolver(hostname)
    public: list[str] = []
    broken: list[str] = []
    for answer in answers:
        try:
            parsed = ipaddress.ip_address(answer)
        except ValueError:
            broken.append(answer)
            continue
        if _ip_is_public(parsed):
            public.append(answer)
    if not answers:
        reason = f"host {hostname!r} does not resolve"
    elif broken:
        reason = f"host {hostname!r} answered with unparseable addresses {broken}"
    elif public:
        reason = f"host {hostname!r} resolves to public address(es) {public}"
    else:
        return
    if allowed:
        return
    raise LlmConfigError(
        f"purpose {purpose!r} uses on-prem trust but {reason}; refusing so "
        f"raw evidence never leaves the network — set {opt_in_var}=1 to "
        "allow it"
    )


def get_backend(
    purpose: str,
    price_book_path: str | Path | None = None,
    resolve_host: ResolveHost | None = None,
) -> BackendConfig:
    """Return the validated backend serving ``purpose``.

    Raises :class:`LlmConfigError` for an unknown purpose, a missing /
    invalid required value, a model with no price-book row, or an
    on-prem backend pointing at a public address.
    """
    if purpose not in PURPOSES:
        raise LlmConfigError(
            f"unknown LLM purpose {purpose!r}; expected one of 'triage', 'analysis'"
        )
    profile = _shared_settings().model_profile
    if profile == "all-local" and purpose == "analysis":
        backend_source, limits_source = "triage", "analysis"
    elif profile == "all-cloud" and purpose == "triage":
        backend_source, limits_source = "analysis", "triage"
    else:
        backend_source, limits_source = purpose, purpose
    backend = _resolve_group(backend_source)
    if limits_source == backend_source:
        config = backend
    else:
        limits = _resolve_group(limits_source)
        config = replace(
            backend,
            purpose=purpose,
            concurrency=limits.concurrency,
            requests_per_minute=limits.requests_per_minute,
            max_input_tokens=limits.max_input_tokens,
            max_output_tokens=limits.max_output_tokens,
        )
    if config.trust == "cloud" and not config.api_key:
        if backend_source == "analysis":
            key_vars = "ANALYSIS_API_KEY or META_API_KEY"
        else:
            key_vars = "TRIAGE_API_KEY"
        raise LlmConfigError(
            f"missing API key for purpose {purpose!r} (served by the "
            f"{backend_source} backend with cloud trust): set {key_vars}"
        )
    _require_price_row(config, purpose, price_book_path)
    _check_onprem_endpoint(config, purpose, resolve_host)
    return config


def load_llm_config(
    price_book_path: str | Path | None = None,
    resolve_host: ResolveHost | None = None,
) -> dict[str, BackendConfig]:
    """Resolve and validate both purposes; call once at startup."""
    return {
        purpose: get_backend(
            purpose, price_book_path=price_book_path, resolve_host=resolve_host
        )
        for purpose in PURPOSES
    }
