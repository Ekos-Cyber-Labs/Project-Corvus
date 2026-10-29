"""Backend configuration: defaults, precedence, routing, secret redaction."""

import logging
from pathlib import Path

import pytest

from corvus.llm.config import (
    LlmConfigError,
    ResolveHost,
    get_backend,
    load_llm_config,
)

PURPOSE_VARS = [
    "TRIAGE_MODEL",
    "TRIAGE_BASE_URL",
    "TRIAGE_API_KEY",
    "TRIAGE_TRUST",
    "TRIAGE_CONCURRENCY",
    "TRIAGE_REQUESTS_PER_MINUTE",
    "TRIAGE_MAX_INPUT_TOKENS",
    "TRIAGE_MAX_OUTPUT_TOKENS",
    "TRIAGE_ALLOW_PUBLIC_ONPREM",
    "ANALYSIS_MODEL",
    "ANALYSIS_BASE_URL",
    "ANALYSIS_API_KEY",
    "ANALYSIS_TRUST",
    "ANALYSIS_CONCURRENCY",
    "ANALYSIS_REQUESTS_PER_MINUTE",
    "ANALYSIS_MAX_INPUT_TOKENS",
    "ANALYSIS_MAX_OUTPUT_TOKENS",
    "ANALYSIS_ALLOW_PUBLIC_ONPREM",
    "PRICE_BOOK_PATH",
]

#: Loopback base URL for the hermetic tests: no DNS lookup is needed.
LOOPBACK_BASE_URL = "http://127.0.0.1:8001/v1"


def _stub_resolver(mapping: dict[str, list[str]]) -> ResolveHost:
    """Return a resolver answering from a fixed table (no real DNS)."""

    def resolve(host: str) -> list[str]:
        return list(mapping.get(host, []))

    return resolve


@pytest.fixture
def base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal hermetic environment: hybrid profile, no purpose overrides."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://127.0.0.1:55432/corvus")
    monkeypatch.setenv("GLIMMER_BASE_URL", LOOPBACK_BASE_URL)
    monkeypatch.setenv("META_API_KEY", "test-meta-key")
    monkeypatch.setenv("MODEL_PROFILE", "hybrid")
    monkeypatch.delenv("META_BASE_URL", raising=False)
    for var in PURPOSE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_defaults(base_env: None) -> None:
    triage = get_backend("triage")
    assert triage.model == "glimmer"
    assert triage.base_url == LOOPBACK_BASE_URL
    assert triage.trust == "onprem"
    assert triage.concurrency == 16
    assert triage.max_output_tokens == 4200
    assert triage.api_key is None

    analysis = get_backend("analysis")
    assert analysis.model == "muse-spark-1.3"
    assert analysis.base_url == "https://api.meta.ai/v1"
    assert analysis.trust == "cloud"
    assert analysis.concurrency == 4
    assert analysis.max_output_tokens == 6000
    assert analysis.api_key == "test-meta-key"


def test_purpose_vars_take_precedence_over_shared(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both overrides name models/addresses that pass the startup checks.
    monkeypatch.setenv("TRIAGE_MODEL", "muse-spark-1.3")
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://10.9.8.7:8001/v1")
    monkeypatch.setenv("ANALYSIS_API_KEY", "test-analysis-key")
    triage = get_backend("triage")
    assert triage.model == "muse-spark-1.3"
    assert triage.base_url == "http://10.9.8.7:8001/v1"
    assert get_backend("analysis").api_key == "test-analysis-key"


def test_unknown_model_fails_startup_naming_model_and_file(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANALYSIS_MODEL", "no-such-model")
    with pytest.raises(LlmConfigError) as excinfo:
        get_backend("analysis")
    assert "no-such-model" in str(excinfo.value)
    assert "price_book.yaml" in str(excinfo.value)


_TEST_BOOK = """\
muse-spark-1.3:
  input_per_mtok: 1.25
  cached_input_per_mtok: 0.15
  output_per_mtok: 4.25
  source: "test"
  date: "2026-10-29"
glimmer:
  input_per_mtok: 0
  cached_input_per_mtok: 0
  output_per_mtok: 0
  source: "test"
  date: "2026-10-29"
muse-spark-9.9:
  input_per_mtok: 2.0
  cached_input_per_mtok: 0.2
  output_per_mtok: 5.0
  source: "test"
  date: "2026-10-29"
"""


def test_test_price_book_row_makes_unknown_model_pass(
    base_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    book = tmp_path / "price_book.yaml"
    book.write_text(_TEST_BOOK, encoding="utf-8")
    monkeypatch.setenv("ANALYSIS_MODEL", "muse-spark-9.9")
    with pytest.raises(LlmConfigError, match="muse-spark-9.9"):
        get_backend("analysis")
    monkeypatch.setenv("PRICE_BOOK_PATH", str(book))
    assert get_backend("analysis").model == "muse-spark-9.9"


def test_unknown_purpose_raises(base_env: None) -> None:
    with pytest.raises(LlmConfigError, match="unknown LLM purpose"):
        get_backend("summarize")


def test_missing_glimmer_base_url_raises_at_startup(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GLIMMER_BASE_URL")
    with pytest.raises(LlmConfigError, match="GLIMMER_BASE_URL"):
        get_backend("triage")


def test_missing_analysis_key_raises_at_startup(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("META_API_KEY")
    with pytest.raises(LlmConfigError, match="META_API_KEY"):
        get_backend("analysis")
    # Triage is unaffected: on-prem needs no key.
    assert get_backend("triage").model == "glimmer"
    with pytest.raises(LlmConfigError, match="META_API_KEY"):
        load_llm_config()


def test_all_local_serves_both_from_glimmer(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MODEL_PROFILE", "all-local")
    monkeypatch.delenv("META_API_KEY")
    config = load_llm_config()
    assert config["triage"].model == "glimmer"
    assert config["analysis"].model == "glimmer"
    assert config["analysis"].base_url == config["triage"].base_url
    assert config["analysis"].trust == "onprem"
    # Operational limits stay per-purpose.
    assert config["analysis"].concurrency == 4
    assert config["analysis"].max_output_tokens == 6000
    assert config["triage"].concurrency == 16


def test_all_cloud_serves_both_from_spark(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MODEL_PROFILE", "all-cloud")
    config = load_llm_config()
    assert config["triage"].model == "muse-spark-1.3"
    assert config["analysis"].model == "muse-spark-1.3"
    assert config["triage"].trust == "cloud"
    assert config["triage"].api_key == "test-meta-key"
    # Operational limits stay per-purpose.
    assert config["triage"].concurrency == 16
    assert config["triage"].max_output_tokens == 4200


def test_all_cloud_triage_needs_cloud_key(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MODEL_PROFILE", "all-cloud")
    monkeypatch.delenv("META_API_KEY")
    with pytest.raises(LlmConfigError, match="API key"):
        get_backend("triage")


def test_onprem_private_endpoints_pass(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve = _stub_resolver(
        {
            "localhost": ["127.0.0.1"],
            "localhost6": ["::1"],
            "glimmer.internal.example": ["10.4.5.6"],
        }
    )
    allowed = [
        "http://127.0.0.1:8001/v1",
        "http://192.168.100.227:8001/v1",
        "http://[fd00::1]:8001/v1",
        "http://localhost:8001/v1",
        "http://localhost6:8001/v1",
        "http://glimmer.internal.example:8001/v1",
    ]
    for base_url in allowed:
        monkeypatch.setenv("TRIAGE_BASE_URL", base_url)
        config = get_backend("triage", resolve_host=resolve)
        assert config.base_url == base_url


def test_onprem_public_or_unresolvable_endpoints_refused(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve = _stub_resolver(
        {
            "public.example": ["8.8.4.4"],
            "mixed.example": ["10.4.5.6", "8.8.8.8"],
        }
    )
    refused_literal = [
        "http://8.8.8.8:8001/v1",
        "http://203.0.113.5:8001/v1",
    ]
    for base_url in refused_literal:
        monkeypatch.setenv("TRIAGE_BASE_URL", base_url)
        with pytest.raises(LlmConfigError, match="public address"):
            get_backend("triage", resolve_host=resolve)
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://public.example:8001/v1")
    with pytest.raises(LlmConfigError, match="public"):
        get_backend("triage", resolve_host=resolve)
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://mixed.example:8001/v1")
    with pytest.raises(LlmConfigError, match="public"):
        get_backend("triage", resolve_host=resolve)
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://gone.example:8001/v1")
    with pytest.raises(LlmConfigError, match="does not resolve"):
        get_backend("triage", resolve_host=resolve)


def test_trusted_hostname_resolving_public_refused(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same trusted name, hostile answer: refused unless opted in.
    resolve = _stub_resolver({"glimmer.internal.example": ["8.8.8.8"]})
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://glimmer.internal.example:8001/v1")
    with pytest.raises(LlmConfigError, match="public"):
        get_backend("triage", resolve_host=resolve)
    monkeypatch.setenv("TRIAGE_ALLOW_PUBLIC_ONPREM", "1")
    config = get_backend("triage", resolve_host=resolve)
    assert config.base_url == "http://glimmer.internal.example:8001/v1"


def test_public_onprem_opt_in_allows_each_refused_case(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve = _stub_resolver(
        {
            "public.example": ["8.8.4.4"],
            "mixed.example": ["10.4.5.6", "8.8.8.8"],
        }
    )
    monkeypatch.setenv("TRIAGE_ALLOW_PUBLIC_ONPREM", "1")
    refused = [
        "http://8.8.8.8:8001/v1",
        "http://203.0.113.5:8001/v1",
        "http://public.example:8001/v1",
        "http://mixed.example:8001/v1",
        "http://gone.example:8001/v1",
    ]
    for base_url in refused:
        monkeypatch.setenv("TRIAGE_BASE_URL", base_url)
        assert get_backend("triage", resolve_host=resolve).base_url == base_url


def test_cloud_trust_on_private_address_allowed(
    base_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRIAGE_TRUST", "cloud")
    monkeypatch.setenv("TRIAGE_API_KEY", "test-triage-key")
    monkeypatch.setenv("TRIAGE_BASE_URL", "http://192.168.100.227:8001/v1")
    config = get_backend("triage", resolve_host=_stub_resolver({}))
    assert config.trust == "cloud"
    assert config.api_key == "test-triage-key"


def test_invalid_values_raise(base_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIAGE_CONCURRENCY", "0")
    with pytest.raises(LlmConfigError, match="TRIAGE_CONCURRENCY"):
        get_backend("triage")
    monkeypatch.setenv("TRIAGE_CONCURRENCY", "16")
    monkeypatch.setenv("TRIAGE_TRUST", "dmz")
    with pytest.raises(LlmConfigError, match="TRIAGE_TRUST"):
        get_backend("triage")
    monkeypatch.setenv("TRIAGE_TRUST", "onprem")
    monkeypatch.setenv("ANALYSIS_MAX_OUTPUT_TOKENS", "many")
    with pytest.raises(LlmConfigError, match="ANALYSIS_MAX_OUTPUT_TOKENS"):
        get_backend("analysis")


def test_secrets_never_leak(
    base_env: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "test-only-fake-secret-abc123"
    monkeypatch.setenv("ANALYSIS_API_KEY", secret)
    config = get_backend("analysis")
    assert config.api_key == secret
    assert secret not in repr(config)
    assert secret not in str(config)
    with caplog.at_level(logging.DEBUG):
        load_llm_config()
    assert secret not in caplog.text
    monkeypatch.setenv("TRIAGE_CONCURRENCY", "0")
    with pytest.raises(LlmConfigError) as excinfo:
        get_backend("triage")
    assert secret not in str(excinfo.value)
    with pytest.raises(LlmConfigError) as excinfo:
        get_backend("nope")
    assert secret not in str(excinfo.value)
