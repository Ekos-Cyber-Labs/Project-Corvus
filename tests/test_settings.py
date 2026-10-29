"""Settings must come from the process environment only."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from corvus.settings import get_settings


def test_missing_glimmer_url_fails_clearly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLIMMER_BASE_URL", raising=False)
    with pytest.raises(ValidationError) as excinfo:
        get_settings()
    assert "GLIMMER_BASE_URL" in str(excinfo.value)


def test_dotenv_file_in_cwd_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A .env file must never supply settings; only the environment counts."""
    workdir = tmp_path
    monkeypatch.delenv("GLIMMER_BASE_URL", raising=False)
    monkeypatch.chdir(workdir)
    workdir.joinpath(".env").write_text(
        "GLIMMER_BASE_URL=http://from-dotenv:8001/v1\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError):
        get_settings()


def test_missing_database_url_fails_clearly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://glimmer-host:8001/v1")
    with pytest.raises(ValidationError) as excinfo:
        get_settings()
    assert "DATABASE_URL" in str(excinfo.value)


def test_minimal_environment_constructs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://glimmer-host:8001/v1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://127.0.0.1:55432/corvus")
    monkeypatch.delenv("MODEL_PROFILE", raising=False)
    settings = get_settings()
    assert settings.glimmer_base_url == "http://glimmer-host:8001/v1"
    assert settings.database_url == "postgresql://127.0.0.1:55432/corvus"
    assert settings.model_profile == "hybrid"


def test_wazuh_indexer_ca_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """WAZUH_INDEXER_CA is read from the environment; no TLS-off flag exists."""
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://glimmer-host:8001/v1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://127.0.0.1:55432/corvus")
    monkeypatch.setenv("WAZUH_INDEXER_CA", "/run/corvus/wazuh-indexer-ca.pem")
    assert get_settings().wazuh_indexer_ca == "/run/corvus/wazuh-indexer-ca.pem"
    monkeypatch.delenv("WAZUH_INDEXER_CA")
    assert get_settings().wazuh_indexer_ca is None
    # The removed WAZUH_VERIFY_TLS flag is ignored, never honored.
    monkeypatch.setenv("WAZUH_VERIFY_TLS", "false")
    assert get_settings().wazuh_indexer_ca is None
    assert not hasattr(get_settings(), "wazuh_verify_tls")
