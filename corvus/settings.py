"""Environment-based settings for Corvus."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration read from environment variables."""

    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(validation_alias="DATABASE_URL")
    glimmer_base_url: str = Field(validation_alias="GLIMMER_BASE_URL")
    meta_base_url: str = Field(
        default="https://api.meta.ai/v1",
        validation_alias="META_BASE_URL",
    )
    meta_api_key: str | None = Field(default=None, validation_alias="META_API_KEY")
    model_profile: Literal["all-local", "hybrid", "all-cloud"] = Field(
        default="hybrid", validation_alias="MODEL_PROFILE"
    )
    wazuh_indexer_url: str | None = Field(
        default=None, validation_alias="WAZUH_INDEXER_URL"
    )
    wazuh_indexer_user: str | None = Field(
        default=None, validation_alias="WAZUH_INDEXER_USER"
    )
    wazuh_indexer_password: str | None = Field(
        default=None, validation_alias="WAZUH_INDEXER_PASSWORD"
    )
    wazuh_api_url: str | None = Field(default=None, validation_alias="WAZUH_API_URL")
    wazuh_api_user: str | None = Field(default=None, validation_alias="WAZUH_API_USER")
    wazuh_api_password: str | None = Field(
        default=None, validation_alias="WAZUH_API_PASSWORD"
    )
    wazuh_verify_tls: bool = Field(default=True, validation_alias="WAZUH_VERIFY_TLS")
    # Deterministic correlation windows (corvus/correlate): two findings
    # join the same incident when they share a join key and the gap from
    # the incident's last finding is at most the session gap; an incident
    # never spans more than the max span, however long the chain runs.
    correlation_session_gap_minutes: int = Field(
        default=30, validation_alias="CORRELATION_SESSION_GAP_MINUTES"
    )
    correlation_max_span_hours: int = Field(
        default=24, validation_alias="CORRELATION_MAX_SPAN_HOURS"
    )
    # Success-vs-attempt factor: a successful authentication counts as a
    # success only after at least this many failures against the same
    # target user/host inside the incident; failures alone add nothing.
    correlation_auth_failure_threshold: int = Field(
        default=3, validation_alias="CORRELATION_AUTH_FAILURE_THRESHOLD"
    )


def get_settings() -> Settings:
    """Load settings from the environment."""
    return Settings()  # type: ignore[call-arg]
