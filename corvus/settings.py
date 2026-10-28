"""Environment-based settings for Corvus."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration read from environment variables."""

    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(
        default="postgresql://corvus:corvus@localhost:5432/corvus",
        validation_alias="DATABASE_URL",
    )
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


def get_settings() -> Settings:
    """Load settings from the environment."""
    return Settings()  # type: ignore[call-arg]
