from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelAI"
    environment: str = "development"
    database_url: str = "sqlite:///./sentinel.db"
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    response_mode: str = "simulate"
    extension_token: str = "local-development-token"
    evidence_directory: str = "./evidence"
    screenshot_max_bytes: int = 4_000_000
    auto_capture_screenshots: bool = True
    screenshot_timeout_ms: int = 20_000
    screenshot_settle_ms: int = 1_500
    screenshot_viewport_width: int = 1440
    screenshot_viewport_height: int = 900

    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    urlscan_api_key: str | None = None

    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str = "2025-04-01-preview"
    azure_openai_chat_deployment: str | None = None
    azure_openai_vision_deployment: str | None = None
    azure_openai_embedding_deployment: str | None = None
    vlm_base_url: str = "http://host.docker.internal:12434/engines/v1"
    vlm_api_key: str = "docker-model-runner"
    vlm_model: str = "ministral3"
    azure_search_endpoint: str | None = None
    azure_search_api_key: str | None = None
    azure_search_index: str = "cybersecurity-knowledge"
    azure_storage_connection_string: str | None = None
    azure_storage_container: str = "evidence"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
