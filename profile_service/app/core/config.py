"""Application configuration via pydantic-settings."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/profile_service"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT Configuration (public key for validation only)
    jwt_public_key: str = ""
    jwt_algorithm: str = "RS256"
    jwt_audience: str = "kalosphere"
    jwt_issuer: str = "kalosphere-auth"

    # Storage
    avatar_bucket: str = "kalosphere-avatars"
    avatar_max_size_mb: int = 5
    cdn_base_url: str = ""

    # AWS/S3 Configuration
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    s3_endpoint_url: Optional[str] = None

    # Events
    event_stream_prefix: str = "kalosphere"
    consumer_group: str = "profile-service"

    # Application
    debug: bool = False

    @property
    def avatar_max_size_bytes(self) -> int:
        """Max avatar size in bytes."""
        return self.avatar_max_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
