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
    database_url: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5434/content_service"
    )

    # Redis
    redis_url: str = "redis://localhost:6381/0"

    # JWT Configuration (public key for validation only)
    jwt_public_key: str = ""
    jwt_algorithm: str = "RS256"
    jwt_audience: str = "kalosphere"
    jwt_issuer: str = "kalosphere-auth"

    # Storage
    media_bucket: str = "kalosphere-content"
    media_max_size_mb: int = 50
    cdn_base_url: str = ""

    # AWS/S3 Configuration
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    s3_endpoint_url: Optional[str] = None

    # Events
    event_stream_prefix: str = "kalosphere"
    consumer_group: str = "content-service"

    # Rate Limiting
    rate_limit_posts_per_day: int = 10
    rate_limit_likes_per_hour: int = 100
    rate_limit_comments_per_hour: int = 30

    # Image Processing
    image_max_dimension: int = 2048
    thumbnail_dimension: int = 400

    # Application
    debug: bool = False

    # Docker related
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    postgres_db: str = "content_service"

    minio_root_user: str = "minioadmin"
    minio_root_password: str = "minioadmin"

    @property
    def media_max_size_bytes(self) -> int:
        """Max media size in bytes."""
        return self.media_max_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
