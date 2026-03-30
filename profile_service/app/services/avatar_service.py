"""Avatar service - storage operations for user avatars."""

import logging
from uuid import UUID

import aioboto3

from app.core.config import settings
from app.core.exceptions import InvalidAvatarError

logger = logging.getLogger(__name__)

# Allowed MIME types
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}


class AvatarService:
    """Service for avatar upload and storage operations."""

    def __init__(self):
        self.session = aioboto3.Session()

    def _get_client_kwargs(self) -> dict:
        """Get boto3 client configuration."""
        kwargs = {"region_name": settings.aws_region}
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        return kwargs

    async def upload(
        self,
        user_id: UUID,
        file_content: bytes,
        content_type: str,
    ) -> str:
        """
        Upload avatar to S3-compatible storage.

        Returns storage key (not full URL).
        """
        # Validate content type
        if content_type not in ALLOWED_TYPES:
            raise InvalidAvatarError(
                f"Invalid file type. Allowed: {', '.join(ALLOWED_TYPES)}"
            )

        # Validate size
        if len(file_content) > settings.avatar_max_size_bytes:
            raise InvalidAvatarError(
                f"File too large. Maximum: {settings.avatar_max_size_mb}MB"
            )

        # Generate storage key
        ext = content_type.split("/")[-1]
        storage_key = f"avatars/{user_id}.{ext}"

        async with self.session.client("s3", **self._get_client_kwargs()) as s3:
            await s3.put_object(
                Bucket=settings.avatar_bucket,
                Key=storage_key,
                Body=file_content,
                ContentType=content_type,
                CacheControl="max-age=86400",  # 1 day cache
            )

        logger.info(f"Uploaded avatar for user {user_id}: {storage_key}")
        return storage_key

    async def delete(self, user_id: UUID, storage_key: str) -> None:
        """Delete avatar from storage."""
        async with self.session.client("s3", **self._get_client_kwargs()) as s3:
            await s3.delete_object(
                Bucket=settings.avatar_bucket,
                Key=storage_key,
            )

        logger.info(f"Deleted avatar for user {user_id}: {storage_key}")
