"""Media service - storage and image optimization for content uploads.

Handles S3 upload/delete, image resizing, and automatic thumbnail generation.
Uses Pillow for server-side image processing.
"""

import io
import logging
from uuid import UUID, uuid4

import aioboto3
from PIL import Image, ImageOps

from app.core.config import settings
from app.core.exceptions import InvalidMediaError

logger = logging.getLogger(__name__)

# Allowed MIME types by media category
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
ALLOWED_VIDEO_TYPES = {"video/mp4", "video/webm", "video/quicktime"}
ALLOWED_AUDIO_TYPES = {"audio/mpeg", "audio/wav", "audio/ogg", "audio/flac"}
ALLOWED_DOCUMENT_TYPES = {"application/pdf"}

ALLOWED_TYPES = ALLOWED_IMAGE_TYPES | ALLOWED_VIDEO_TYPES | ALLOWED_AUDIO_TYPES | ALLOWED_DOCUMENT_TYPES

# Image types that support Pillow processing
PROCESSABLE_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}


class MediaService:
    """Service for media upload, optimization, and storage operations."""

    def __init__(self) -> None:
        self.session = aioboto3.Session()

    def _get_client_kwargs(self) -> dict:
        """Get boto3 client configuration."""
        kwargs: dict = {"region_name": settings.aws_region}
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        return kwargs

    def _get_extension(self, content_type: str) -> str:
        """Map MIME type to file extension."""
        ext_map = {
            "image/jpeg": "jpg",
            "image/png": "png",
            "image/webp": "webp",
            "image/gif": "gif",
            "video/mp4": "mp4",
            "video/webm": "webm",
            "video/quicktime": "mov",
            "audio/mpeg": "mp3",
            "audio/wav": "wav",
            "audio/ogg": "ogg",
            "audio/flac": "flac",
            "application/pdf": "pdf",
        }
        return ext_map.get(content_type, "bin")

    def _optimize_image(self, file_content: bytes, content_type: str) -> bytes:
        """
        Optimize image: resize to max dimension, fix EXIF orientation.

        Returns processed image bytes. Non-image types pass through unchanged.
        """
        if content_type not in PROCESSABLE_IMAGE_TYPES:
            return file_content

        try:
            img = Image.open(io.BytesIO(file_content))

            # Fix EXIF orientation (auto-rotate based on camera metadata)
            img = ImageOps.exif_transpose(img)

            # Resize if larger than max dimension (preserves aspect ratio)
            max_dim = settings.image_max_dimension
            if img.width > max_dim or img.height > max_dim:
                img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
                logger.info(f"Resized image to {img.width}x{img.height}")

            # Save to bytes
            output = io.BytesIO()
            fmt = "JPEG" if content_type == "image/jpeg" else img.format or "PNG"
            save_kwargs: dict = {}
            if fmt == "JPEG":
                save_kwargs["quality"] = 85
                save_kwargs["optimize"] = True
            elif fmt == "WEBP":
                save_kwargs["quality"] = 85
            img.save(output, format=fmt, **save_kwargs)
            return output.getvalue()

        except Exception as e:
            logger.warning(f"Image optimization failed, using original: {e}")
            return file_content

    def _generate_thumbnail(self, file_content: bytes, content_type: str) -> bytes | None:
        """
        Generate a WebP thumbnail from an image.

        Returns thumbnail bytes or None if generation fails.
        """
        if content_type not in PROCESSABLE_IMAGE_TYPES:
            return None

        try:
            img = Image.open(io.BytesIO(file_content))
            img = ImageOps.exif_transpose(img)

            # Generate square-ish thumbnail
            thumb_size = settings.thumbnail_dimension
            img.thumbnail((thumb_size, thumb_size), Image.Resampling.LANCZOS)

            output = io.BytesIO()
            img.save(output, format="WEBP", quality=80)
            return output.getvalue()

        except Exception as e:
            logger.warning(f"Thumbnail generation failed: {e}")
            return None

    async def upload(
        self,
        author_id: UUID,
        file_content: bytes,
        content_type: str,
    ) -> tuple[str, str | None]:
        """
        Upload media to S3-compatible storage with optimization.

        Returns tuple of (media_key, thumbnail_key).
        The thumbnail_key may be None if thumbnail generation fails or isn't applicable.
        """
        # Validate content type
        if content_type not in ALLOWED_TYPES:
            raise InvalidMediaError(
                f"Invalid file type '{content_type}'. "
                f"Allowed: images, videos, audio, PDF"
            )

        # Validate size
        if len(file_content) > settings.media_max_size_bytes:
            raise InvalidMediaError(
                f"File too large. Maximum: {settings.media_max_size_mb}MB"
            )

        # Generate unique storage key
        file_id = uuid4()
        ext = self._get_extension(content_type)
        media_key = f"content/{author_id}/{file_id}.{ext}"

        # Optimize image if applicable
        processed_content = self._optimize_image(file_content, content_type)

        # Generate thumbnail
        thumbnail_content = self._generate_thumbnail(file_content, content_type)
        thumbnail_key: str | None = None

        async with self.session.client("s3", **self._get_client_kwargs()) as s3:
            # Upload main media file
            await s3.put_object(
                Bucket=settings.media_bucket,
                Key=media_key,
                Body=processed_content,
                ContentType=content_type,
                CacheControl="max-age=86400",
            )

            # Upload thumbnail if generated
            if thumbnail_content:
                thumbnail_key = f"content/{author_id}/{file_id}_thumb.webp"
                await s3.put_object(
                    Bucket=settings.media_bucket,
                    Key=thumbnail_key,
                    Body=thumbnail_content,
                    ContentType="image/webp",
                    CacheControl="max-age=86400",
                )

        logger.info(f"Uploaded media for user {author_id}: {media_key}")
        return media_key, thumbnail_key

    async def delete(self, storage_key: str) -> None:
        """Delete a single file from storage."""
        async with self.session.client("s3", **self._get_client_kwargs()) as s3:
            await s3.delete_object(
                Bucket=settings.media_bucket,
                Key=storage_key,
            )
        logger.info(f"Deleted media: {storage_key}")

    async def delete_post_media(self, media_key: str, thumbnail_key: str | None) -> None:
        """Delete both media and thumbnail for a post."""
        await self.delete(media_key)
        if thumbnail_key:
            await self.delete(thumbnail_key)
