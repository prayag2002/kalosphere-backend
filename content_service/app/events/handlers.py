"""Event handlers for inter-service communication."""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.events import UserDeletedEvent
from app.services.post_service import PostService

logger = logging.getLogger(__name__)


async def handle_user_deleted(event_data: dict[str, Any], db: AsyncSession) -> None:
    """
    Handle user.deleted event - soft delete all user's posts.

    When a user account is deleted in the Auth Service, we soft-delete
    all of their content to maintain referential integrity.
    """
    try:
        event = UserDeletedEvent.model_validate(event_data)
        payload = event.payload

        service = PostService(db)
        count = await service.soft_delete_by_author(payload.user_id)

        logger.info(
            f"Soft-deleted {count} posts for deleted user {payload.user_id}"
        )

    except Exception as e:
        logger.error(f"Failed to handle user.deleted: {e}")
        raise


# Event type to handler mapping
EVENT_HANDLERS: dict[str, Any] = {
    "user.deleted": handle_user_deleted,
}
