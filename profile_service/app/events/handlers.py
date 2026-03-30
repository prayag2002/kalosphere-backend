"""Event handlers for inter-service communication."""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.events import (
    ReputationUpdatedEvent,
    UserCreatedEvent,
    UserDeletedEvent,
)
from app.schemas.profile import ProfileCreate
from app.services.profile_service import ProfileService
from app.services.reputation_service import ReputationService

logger = logging.getLogger(__name__)


async def handle_user_created(event_data: dict[str, Any], db: AsyncSession) -> None:
    """Handle user.created event - create profile skeleton."""
    try:
        event = UserCreatedEvent.model_validate(event_data)
        payload = event.payload

        service = ProfileService(db)
        await service.create(
            ProfileCreate(
                user_id=payload.user_id,
                username=payload.username,
                bio=None,
            )
        )

        logger.info(f"Created profile for user {payload.user_id}")

    except Exception as e:
        logger.error(f"Failed to handle user.created: {e}")
        raise


async def handle_user_deleted(event_data: dict[str, Any], db: AsyncSession) -> None:
    """Handle user.deleted event - soft delete profile."""
    try:
        event = UserDeletedEvent.model_validate(event_data)
        payload = event.payload

        service = ProfileService(db)
        await service.soft_delete(payload.user_id)

        logger.info(f"Soft-deleted profile for user {payload.user_id}")

    except Exception as e:
        logger.error(f"Failed to handle user.deleted: {e}")
        raise


async def handle_reputation_updated(
    event_data: dict[str, Any], db: AsyncSession
) -> None:
    """Handle reputation.updated event - update score read model."""
    try:
        event = ReputationUpdatedEvent.model_validate(event_data)

        service = ReputationService(db)
        processed = await service.handle_reputation_update(event)

        if processed:
            logger.info(
                f"Updated reputation for user {event.payload.user_id}: "
                f"{event.payload.delta:+.2f} -> {event.payload.new_score:.2f}"
            )
        else:
            logger.debug(f"Duplicate event {event.event_id}, skipping")

    except Exception as e:
        logger.error(f"Failed to handle reputation.updated: {e}")
        raise


# Event type to handler mapping
EVENT_HANDLERS = {
    "user.created": handle_user_created,
    "user.deleted": handle_user_deleted,
    "reputation.updated": handle_reputation_updated,
}
