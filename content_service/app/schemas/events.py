"""Event schemas for inter-service communication."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class BaseEvent(BaseModel):
    """Base schema for all events."""

    event_id: UUID
    event_type: str
    timestamp: datetime
    version: int = 1


class UserDeletedPayload(BaseModel):
    """Payload for user.deleted event."""

    user_id: UUID
    reason: str | None = None


class UserDeletedEvent(BaseEvent):
    """Event emitted when user account is deleted."""

    event_type: str = "user.deleted"
    payload: UserDeletedPayload


# --- Events this service publishes ---


class PostCreatedPayload(BaseModel):
    """Payload for post.created event."""

    post_id: UUID
    author_id: UUID
    title: str
    category_id: UUID
    media_type: str


class PostDeletedPayload(BaseModel):
    """Payload for post.deleted event."""

    post_id: UUID
    author_id: UUID


class PostLikedPayload(BaseModel):
    """Payload for post.liked event."""

    post_id: UUID
    author_id: UUID  # Post author (receives reputation)
    liker_id: UUID  # User who liked
    like_count: int  # New total
