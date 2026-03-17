"""Event schemas for inter-service communication."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class BaseEvent(BaseModel):
    """Base schema for all events."""

    event_id: UUID
    event_type: str
    timestamp: datetime
    version: int = 1


class UserCreatedPayload(BaseModel):
    """Payload for user.created event."""

    user_id: UUID
    username: str
    email: str


class UserCreatedEvent(BaseEvent):
    """Event emitted when user registers in Auth Service."""

    event_type: str = "user.created"
    payload: UserCreatedPayload


class UserDeletedPayload(BaseModel):
    """Payload for user.deleted event."""

    user_id: UUID
    reason: str | None = None


class UserDeletedEvent(BaseEvent):
    """Event emitted when user account is deleted."""

    event_type: str = "user.deleted"
    payload: UserDeletedPayload


class ReputationBreakdown(BaseModel):
    """Breakdown of reputation score by category."""

    peer_rating: Decimal = Field(default=Decimal("0.00"))
    curator_rating: Decimal = Field(default=Decimal("0.00"))
    technical: Decimal = Field(default=Decimal("0.00"))


class ReputationUpdatedPayload(BaseModel):
    """Payload for reputation.updated event."""

    user_id: UUID
    new_score: Decimal
    delta: Decimal
    breakdown: dict[str, Any]
    reason: str


class ReputationUpdatedEvent(BaseEvent):
    """Event emitted when Quality Scoring Service updates reputation."""

    event_type: str = "reputation.updated"
    payload: ReputationUpdatedPayload
