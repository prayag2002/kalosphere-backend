"""Reputation history schemas."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReputationHistoryItem(BaseModel):
    """Single reputation change entry."""

    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime
    score_delta: Decimal
    new_score: Decimal
    reason: str
    source_event_id: UUID


class ReputationHistoryResponse(BaseModel):
    """Paginated reputation history."""

    items: list[ReputationHistoryItem]
    current_score: Decimal
    total_items: int
    has_more: bool = False
