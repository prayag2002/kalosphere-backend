"""Reputation service - handles reputation events and history."""

from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.profile import Profile
from app.models.reputation import ReputationHistory
from app.schemas.events import ReputationUpdatedEvent
from app.schemas.reputation import (
    ReputationHistoryItem,
    ReputationHistoryResponse,
)


class ReputationService:
    """Service for reputation updates and history."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def handle_reputation_update(self, event: ReputationUpdatedEvent) -> bool:
        """
        Handle reputation.updated event from Quality Scoring Service.

        Returns True if processed, False if already processed (idempotent).
        """
        payload = event.payload

        # Idempotent insert using source_event_id
        history_stmt = (
            insert(ReputationHistory)
            .values(
                user_id=payload.user_id,
                score_delta=payload.delta,
                new_score=payload.new_score,
                reason=payload.reason,
                source_event_id=event.event_id,
                event_metadata=payload.breakdown,
            )
            .on_conflict_do_nothing(index_elements=["source_event_id"])
        )

        result = await self.db.execute(history_stmt)

        if result.rowcount == 0:
            # Already processed this event
            return False

        # Update profile read model
        await self.db.execute(
            update(Profile)
            .where(Profile.user_id == payload.user_id)
            .values(
                reputation_score=payload.new_score,
                reputation_breakdown=payload.breakdown,
            )
        )

        await self.db.commit()
        return True

    async def get_history(
        self,
        user_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> ReputationHistoryResponse:
        """Get reputation history for a user."""
        # Get current score
        profile = await self.db.get(Profile, user_id)
        current_score = profile.reputation_score if profile else Decimal("0.00")

        # Count total
        count_result = await self.db.execute(
            select(func.count())
            .select_from(ReputationHistory)
            .where(ReputationHistory.user_id == user_id)
        )
        total = count_result.scalar() or 0

        # Get paginated history
        result = await self.db.execute(
            select(ReputationHistory)
            .where(ReputationHistory.user_id == user_id)
            .order_by(ReputationHistory.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        records = result.scalars().all()

        items = [
            ReputationHistoryItem(
                timestamp=r.created_at,
                score_delta=r.score_delta,
                new_score=r.new_score,
                reason=r.reason,
                source_event_id=r.source_event_id,
            )
            for r in records
        ]

        return ReputationHistoryResponse(
            items=items,
            current_score=current_score,
            total_items=total,
            has_more=(offset + len(items)) < total,
        )
