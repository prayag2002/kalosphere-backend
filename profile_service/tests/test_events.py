"""Tests for event handlers."""

from decimal import Decimal
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.handlers import (
    handle_reputation_updated,
    handle_user_created,
    handle_user_deleted,
)
from app.models.profile import Profile
from app.models.reputation import ReputationHistory


class TestUserCreatedHandler:
    """Test user.created event handler."""

    async def test_creates_profile(self, db_session: AsyncSession):
        event_data = {
            "event_id": str(uuid4()),
            "event_type": "user.created",
            "timestamp": "2025-01-21T10:00:00Z",
            "version": 1,
            "payload": {
                "user_id": str(uuid4()),
                "username": "newuser",
                "email": "new@example.com",
            },
        }

        await handle_user_created(event_data, db_session)

        # Verify profile was created
        result = await db_session.execute(
            select(Profile).where(Profile.username == "newuser")
        )
        profile = result.scalar_one()
        assert profile is not None
        assert profile.reputation_score == Decimal("0.00")

    async def test_idempotent(self, db_session: AsyncSession):
        """Processing same event twice should not fail."""
        user_id = str(uuid4())
        event_data = {
            "event_id": str(uuid4()),
            "event_type": "user.created",
            "timestamp": "2025-01-21T10:00:00Z",
            "version": 1,
            "payload": {
                "user_id": user_id,
                "username": "testuser",
                "email": "test@example.com",
            },
        }

        await handle_user_created(event_data, db_session)
        # Second call should not raise
        await handle_user_created(event_data, db_session)


class TestReputationUpdatedHandler:
    """Test reputation.updated event handler."""

    async def test_updates_score(self, db_session: AsyncSession):
        # First create profile
        user_id = uuid4()
        profile = Profile(
            user_id=user_id,
            username="testuser",
            reputation_score=Decimal("0.00"),
            reputation_breakdown={},
        )
        db_session.add(profile)
        await db_session.commit()

        # Send reputation update
        event_data = {
            "event_id": str(uuid4()),
            "event_type": "reputation.updated",
            "timestamp": "2025-01-21T10:00:00Z",
            "version": 1,
            "payload": {
                "user_id": str(user_id),
                "new_score": "4.50",
                "delta": "4.50",
                "breakdown": {"peer_rating": 4.5, "curator_rating": 0, "technical": 0},
                "reason": "peer_rating_received",
            },
        }

        await handle_reputation_updated(event_data, db_session)

        # Verify update
        await db_session.refresh(profile)
        assert profile.reputation_score == Decimal("4.50")
        assert profile.reputation_breakdown["peer_rating"] == 4.5

    async def test_idempotent(self, db_session: AsyncSession):
        """Duplicate events should not update score twice."""
        user_id = uuid4()
        event_id = uuid4()

        profile = Profile(
            user_id=user_id,
            username="testuser2",
            reputation_score=Decimal("0.00"),
            reputation_breakdown={},
        )
        db_session.add(profile)
        await db_session.commit()

        event_data = {
            "event_id": str(event_id),
            "event_type": "reputation.updated",
            "timestamp": "2025-01-21T10:00:00Z",
            "version": 1,
            "payload": {
                "user_id": str(user_id),
                "new_score": "1.00",
                "delta": "1.00",
                "breakdown": {},
                "reason": "test",
            },
        }

        await handle_reputation_updated(event_data, db_session)
        await handle_reputation_updated(event_data, db_session)

        # Should only have one history entry
        result = await db_session.execute(
            select(ReputationHistory).where(
                ReputationHistory.source_event_id == event_id
            )
        )
        entries = result.scalars().all()
        assert len(entries) == 1
