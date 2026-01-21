"""Reputation history model for audit trail."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ReputationHistory(Base):
    """
    Audit log of reputation changes.

    Used for:
    - Trend analysis (user can see score over time)
    - Debugging scoring issues
    - Idempotent event processing via source_event_id
    """

    __tablename__ = "reputation_history"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("profiles.user_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Score change
    score_delta: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    new_score: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )

    # Context
    reason: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    source_event_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,  # Idempotency key
        nullable=False,
    )
    metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship
    profile: Mapped["Profile"] = relationship(
        "Profile",
        back_populates="reputation_history",
    )

    __table_args__ = (
        # For fetching user's history in chronological order
        Index("idx_reputation_user_time", "user_id", created_at.desc()),
    )

    def __repr__(self) -> str:
        return f"<ReputationHistory {self.user_id} {self.score_delta:+.2f}>"


# Import for type hints
from app.models.profile import Profile  # noqa: E402, F401
