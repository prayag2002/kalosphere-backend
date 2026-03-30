"""Profile model - core user profile data."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class Profile(Base, TimestampMixin):
    """
    User profile model.

    Owns: username, bio, avatar, reputation (read model).
    user_id comes from Auth Service - no FK constraint (cross-service boundary).
    """

    __tablename__ = "profiles"

    # Primary key - UUID from Auth Service
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )

    # Profile fields
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    avatar_key: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Reputation - read model updated via events
    reputation_score: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        default=Decimal("0.00"),
        nullable=False,
    )
    reputation_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Soft delete
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    preferences: Mapped["UserPreferences"] = relationship(
        "UserPreferences",
        back_populates="profile",
        uselist=False,
        lazy="selectin",
    )
    reputation_history: Mapped[list["ReputationHistory"]] = relationship(
        "ReputationHistory",
        back_populates="profile",
        lazy="dynamic",
    )

    __table_args__ = (
        # Partial index for active profiles
        Index(
            "idx_profiles_username_active",
            "username",
            postgresql_where=deleted_at.is_(None),
        ),
        Index(
            "idx_profiles_reputation",
            reputation_score.desc(),
            postgresql_where=deleted_at.is_(None),
        ),
    )

    def __repr__(self) -> str:
        return f"<Profile {self.username} ({self.user_id})>"

    @property
    def is_deleted(self) -> bool:
        """Check if profile is soft-deleted."""
        return self.deleted_at is not None


# Import for type hints - avoid circular import
from app.models.preferences import UserPreferences  # noqa: E402
from app.models.reputation import ReputationHistory  # noqa: E402
