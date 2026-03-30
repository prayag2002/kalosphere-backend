"""User preferences model."""

from typing import Any
from uuid import UUID

from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class UserPreferences(Base, TimestampMixin):
    """
    User preferences - separated from Profile for cache efficiency.

    High-frequency reads don't invalidate when profile updates.
    """

    __tablename__ = "user_preferences"

    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("profiles.user_id", ondelete="CASCADE"),
        primary_key=True,
    )

    preferences: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Relationship
    profile: Mapped["Profile"] = relationship(
        "Profile",
        back_populates="preferences",
    )

    def __repr__(self) -> str:
        return f"<UserPreferences ({self.user_id})>"

    def get(self, key: str, default: Any = None) -> Any:
        """Get a preference value with default."""
        return self.preferences.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a preference value."""
        self.preferences[key] = value


# Import for type hints
from app.models.profile import Profile  # noqa: E402, F401
