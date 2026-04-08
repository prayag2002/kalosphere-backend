"""Tag model - subcategories linked to categories.

Tags act as subcategories, not random hashtags like Instagram.
Each tag belongs to a specific category. If a tag gains enough traction,
it can be promoted to a full category in the future.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Tag(Base):
    """
    Content tag — subcategory within a parent category.

    Unlike Instagram hashtags, these are curated subcategories.
    Example: Category "Photography" → Tags: "Landscape", "Portrait", "Street".
    """

    __tablename__ = "tags"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    category_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("categories.id", ondelete="CASCADE"),
        nullable=False,
    )
    post_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    category: Mapped["Category"] = relationship(
        "Category",
        back_populates="tags",
    )

    __table_args__ = (
        # Unique tag name within a category
        {"comment": "Tags are unique within their parent category"},
    )

    def __repr__(self) -> str:
        return f"<Tag {self.name} (category={self.category_id})>"


# Import for type hints
from app.models.category import Category  # noqa: E402, F401
