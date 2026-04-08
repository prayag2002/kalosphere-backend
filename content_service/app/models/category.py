"""Category model - dynamic content categories.

Categories are not hardcoded enums — they are stored in the database and can grow
over time. Initial categories are seeded via migration. Tags that gain enough traction
can graduate to become categories in the future.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Category(Base):
    """
    Content category — top-level classification for posts.

    Examples: Photography, Digital Art, Music, Film, etc.
    Designed to grow organically — not a fixed enum.
    """

    __tablename__ = "categories"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_order: Mapped[int] = mapped_column(
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
    tags: Mapped[list["Tag"]] = relationship(
        "Tag",
        back_populates="category",
        lazy="selectin",
        order_by="Tag.name",
    )

    def __repr__(self) -> str:
        return f"<Category {self.name}>"


# Import for type hints
from app.models.tag import Tag  # noqa: E402, F401
