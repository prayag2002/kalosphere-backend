"""Post model - core content entity.

A post represents a creative work uploaded by a user. It contains media (image, video, etc.),
metadata (title, description), and is classified by category + tags (subcategories).
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

# Junction table for many-to-many post <-> tag relationship
post_tags = Table(
    "post_tags",
    Base.metadata,
    Column(
        "post_id",
        PG_UUID(as_uuid=True),
        ForeignKey("posts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "tag_id",
        PG_UUID(as_uuid=True),
        ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Post(Base, TimestampMixin):
    """
    Creative work posted by a user.

    author_id comes from Auth Service JWT - no FK constraint (cross-service boundary).
    Denormalized counters (view_count, like_count, comment_count) for read performance.
    """

    __tablename__ = "posts"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    # Author — no FK (cross-service boundary)
    author_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # Content metadata
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Classification
    category_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("categories.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Media storage
    media_key: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    media_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    thumbnail_key: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Status workflow: draft → published → archived/removed
    status: Mapped[str] = mapped_column(
        String(20),
        default="published",
        nullable=False,
        index=True,
    )

    # Denormalized counters for read performance
    view_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    like_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    comment_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    category: Mapped["Category"] = relationship(
        "Category",
        lazy="selectin",
    )
    tags: Mapped[list["Tag"]] = relationship(
        "Tag",
        secondary=post_tags,
        lazy="selectin",
    )
    comments: Mapped[list["Comment"]] = relationship(
        "Comment",
        back_populates="post",
        lazy="dynamic",
    )
    likes: Mapped[list["Like"]] = relationship(
        "Like",
        back_populates="post",
        lazy="dynamic",
    )

    __table_args__ = (
        # Author's published posts (most common query)
        Index(
            "idx_posts_author_published",
            "author_id",
            "status",
            postgresql_where=deleted_at.is_(None),
        ),
        # Category browsing
        Index(
            "idx_posts_category_published",
            "category_id",
            published_at.desc(),
            postgresql_where=deleted_at.is_(None),
        ),
        # Chronological feed
        Index(
            "idx_posts_published_at",
            published_at.desc(),
            postgresql_where=deleted_at.is_(None),
        ),
        # Trending / popular sort
        Index(
            "idx_posts_like_count",
            like_count.desc(),
            postgresql_where=deleted_at.is_(None),
        ),
    )

    def __repr__(self) -> str:
        return f"<Post {self.title[:30]} ({self.id})>"

    @property
    def is_deleted(self) -> bool:
        """Check if post is soft-deleted."""
        return self.deleted_at is not None

    @property
    def is_published(self) -> bool:
        """Check if post is live."""
        return self.status == "published" and not self.is_deleted


# Import for type hints — avoid circular imports
from app.models.category import Category  # noqa: E402, F401
from app.models.comment import Comment  # noqa: E402, F401
from app.models.like import Like  # noqa: E402, F401
from app.models.tag import Tag  # noqa: E402, F401
