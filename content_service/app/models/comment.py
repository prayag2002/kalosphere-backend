"""Comment model - threaded comments on posts."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class Comment(Base, TimestampMixin):
    """
    Comment on a post.

    Supports threaded replies via parent_id self-reference.
    author_id comes from JWT - no FK constraint (cross-service boundary).
    """

    __tablename__ = "comments"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    # Which post this comment belongs to
    post_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("posts.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Author — no FK (cross-service boundary)
    author_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )

    # Threading: null = top-level comment, non-null = reply
    parent_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("comments.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Content
    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Soft delete
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    post: Mapped["Post"] = relationship(
        "Post",
        back_populates="comments",
    )
    replies: Mapped[list["Comment"]] = relationship(
        "Comment",
        back_populates="parent",
        lazy="selectin",
    )
    parent: Mapped["Comment | None"] = relationship(
        "Comment",
        back_populates="replies",
        remote_side=[id],
    )

    __table_args__ = (
        # Fetch comments for a post in chronological order
        Index(
            "idx_comments_post_time",
            "post_id",
            created_at.desc(),
            postgresql_where=deleted_at.is_(None),
        ),
        # Fetch replies for a parent comment
        Index(
            "idx_comments_parent",
            "parent_id",
            created_at.asc(),
            postgresql_where=deleted_at.is_(None),
        ),
    )

    def __repr__(self) -> str:
        return f"<Comment {self.id} on post {self.post_id}>"

    @property
    def is_deleted(self) -> bool:
        """Check if comment is soft-deleted."""
        return self.deleted_at is not None

    @property
    def is_reply(self) -> bool:
        """Check if this is a reply to another comment."""
        return self.parent_id is not None


# Import for type hints
from app.models.post import Post  # noqa: E402, F401
