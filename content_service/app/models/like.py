"""Like model - user likes on posts."""

from datetime import datetime, timezone as tz
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Like(Base):
    """
    Like on a post.

    Unique constraint (post_id, user_id) ensures one like per user per post.
    user_id comes from JWT - no FK constraint (cross-service boundary).
    """

    __tablename__ = "likes"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    post_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("posts.id", ondelete="CASCADE"),
        nullable=False,
    )

    # User who liked — no FK (cross-service boundary)
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(tz.utc),
        nullable=False,
    )

    # Relationships
    post: Mapped["Post"] = relationship(
        "Post",
        back_populates="likes",
    )

    __table_args__ = (
        UniqueConstraint("post_id", "user_id", name="uq_like_post_user"),
    )

    def __repr__(self) -> str:
        return f"<Like user={self.user_id} post={self.post_id}>"


# Import for type hints
from app.models.post import Post  # noqa: E402, F401
