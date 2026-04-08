"""Interaction schemas - comments and likes."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Comments ---


class CommentCreate(BaseModel):
    """Schema for creating a comment."""

    body: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Comment text",
    )
    parent_id: UUID | None = Field(
        None,
        description="Parent comment ID for threaded replies",
    )


class CommentUpdate(BaseModel):
    """Schema for updating a comment (owner only)."""

    body: str = Field(
        ...,
        min_length=1,
        max_length=2000,
    )


class CommentResponse(BaseModel):
    """Single comment response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    post_id: UUID
    author_id: UUID
    parent_id: UUID | None = None
    body: str
    created_at: datetime
    updated_at: datetime
    replies: list["CommentResponse"] = Field(default_factory=list)


class CommentListResponse(BaseModel):
    """Paginated list of comments."""

    items: list[CommentResponse]
    total: int
    has_more: bool = False


# --- Likes ---


class LikeStatusResponse(BaseModel):
    """Like status for current user + total count."""

    is_liked: bool = False
    like_count: int = 0
