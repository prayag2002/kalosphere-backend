"""Post schemas for API request/response."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.schemas.category import CategoryResponse, TagResponse


class PostCreate(BaseModel):
    """Schema for creating a post (metadata only — file uploaded separately)."""

    title: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Title of the creative work",
    )
    description: str | None = Field(None, max_length=5000)
    category_id: UUID = Field(..., description="Category UUID")
    tag_ids: list[UUID] = Field(
        default_factory=list,
        max_length=10,
        description="Tag UUIDs (subcategories, max 10)",
    )
    status: Literal["draft", "published"] = Field(
        default="published",
        description="Initial status: draft or published",
    )


class PostUpdate(BaseModel):
    """Schema for updating a post (owner only)."""

    title: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=5000)
    category_id: UUID | None = None
    tag_ids: list[UUID] | None = Field(None, max_length=10)
    status: Literal["draft", "published", "archived"] | None = None


class PostResponse(BaseModel):
    """Full post response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    author_id: UUID
    title: str
    description: str | None = None
    category: CategoryResponse
    tags: list[TagResponse] = Field(default_factory=list)
    media_url: HttpUrl | None = None
    media_type: str
    thumbnail_url: HttpUrl | None = None
    status: str
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    is_liked: bool = False  # Set per-request based on current user
    published_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class PostSummaryResponse(BaseModel):
    """Lightweight post for feed/list views."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    author_id: UUID
    title: str
    category_name: str
    thumbnail_url: HttpUrl | None = None
    media_type: str
    like_count: int = 0
    comment_count: int = 0
    view_count: int = 0
    is_liked: bool = False
    published_at: datetime | None = None
    created_at: datetime


class PostListResponse(BaseModel):
    """Paginated list of posts."""

    items: list[PostSummaryResponse]
    total: int
    has_more: bool = False
    next_cursor: str | None = None


class PostFeedQuery(BaseModel):
    """Query parameters for feed/listing endpoints."""

    category_id: UUID | None = None
    tag_ids: list[UUID] | None = None
    sort: Literal["recent", "popular", "trending"] = "recent"
    cursor: str | None = None
    limit: int = Field(default=20, ge=1, le=50)
    author_id: UUID | None = None
