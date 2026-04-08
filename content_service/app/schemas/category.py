"""Category and tag schemas for API request/response."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TagResponse(BaseModel):
    """Tag response - subcategory info."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    category_id: UUID
    post_count: int = 0
    is_active: bool = True


class CategoryResponse(BaseModel):
    """Category response with nested tags."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    description: str | None = None
    display_order: int = 0
    is_active: bool = True
    tags: list[TagResponse] = Field(default_factory=list)
    created_at: datetime


class CategoryListResponse(BaseModel):
    """List of all categories."""

    categories: list[CategoryResponse]
    total: int
