"""Profile schemas for API request/response."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ProfileBase(BaseModel):
    """Base profile fields."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Unique username (alphanumeric + underscore)",
    )
    bio: str | None = Field(None, max_length=500)


class ProfileCreate(ProfileBase):
    """Schema for creating a profile (internal, via event)."""

    user_id: UUID


class ProfileUpdate(BaseModel):
    """Schema for updating own profile."""

    username: str | None = Field(
        None,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_]+$",
    )
    bio: str | None = Field(None, max_length=500)


class ProfilePublicResponse(BaseModel):
    """
    Public profile view - what others see.

    IMPORTANT: Does NOT include reputation score.
    """

    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    username: str
    bio: str | None
    avatar_url: HttpUrl | None = None
    created_at: datetime


class ProfilePrivateResponse(ProfilePublicResponse):
    """
    Private profile view - what the owner sees.

    Includes reputation score and breakdown.
    """

    reputation_score: Decimal
    reputation_breakdown: dict[str, Any] = Field(default_factory=dict)


class AvatarUploadResponse(BaseModel):
    """Response after avatar upload."""

    avatar_url: HttpUrl
    message: str = "Avatar uploaded successfully"
