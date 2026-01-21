"""Profile service - business logic for profile operations."""

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from pydantic import HttpUrl
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ProfileNotFoundError, UsernameAlreadyTakenError
from app.models.preferences import UserPreferences
from app.models.profile import Profile
from app.schemas.profile import (
    ProfileCreate,
    ProfilePrivateResponse,
    ProfilePublicResponse,
    ProfileUpdate,
)


class ProfileService:
    """Service for profile CRUD operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _build_avatar_url(self, avatar_key: str | None) -> HttpUrl | None:
        """Build full avatar URL from storage key."""
        if not avatar_key:
            return None
        base = settings.cdn_base_url.rstrip("/")
        return HttpUrl(f"{base}/{avatar_key}")

    async def get_by_user_id(self, user_id: UUID) -> Profile | None:
        """Get profile by user ID."""
        result = await self.db.execute(
            select(Profile).where(
                Profile.user_id == user_id,
                Profile.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> Profile | None:
        """Get profile by username."""
        result = await self.db.execute(
            select(Profile).where(
                Profile.username == username,
                Profile.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def create(self, data: ProfileCreate) -> Profile:
        """
        Create a new profile.

        Called when user.created event is received.
        Uses upsert to handle duplicate events idempotently.
        """
        stmt = (
            insert(Profile)
            .values(
                user_id=data.user_id,
                username=data.username,
                bio=data.bio,
                reputation_score=Decimal("0.00"),
                reputation_breakdown={},
            )
            .on_conflict_do_nothing(index_elements=["user_id"])
        )
        await self.db.execute(stmt)

        # Also create preferences record
        pref_stmt = (
            insert(UserPreferences)
            .values(user_id=data.user_id, preferences={})
            .on_conflict_do_nothing(index_elements=["user_id"])
        )
        await self.db.execute(pref_stmt)

        await self.db.commit()

        return await self.get_by_user_id(data.user_id)  # type: ignore

    async def update(self, user_id: UUID, data: ProfileUpdate) -> Profile:
        """Update profile fields."""
        profile = await self.get_by_user_id(user_id)
        if not profile:
            raise ProfileNotFoundError(str(user_id))

        update_data = data.model_dump(exclude_unset=True)

        # Check username uniqueness if changing
        if "username" in update_data and update_data["username"] != profile.username:
            existing = await self.get_by_username(update_data["username"])
            if existing:
                raise UsernameAlreadyTakenError(update_data["username"])

        if update_data:
            await self.db.execute(
                update(Profile)
                .where(Profile.user_id == user_id)
                .values(**update_data)
            )
            await self.db.commit()
            await self.db.refresh(profile)

        return profile

    async def soft_delete(self, user_id: UUID) -> None:
        """Soft delete a profile (on user.deleted event)."""
        await self.db.execute(
            update(Profile)
            .where(Profile.user_id == user_id)
            .values(deleted_at=datetime.now(timezone.utc))
        )
        await self.db.commit()

    async def update_avatar(self, user_id: UUID, avatar_key: str) -> Profile:
        """Update avatar storage key."""
        profile = await self.get_by_user_id(user_id)
        if not profile:
            raise ProfileNotFoundError(str(user_id))

        await self.db.execute(
            update(Profile)
            .where(Profile.user_id == user_id)
            .values(avatar_key=avatar_key)
        )
        await self.db.commit()
        await self.db.refresh(profile)
        return profile

    async def delete_avatar(self, user_id: UUID) -> Profile:
        """Remove avatar."""
        profile = await self.get_by_user_id(user_id)
        if not profile:
            raise ProfileNotFoundError(str(user_id))

        await self.db.execute(
            update(Profile)
            .where(Profile.user_id == user_id)
            .values(avatar_key=None)
        )
        await self.db.commit()
        await self.db.refresh(profile)
        return profile

    def to_private_response(self, profile: Profile) -> ProfilePrivateResponse:
        """Convert profile to private response (includes score)."""
        return ProfilePrivateResponse(
            user_id=profile.user_id,
            username=profile.username,
            bio=profile.bio,
            avatar_url=self._build_avatar_url(profile.avatar_key),
            created_at=profile.created_at,
            reputation_score=profile.reputation_score,
            reputation_breakdown=profile.reputation_breakdown,
        )

    def to_public_response(self, profile: Profile) -> ProfilePublicResponse:
        """Convert profile to public response (NO score)."""
        return ProfilePublicResponse(
            user_id=profile.user_id,
            username=profile.username,
            bio=profile.bio,
            avatar_url=self._build_avatar_url(profile.avatar_key),
            created_at=profile.created_at,
        )
