"""Preferences service."""

from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProfileNotFoundError
from app.models.preferences import UserPreferences
from app.schemas.preferences import PreferencesResponse, PreferencesUpdate


class PreferencesService:
    """Service for user preferences operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, user_id: UUID) -> PreferencesResponse:
        """Get user preferences."""
        prefs = await self.db.get(UserPreferences, user_id)
        if not prefs:
            raise ProfileNotFoundError(str(user_id))

        return PreferencesResponse.from_jsonb(prefs.preferences)

    async def update(
        self, user_id: UUID, data: PreferencesUpdate
    ) -> PreferencesResponse:
        """Update user preferences."""
        prefs = await self.db.get(UserPreferences, user_id)
        if not prefs:
            raise ProfileNotFoundError(str(user_id))

        # Merge updates into existing preferences
        update_data = data.model_dump(exclude_unset=True)
        new_prefs = {**prefs.preferences, **update_data}

        await self.db.execute(
            update(UserPreferences)
            .where(UserPreferences.user_id == user_id)
            .values(preferences=new_prefs)
        )
        await self.db.commit()

        return PreferencesResponse.from_jsonb(new_prefs)
