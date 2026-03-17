"""Profile API endpoints."""

from uuid import UUID

from fastapi import APIRouter, File, Query, UploadFile, status

from app.api.deps import AuthenticatedUser, DBSession
from app.core.exceptions import (
    ProfileNotFoundError,
    UsernameAlreadyTakenError,
    http_profile_not_found,
    http_username_taken,
)
from app.schemas.preferences import PreferencesResponse, PreferencesUpdate
from app.schemas.profile import (
    AvatarUploadResponse,
    ProfilePrivateResponse,
    ProfilePublicResponse,
    ProfileUpdate,
)
from app.schemas.reputation import ReputationHistoryResponse
from app.services.avatar_service import AvatarService
from app.services.preferences_service import PreferencesService
from app.services.profile_service import ProfileService
from app.services.reputation_service import ReputationService

router = APIRouter()


# --- Own Profile Endpoints ---


@router.get("/me", response_model=ProfilePrivateResponse)
async def get_my_profile(
    db: DBSession,
    current_user: AuthenticatedUser,
) -> ProfilePrivateResponse:
    """
    Get current user's profile with reputation score.

    Returns full profile including score breakdown (visible only to owner).
    """
    service = ProfileService(db)
    profile = await service.get_by_user_id(current_user.user_id)

    if not profile:
        raise http_profile_not_found()

    return service.to_private_response(profile)


@router.patch("/me", response_model=ProfilePrivateResponse)
async def update_my_profile(
    data: ProfileUpdate,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> ProfilePrivateResponse:
    """Update current user's profile."""
    service = ProfileService(db)

    try:
        profile = await service.update(current_user.user_id, data)
    except ProfileNotFoundError:
        raise http_profile_not_found()
    except UsernameAlreadyTakenError:
        raise http_username_taken()

    return service.to_private_response(profile)


@router.put("/me/avatar", response_model=AvatarUploadResponse)
async def upload_avatar(
    db: DBSession,
    current_user: AuthenticatedUser,
    file: UploadFile = File(...),
) -> AvatarUploadResponse:
    """Upload or replace avatar."""
    profile_service = ProfileService(db)
    avatar_service = AvatarService()

    # Read file content
    content = await file.read()
    content_type = file.content_type or "application/octet-stream"

    # Upload to storage
    storage_key = await avatar_service.upload(
        current_user.user_id,
        content,
        content_type,
    )

    # Update profile
    profile = await profile_service.update_avatar(current_user.user_id, storage_key)

    avatar_url = profile_service._build_avatar_url(storage_key)
    return AvatarUploadResponse(avatar_url=avatar_url)  # type: ignore


@router.delete("/me/avatar", status_code=status.HTTP_204_NO_CONTENT)
async def delete_avatar(
    db: DBSession,
    current_user: AuthenticatedUser,
) -> None:
    """Remove current avatar."""
    profile_service = ProfileService(db)

    profile = await profile_service.get_by_user_id(current_user.user_id)
    if not profile:
        raise http_profile_not_found()

    # Delete from storage if exists
    if profile.avatar_key:
        avatar_service = AvatarService()
        await avatar_service.delete(current_user.user_id, profile.avatar_key)

    # Clear from profile
    await profile_service.delete_avatar(current_user.user_id)


# --- Preferences Endpoints ---


@router.get("/me/preferences", response_model=PreferencesResponse)
async def get_my_preferences(
    db: DBSession,
    current_user: AuthenticatedUser,
) -> PreferencesResponse:
    """Get current user's preferences."""
    service = PreferencesService(db)

    try:
        return await service.get(current_user.user_id)
    except ProfileNotFoundError:
        raise http_profile_not_found()


@router.patch("/me/preferences", response_model=PreferencesResponse)
async def update_my_preferences(
    data: PreferencesUpdate,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> PreferencesResponse:
    """Update current user's preferences."""
    service = PreferencesService(db)

    try:
        return await service.update(current_user.user_id, data)
    except ProfileNotFoundError:
        raise http_profile_not_found()


# --- Reputation History ---


@router.get("/me/reputation/history", response_model=ReputationHistoryResponse)
async def get_my_reputation_history(
    db: DBSession,
    current_user: AuthenticatedUser,
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0, ge=0),
) -> ReputationHistoryResponse:
    """Get current user's reputation history."""
    service = ReputationService(db)
    return await service.get_history(current_user.user_id, limit=limit, offset=offset)


# --- Public Profile Endpoints ---


@router.get("/{user_id}", response_model=ProfilePublicResponse)
async def get_profile(
    user_id: UUID,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> ProfilePublicResponse:
    """
    Get another user's public profile.

    IMPORTANT: Does NOT include reputation score (privacy by design).
    """
    service = ProfileService(db)
    profile = await service.get_by_user_id(user_id)

    if not profile:
        raise http_profile_not_found()

    return service.to_public_response(profile)
