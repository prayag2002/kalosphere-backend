"""Custom exceptions and exception handlers."""

from typing import Any, Optional

from fastapi import HTTPException, status


class ProfileServiceError(Exception):
    """Base exception for Profile Service."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class ProfileNotFoundError(ProfileServiceError):
    """Profile does not exist."""

    def __init__(self, user_id: str):
        super().__init__(f"Profile not found for user: {user_id}")
        self.user_id = user_id


class UsernameAlreadyTakenError(ProfileServiceError):
    """Username is already in use."""

    def __init__(self, username: str):
        super().__init__(f"Username already taken: {username}")
        self.username = username


class InvalidAvatarError(ProfileServiceError):
    """Avatar validation failed."""

    def __init__(self, reason: str):
        super().__init__(f"Invalid avatar: {reason}")
        self.reason = reason


class EventProcessingError(ProfileServiceError):
    """Failed to process an event."""

    def __init__(self, event_id: str, reason: str):
        super().__init__(f"Failed to process event {event_id}: {reason}")
        self.event_id = event_id
        self.reason = reason


# HTTP Exception helpers
def http_profile_not_found() -> HTTPException:
    """Return 404 for profile not found."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "PROFILE_NOT_FOUND", "message": "Profile not found"},
    )


def http_username_taken() -> HTTPException:
    """Return 409 for username conflict."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "USERNAME_TAKEN", "message": "Username is already taken"},
    )


def http_forbidden() -> HTTPException:
    """Return 403 for forbidden access."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "FORBIDDEN", "message": "Access denied"},
    )


def http_invalid_avatar(reason: str) -> HTTPException:
    """Return 400 for invalid avatar."""
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"code": "INVALID_AVATAR", "message": reason},
    )
