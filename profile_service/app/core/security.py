"""JWT authentication and security utilities."""

from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings

bearer_scheme = HTTPBearer(auto_error=True)


class CurrentUser:
    """Represents the authenticated user from JWT."""

    def __init__(self, user_id: UUID, email: str | None = None, roles: list[str] | None = None):
        self.user_id = user_id
        self.email = email
        self.roles = roles or []

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Validate JWT and return current user.

    Performs stateless validation using the Auth Service's public key.
    Does NOT call Auth Service - decoupled validation.
    """
    token = credentials.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "INVALID_TOKEN", "message": "Invalid or expired token"},
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )

        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception

        return CurrentUser(
            user_id=UUID(user_id_str),
            email=payload.get("email"),
            roles=payload.get("roles", []),
        )

    except JWTError:
        raise credentials_exception
    except ValueError:
        # Invalid UUID in subject
        raise credentials_exception


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        HTTPBearer(auto_error=False)
    ),
) -> CurrentUser | None:
    """
    Optionally validate JWT - returns None if no token provided.

    Useful for endpoints that behave differently for authenticated vs anonymous.
    """
    if credentials is None:
        return None

    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None
