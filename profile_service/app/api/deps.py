"""API dependencies for dependency injection."""

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db

# Type aliases for cleaner endpoint signatures
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthenticatedUser = Annotated[CurrentUser, Depends(get_current_user)]
