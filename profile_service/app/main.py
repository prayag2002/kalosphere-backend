"""FastAPI application factory and lifespan management."""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import (
    InvalidAvatarError,
    ProfileNotFoundError,
    ProfileServiceError,
    UsernameAlreadyTakenError,
)
from app.events.consumer import start_event_consumer

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - startup and shutdown."""
    # Startup
    logger.info("Starting Profile Service...")

    # Start event consumer in background
    consumer_task = asyncio.create_task(start_event_consumer())

    yield

    # Shutdown
    logger.info("Shutting down Profile Service...")
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Kalosphere Profile Service",
        description="Profile management service for Kalosphere platform",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure properly in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routers
    app.include_router(api_router, prefix="/api/v1")

    # Exception handlers
    @app.exception_handler(ProfileNotFoundError)
    async def profile_not_found_handler(
        request: Request, exc: ProfileNotFoundError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"code": "PROFILE_NOT_FOUND", "message": exc.message},
        )

    @app.exception_handler(UsernameAlreadyTakenError)
    async def username_taken_handler(
        request: Request, exc: UsernameAlreadyTakenError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"code": "USERNAME_TAKEN", "message": exc.message},
        )

    @app.exception_handler(InvalidAvatarError)
    async def invalid_avatar_handler(
        request: Request, exc: InvalidAvatarError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": "INVALID_AVATAR", "message": exc.message},
        )

    @app.exception_handler(ProfileServiceError)
    async def service_error_handler(
        request: Request, exc: ProfileServiceError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": "SERVICE_ERROR", "message": exc.message},
        )

    # Health check
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": "profile-service"}

    return app


# Application instance
app = create_app()