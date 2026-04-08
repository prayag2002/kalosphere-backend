"""FastAPI application factory and lifespan management."""

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
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
    logger.info("Starting Content Service...")

    # Start event consumer in background
    consumer_task = asyncio.create_task(start_event_consumer())

    yield

    # Shutdown
    logger.info("Shutting down Content Service...")

    # Close rate limiter Redis connection
    from app.services.rate_limiter import rate_limiter

    await rate_limiter.close()

    # Close event publisher Redis connection
    from app.events.publisher import close_publisher

    await close_publisher()

    # Cancel event consumer
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Kalosphere Content Service",
        description="Content management service for the Kalosphere platform — posts, interactions, and media.",
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

    # Health check
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": "content-service"}

    return app


# Application instance
app = create_app()

# Run directly (default port setup)
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8002,
        reload=True,
    )
