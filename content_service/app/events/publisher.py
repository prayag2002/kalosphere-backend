"""Redis Streams event publisher.

Publishes events for other services to consume (e.g., Quality Scoring Service).
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from redis import asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    """Lazy-initialize Redis connection for publishing."""
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def publish_event(event_type: str, payload: dict[str, Any]) -> None:
    """
    Publish an event to Redis Streams.

    Event format matches the Auth Service's format for consistency:
    {
        "event_id": "<uuid>",
        "event_type": "<type>",
        "timestamp": "<iso8601>",
        "version": 1,
        "payload": { ... }
    }
    """
    try:
        redis = await _get_redis()

        event = {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "payload": payload,
        }

        stream = f"{settings.event_stream_prefix}:events"
        await redis.xadd(stream, {"payload": json.dumps(event)})

        logger.info("Published event %s: %s", event_type, payload)

    except Exception as exc:
        logger.error("Failed to publish event %s: %s", event_type, exc)
        # Don't raise — event publishing is fire-and-forget


async def close_publisher() -> None:
    """Close publisher Redis connection."""
    global _redis
    if _redis:
        await _redis.close()
        _redis = None
