"""Redis Streams event consumer.

Designed with abstraction to allow Kafka swap in the future.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Coroutine

from redis import asyncio as aioredis

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.events.handlers import EVENT_HANDLERS

logger = logging.getLogger(__name__)

# Type for async handler functions
HandlerFunc = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class EventConsumer(ABC):
    """Abstract base for event consumers."""

    @abstractmethod
    async def consume(self) -> None:
        """Start consuming events."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop consuming events."""
        ...


class RedisStreamConsumer(EventConsumer):
    """
    Redis Streams consumer implementation.

    Uses consumer groups for at-least-once delivery.
    Swap for KafkaConsumer when scaling.
    """

    def __init__(
        self,
        redis_url: str,
        stream: str,
        group: str,
        consumer_name: str,
    ):
        self.redis_url = redis_url
        self.stream = stream
        self.group = group
        self.consumer_name = consumer_name
        self.redis: aioredis.Redis | None = None
        self._running = False

    async def _ensure_group(self) -> None:
        """Create consumer group if it doesn't exist."""
        if not self.redis:
            return

        try:
            await self.redis.xgroup_create(
                self.stream,
                self.group,
                id="0",
                mkstream=True,
            )
            logger.info(f"Created consumer group {self.group} for stream {self.stream}")
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
            # Group already exists, that's fine

    async def consume(self) -> None:
        """Start consuming events from Redis Stream."""
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        await self._ensure_group()

        self._running = True
        logger.info(f"Starting Redis consumer: {self.consumer_name}")

        while self._running:
            try:
                messages = await self.redis.xreadgroup(
                    self.group,
                    self.consumer_name,
                    {self.stream: ">"},
                    count=10,
                    block=5000,
                )

                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        await self._process_message(message_id, data)

            except asyncio.CancelledError:
                logger.info("Consumer cancelled")
                break
            except Exception as e:
                logger.error(f"Error consuming events: {e}")
                await asyncio.sleep(1)

        if self.redis:
            await self.redis.close()

    async def _process_message(
        self, message_id: str, data: dict[str, str]
    ) -> None:
        """Process a single message."""
        try:
            # Parse event data
            event_data = json.loads(data.get("payload", "{}"))
            event_type = event_data.get("event_type")

            handler = EVENT_HANDLERS.get(event_type)
            if not handler:
                logger.warning(f"No handler for event type: {event_type}")
                # Still ACK to avoid blocking
                await self.redis.xack(self.stream, self.group, message_id)  # type: ignore
                return

            # Process with database session
            async with AsyncSessionLocal() as db:
                await handler(event_data, db)

            # Acknowledge successful processing
            await self.redis.xack(self.stream, self.group, message_id)  # type: ignore
            logger.debug(f"Processed event {message_id}: {event_type}")

        except Exception as e:
            logger.error(f"Failed to process message {message_id}: {e}")
            # Don't ACK - message will be redelivered
            # TODO: Implement dead-letter queue after N retries

    async def stop(self) -> None:
        """Stop the consumer."""
        self._running = False


def get_consumer() -> EventConsumer:
    """Factory to get appropriate event consumer."""
    # Future: check settings.USE_KAFKA and return KafkaConsumer
    return RedisStreamConsumer(
        redis_url=settings.redis_url,
        stream=f"{settings.event_stream_prefix}:events",
        group=settings.consumer_group,
        consumer_name=f"{settings.consumer_group}-1",
    )


async def start_event_consumer() -> None:
    """Start the event consumer as a background task."""
    consumer = get_consumer()
    try:
        await consumer.consume()
    except asyncio.CancelledError:
        await consumer.stop()
