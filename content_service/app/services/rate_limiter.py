"""Rate limiter using Redis sliding window algorithm.

Provides per-user, per-action rate limiting with configurable windows.
Uses Redis sorted sets for a precise sliding window counter.
"""

import logging
import time

from redis import asyncio as aioredis

from app.core.config import settings
from app.core.exceptions import RateLimitExceededError

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Redis-based sliding window rate limiter.

    Uses sorted sets: each member is a unique request ID (timestamp-based),
    scored by the timestamp. On each check, expired entries are pruned,
    and the remaining count determines if the limit is breached.
    """

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis:
        """Lazy-initialize Redis connection."""
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
        return self._redis

    async def check_rate_limit(
        self,
        user_id: str,
        action: str,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        """
        Check if user has exceeded rate limit for a given action.

        Raises RateLimitExceededError if limit is exceeded.

        Args:
            user_id: The user's UUID as string.
            action: Action name (e.g., "post_create", "like", "comment").
            max_requests: Maximum allowed requests within the window.
            window_seconds: Time window in seconds.
        """
        redis = await self._get_redis()
        key = f"rate_limit:{action}:{user_id}"
        now = time.time()
        window_start = now - window_seconds

        pipe = redis.pipeline()

        # Remove expired entries
        pipe.zremrangebyscore(key, "-inf", window_start)

        # Count remaining entries in the window
        pipe.zcard(key)

        # Add the current request
        pipe.zadd(key, {f"{now}:{id(now)}": now})

        # Set TTL on the key to auto-cleanup
        pipe.expire(key, window_seconds + 10)

        results = await pipe.execute()
        current_count = results[1]  # zcard result

        if current_count >= max_requests:
            # Calculate retry-after based on the oldest entry in the window
            oldest = await redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window_seconds - now) + 1
            else:
                retry_after = window_seconds

            # Remove the entry we just added (it shouldn't count)
            await redis.zremrangebyscore(key, now, now + 1)

            raise RateLimitExceededError(action=action, retry_after=max(1, retry_after))

    async def check_post_rate_limit(self, user_id: str) -> None:
        """Check rate limit for post creation."""
        await self.check_rate_limit(
            user_id=user_id,
            action="post_create",
            max_requests=settings.rate_limit_posts_per_day,
            window_seconds=86400,  # 24 hours
        )

    async def check_like_rate_limit(self, user_id: str) -> None:
        """Check rate limit for liking posts."""
        await self.check_rate_limit(
            user_id=user_id,
            action="like",
            max_requests=settings.rate_limit_likes_per_hour,
            window_seconds=3600,  # 1 hour
        )

    async def check_comment_rate_limit(self, user_id: str) -> None:
        """Check rate limit for commenting."""
        await self.check_rate_limit(
            user_id=user_id,
            action="comment",
            max_requests=settings.rate_limit_comments_per_hour,
            window_seconds=3600,  # 1 hour
        )

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None


# Singleton instance
rate_limiter = RateLimiter()
