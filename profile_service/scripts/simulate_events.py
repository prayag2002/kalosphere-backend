"""Simulate events for testing the event consumer."""

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone

from redis import asyncio as aioredis


REDIS_URL = "redis://localhost:6380"
STREAM_NAME = "kalosphere:events"


async def publish_user_created(username: str) -> str:
    """Publish a user.created event."""
    redis = aioredis.from_url(REDIS_URL)
    
    user_id = str(uuid.uuid4())
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "user.created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "payload": {
            "user_id": user_id,
            "username": username,
            "email": f"{username}@example.com",
        }
    }
    
    await redis.xadd(STREAM_NAME, {"payload": json.dumps(event)})
    
    print(f"\n{'='*60}")
    print("USER CREATED EVENT PUBLISHED")
    print(f"{'='*60}")
    print(f"\nUsername: {username}")
    print(f"User ID:  {user_id}")
    print(f"\nThe event consumer will create the profile automatically.")
    print(f"\n{'='*60}")
    
    await redis.close()
    return user_id


async def publish_reputation_update(
    user_id: str, delta: float, new_score: float
) -> None:
    """Publish a reputation.updated event."""
    redis = aioredis.from_url(REDIS_URL)
    
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "reputation.updated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "payload": {
            "user_id": user_id,
            "new_score": str(new_score),
            "delta": str(delta),
            "breakdown": {
                "peer_rating": float(new_score),
                "curator_rating": 0.0,
                "technical": 0.0,
            },
            "reason": "peer_rating_received",
        }
    }
    
    await redis.xadd(STREAM_NAME, {"payload": json.dumps(event)})
    
    print(f"\n{'='*60}")
    print("REPUTATION UPDATED EVENT PUBLISHED")
    print(f"{'='*60}")
    print(f"\nUser ID: {user_id}")
    print(f"Delta:   {delta:+.2f}")
    print(f"Score:   {new_score:.2f}")
    print(f"\n{'='*60}")
    
    await redis.close()


def print_usage():
    print("""
Usage:
  python simulate_events.py user <username>
  python simulate_events.py reputation <user_id> <delta> <new_score>

Examples:
  python simulate_events.py user johndoe
  python simulate_events.py reputation abc-123-uuid 4.5 4.5
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "user":
        username = sys.argv[2] if len(sys.argv) > 2 else "testuser"
        asyncio.run(publish_user_created(username))
    
    elif command == "reputation":
        if len(sys.argv) < 3:
            print("Error: user_id required")
            print_usage()
            sys.exit(1)
        
        user_id = sys.argv[2]
        delta = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
        score = float(sys.argv[4]) if len(sys.argv) > 4 else delta
        asyncio.run(publish_reputation_update(user_id, delta, score))
    
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
