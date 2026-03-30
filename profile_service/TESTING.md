# Testing the Profile Service

## Testing Strategies

The Profile Service can be tested **independently** without running the Auth Service.

---

## 1. Automated Tests (No Auth Service Needed)

The test suite mocks authentication entirely.

```bash
cd profile_service
source .venv/Scripts/activate

# Install test dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=app --cov-report=term-missing
```

### What's Tested
- `test_profiles.py` — Profile CRUD, preferences
- `test_events.py` — Event handlers (user.created, reputation.updated)

---

## 2. Manual API Testing (Swagger UI)

### Step 1: Generate a Test JWT

Create a test token script:

```python
# scripts/generate_test_token.py
from datetime import datetime, timedelta, timezone
from jose import jwt
import uuid

# Use a simple secret for local testing (NOT for production)
SECRET = "test-secret-key-for-local-development-only"

def generate_token(user_id: str | None = None):
    user_id = user_id or str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "email": "test@example.com",
        "roles": ["user"],
        "aud": "kalosphere",
        "iss": "kalosphere-auth",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    print(f"User ID: {user_id}")
    print(f"Token: {token}")
    return token, user_id

if __name__ == "__main__":
    generate_token()
```

### Step 2: Update Config for Test Mode

Add to your `.env`:
```env
JWT_PUBLIC_KEY=test-secret-key-for-local-development-only
JWT_ALGORITHM=HS256
```

### Step 3: Create Profile & Test

```bash
# Generate token
python scripts/generate_test_token.py
# Output: User ID: abc-123...  Token: eyJ...

# Create profile first (simulating user.created event)
# Use psql or the event handler

# Or insert directly via SQL:
psql -h localhost -p 5433 -U postgres -d profile_service -c "
INSERT INTO profiles (user_id, username, reputation_score, reputation_breakdown)
VALUES ('YOUR_USER_ID', 'testuser', 0.00, '{}');
INSERT INTO user_preferences (user_id, preferences)
VALUES ('YOUR_USER_ID', '{}');
"

# Test endpoints
TOKEN="eyJ..."

curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/v1/profiles/me
curl -X PATCH -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"bio": "Hello world"}' \
     http://localhost:8001/api/v1/profiles/me
```

### Step 4: Use Swagger UI

1. Open http://localhost:8001/docs
2. Click "Authorize" button
3. Paste your token
4. Test endpoints interactively

---

## 3. Testing Event Handlers

### Simulate Events via Redis

```python
# scripts/simulate_events.py
import asyncio
import json
import uuid
from datetime import datetime, timezone
from redis import asyncio as aioredis

async def publish_user_created(username: str):
    redis = aioredis.from_url("redis://localhost:6380")
    
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "user.created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "payload": {
            "user_id": str(uuid.uuid4()),
            "username": username,
            "email": f"{username}@example.com",
        }
    }
    
    await redis.xadd(
        "kalosphere:events",
        {"payload": json.dumps(event)}
    )
    print(f"Published user.created for {username}")
    print(f"User ID: {event['payload']['user_id']}")
    await redis.close()

async def publish_reputation_update(user_id: str, delta: float, new_score: float):
    redis = aioredis.from_url("redis://localhost:6380")
    
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "reputation.updated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "payload": {
            "user_id": user_id,
            "new_score": str(new_score),
            "delta": str(delta),
            "breakdown": {"peer_rating": new_score, "curator_rating": 0, "technical": 0},
            "reason": "peer_rating_received",
        }
    }
    
    await redis.xadd(
        "kalosphere:events",
        {"payload": json.dumps(event)}
    )
    print(f"Published reputation.updated: +{delta} -> {new_score}")
    await redis.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python simulate_events.py <user|reputation> [args]")
        sys.exit(1)
    
    if sys.argv[1] == "user":
        username = sys.argv[2] if len(sys.argv) > 2 else "testuser"
        asyncio.run(publish_user_created(username))
    elif sys.argv[1] == "reputation":
        user_id = sys.argv[2]
        delta = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
        score = float(sys.argv[4]) if len(sys.argv) > 4 else delta
        asyncio.run(publish_reputation_update(user_id, delta, score))
```

### Usage

```bash
# Create user via event
python scripts/simulate_events.py user johndoe
# Output: User ID: abc-123...

# Update reputation
python scripts/simulate_events.py reputation abc-123... 4.5 4.5
```

---

## 4. Full Integration with Auth Service

If you want to test with the real Auth Service:

### Step 1: Run Auth Service
```bash
cd ../auth_service
python manage.py runserver 8000
```

### Step 2: Get Public Key from Auth Service

Export the JWT public key from Auth Service and add to Profile Service `.env`:
```env
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
<actual-public-key-from-auth-service>
-----END PUBLIC KEY-----"
JWT_ALGORITHM=RS256
```

### Step 3: Login and Get Token
```bash
# Register
curl -X POST http://localhost:8000/api/auth/register/ \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "username": "testuser", "password": "SecurePass123!"}'

# Login
curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "SecurePass123!"}'
# Returns: {"access": "eyJ...", "refresh": "..."}
```

### Step 4: Use Token with Profile Service
```bash
TOKEN="<access-token-from-login>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/v1/profiles/me
```

---

## Quick Reference

| Testing Type | Auth Service Required | How |
|--------------|----------------------|-----|
| Unit tests | ❌ | `pytest tests/` |
| Swagger UI | ❌ | Mock JWT with HS256 |
| Event testing | ❌ | Redis event simulation |
| Full integration | ✅ | Real JWT from Auth Service |

---

## Troubleshooting

### "Invalid or expired token"
- Check `JWT_ALGORITHM` matches token type (HS256 for test, RS256 for prod)
- Check `JWT_PUBLIC_KEY` matches the secret/key used to sign

### "Profile not found"
- Profile must exist before calling `/me`
- Either insert via SQL or publish `user.created` event

### Connection refused
- Ensure Docker containers are running: `docker-compose ps`
- Check ports: postgres=5433, redis=6380
