"""Generate a test JWT for local API testing."""

from datetime import datetime, timedelta, timezone
from jose import jwt
import uuid
import sys

# Use a simple secret for local testing (NOT for production)
SECRET = "test-secret-key-for-local-development-only"


def generate_token(user_id: str | None = None) -> tuple[str, str]:
    """Generate a test JWT token."""
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
    
    print(f"\n{'='*60}")
    print("TEST JWT TOKEN GENERATED")
    print(f"{'='*60}")
    print(f"\nUser ID: {user_id}")
    print(f"\nToken:\n{token}")
    print(f"\n{'='*60}")
    print("\nTo use with curl:")
    print(f'curl -H "Authorization: Bearer {token}" http://localhost:8001/api/v1/profiles/me')
    print(f"\n{'='*60}")
    
    return token, user_id


if __name__ == "__main__":
    user_id = sys.argv[1] if len(sys.argv) > 1 else None
    generate_token(user_id)
