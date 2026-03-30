# Kalosphere Profile Service

Production-ready Profile Service built with FastAPI for the Kalosphere platform.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your settings

# Run migrations
alembic upgrade head

# Start server
uvicorn app.main:app --reload
```

## Environment Variables

```env
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/profile_service
REDIS_URL=redis://localhost:6379/0
JWT_PUBLIC_KEY=<your-public-key>
JWT_ALGORITHM=RS256
CDN_BASE_URL=https://cdn.kalosphere.com
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/profiles/me` | Get own profile with score |
| PATCH | `/api/v1/profiles/me` | Update profile |
| PUT | `/api/v1/profiles/me/avatar` | Upload avatar |
| DELETE | `/api/v1/profiles/me/avatar` | Remove avatar |
| GET | `/api/v1/profiles/me/preferences` | Get preferences |
| PATCH | `/api/v1/profiles/me/preferences` | Update preferences |
| GET | `/api/v1/profiles/{user_id}` | View public profile |
| GET | `/api/v1/profiles/me/reputation/history` | Reputation history |

## Testing

```bash
pytest tests/ -v --cov=app
```

## Project Structure

```
profile_service/
├── app/
│   ├── main.py              # FastAPI application
│   ├── core/                # Configuration, security
│   ├── api/v1/              # API endpoints
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic
│   ├── events/              # Event consumer
│   └── db/                  # Database session
├── tests/
├── alembic.ini
└── requirements.txt
```
