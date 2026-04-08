# Kalosphere Content Service

Content management microservice for the Kalosphere platform. Handles posts (creative works), media uploads, interactions (likes/comments), and content categorization.

## Tech Stack

- **Framework**: FastAPI (async)
- **Database**: PostgreSQL + async SQLAlchemy + Alembic migrations
- **Cache/Events**: Redis (rate limiting + Streams for inter-service events)
- **Storage**: S3-compatible (MinIO for development)
- **Image Processing**: Pillow (resize, thumbnail generation, EXIF fix)
- **Auth**: Stateless JWT validation (RS256 public key from Auth Service)

## Architecture

```
Content Service (Port 8002)
├── API Layer (FastAPI + Pydantic v2)
│   ├── POST /api/v1/posts          — Create post with media upload
│   ├── GET  /api/v1/posts          — Feed (recent/popular/trending)
│   ├── GET  /api/v1/posts/{id}     — Post detail
│   ├── PATCH /api/v1/posts/{id}    — Update (owner only)
│   ├── DELETE /api/v1/posts/{id}   — Soft delete (owner only)
│   ├── POST /api/v1/posts/{id}/like     — Like (rate limited)
│   ├── DELETE /api/v1/posts/{id}/like   — Unlike
│   ├── POST /api/v1/posts/{id}/comments — Comment (rate limited)
│   ├── GET  /api/v1/posts/{id}/comments — List comments
│   ├── GET  /api/v1/categories          — List categories
│   └── GET  /api/v1/categories/{id}/tags — Tags for category
├── Service Layer
│   ├── PostService       — CRUD, feed queries, view counting
│   ├── InteractionService — Likes (idempotent), threaded comments
│   ├── MediaService      — S3 upload, Pillow optimization, thumbnails
│   ├── CategoryService   — Categories and tag management
│   └── RateLimiter       — Redis sliding window rate limiting
├── Event Layer (Redis Streams)
│   ├── Consumer: user.deleted → soft-delete all user posts
│   └── Publisher: post.created, post.liked → future services
└── Data Layer (async SQLAlchemy)
    ├── Categories (dynamic, not enum)
    ├── Tags (subcategories, linked to categories)
    ├── Posts (with denormalized counters)
    ├── Comments (threaded via parent_id)
    └── Likes (unique per user per post)
```

## Quick Start

### Local Development

```bash
# Start infrastructure
docker-compose up -d postgres redis minio

# Create virtualenv & install deps
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Seed categories
python scripts/seed_categories.py

# Start server
uvicorn app.main:app --host 127.0.0.1 --port 8002 --reload
```

### Docker

```bash
docker-compose up --build
```

### API Documentation

When `DEBUG=true`, interactive docs are available at:
- Swagger UI: http://localhost:8002/docs
- ReDoc: http://localhost:8002/redoc

## Rate Limits

| Action | Limit | Window |
|--------|-------|--------|
| Post creation | 10/day | 24 hours |
| Like | 100/hour | 1 hour |
| Comment | 30/hour | 1 hour |

## Port Allocation

| Service | App Port | Postgres | Redis | MinIO |
|---------|----------|----------|-------|-------|
| Auth Service | 8000 | 5432 | 6379 | — |
| Profile Service | 8001 | 5433 | 6380 | 9000/9001 |
| **Content Service** | **8002** | **5434** | **6381** | **9002/9003** |
