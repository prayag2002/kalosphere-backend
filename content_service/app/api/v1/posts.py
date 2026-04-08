"""Post API endpoints."""

from uuid import UUID

from fastapi import APIRouter, File, Form, Query, UploadFile, status

from app.api.deps import AuthenticatedUser, DBSession, OptionalUser
from app.core.exceptions import (
    InvalidMediaError,
    NotPostOwnerError,
    PostNotFoundError,
    RateLimitExceededError,
    http_invalid_media,
    http_not_post_owner,
    http_post_not_found,
    http_rate_limit_exceeded,
)
from app.schemas.post import (
    PostListResponse,
    PostResponse,
    PostUpdate,
)
from app.services.media_service import MediaService
from app.services.post_service import PostService
from app.services.rate_limiter import rate_limiter

router = APIRouter()


@router.post("", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
async def create_post(
    db: DBSession,
    current_user: AuthenticatedUser,
    file: UploadFile = File(..., description="Media file to upload"),
    title: str = Form(..., min_length=1, max_length=200),
    description: str | None = Form(None, max_length=5000),
    category_id: str = Form(..., description="Category UUID"),
    tag_ids: str = Form("", description="Comma-separated tag UUIDs"),
    post_status: str = Form("published", description="draft or published"),
) -> PostResponse:
    """
    Create a new post with media upload.

    Rate limited: max posts per day per user (configurable).
    Automatically optimizes images and generates thumbnails.
    """
    # Rate limiting
    try:
        await rate_limiter.check_post_rate_limit(str(current_user.user_id))
    except RateLimitExceededError as e:
        raise http_rate_limit_exceeded(e.action, e.retry_after)

    # Parse form data
    from app.schemas.post import PostCreate

    parsed_tag_ids = []
    if tag_ids.strip():
        parsed_tag_ids = [UUID(t.strip()) for t in tag_ids.split(",") if t.strip()]

    data = PostCreate(
        title=title,
        description=description,
        category_id=UUID(category_id),
        tag_ids=parsed_tag_ids,
        status=post_status if post_status in ("draft", "published") else "published",
    )

    # Upload media
    content = await file.read()
    content_type = file.content_type or "application/octet-stream"

    media_service = MediaService()
    try:
        media_key, thumbnail_key = await media_service.upload(
            current_user.user_id,
            content,
            content_type,
        )
    except InvalidMediaError as e:
        raise http_invalid_media(e.reason)

    # Create post
    post_service = PostService(db)
    post = await post_service.create(
        author_id=current_user.user_id,
        data=data,
        media_key=media_key,
        media_type=content_type,
        thumbnail_key=thumbnail_key,
    )

    # Publish post.created event (fire-and-forget)
    try:
        from app.events.publisher import publish_event

        await publish_event("post.created", {
            "post_id": str(post.id),
            "author_id": str(post.author_id),
            "title": post.title,
            "category_id": str(post.category_id),
            "media_type": post.media_type,
        })
    except Exception:
        pass  # Don't fail the request if event publishing fails

    return post_service.to_response(post)


@router.get("", response_model=PostListResponse)
async def list_posts(
    db: DBSession,
    current_user: OptionalUser,
    category_id: UUID | None = Query(None),
    sort: str = Query("recent", pattern="^(recent|popular|trending)$"),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
) -> PostListResponse:
    """
    List published posts (public feed).

    Supports filtering by category and sorting by recent, popular, or trending.
    """
    service = PostService(db)
    return await service.list_published(
        limit=limit,
        offset=offset,
        category_id=category_id,
        sort=sort,
    )


@router.get("/me", response_model=PostListResponse)
async def list_my_posts(
    db: DBSession,
    current_user: AuthenticatedUser,
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
) -> PostListResponse:
    """List current user's posts (includes drafts)."""
    service = PostService(db)
    return await service.list_by_author(
        author_id=current_user.user_id,
        include_drafts=True,
        limit=limit,
        offset=offset,
    )


@router.get("/user/{user_id}", response_model=PostListResponse)
async def list_user_posts(
    user_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
) -> PostListResponse:
    """List a user's published posts."""
    service = PostService(db)
    return await service.list_by_author(
        author_id=user_id,
        include_drafts=False,
        limit=limit,
        offset=offset,
    )


@router.get("/{post_id}", response_model=PostResponse)
async def get_post(
    post_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> PostResponse:
    """
    Get a single post by ID.

    Increments view counter on each request.
    """
    service = PostService(db)
    post = await service.get_by_id(post_id)

    if not post:
        raise http_post_not_found()

    # Increment view count (fire-and-forget)
    await service.increment_view(post_id)

    # Check like status if authenticated
    is_liked = False
    if current_user:
        from app.services.interaction_service import InteractionService

        interaction_service = InteractionService(db)
        like_status = await interaction_service.get_like_status(post_id, current_user.user_id)
        is_liked = like_status.is_liked

    return service.to_response(post, is_liked=is_liked)


@router.patch("/{post_id}", response_model=PostResponse)
async def update_post(
    post_id: UUID,
    data: PostUpdate,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> PostResponse:
    """Update a post (owner only)."""
    service = PostService(db)

    try:
        post = await service.update(post_id, current_user.user_id, data)
    except PostNotFoundError:
        raise http_post_not_found()
    except NotPostOwnerError:
        raise http_not_post_owner()

    return service.to_response(post)


@router.delete("/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_post(
    post_id: UUID,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> None:
    """Soft-delete a post (owner only)."""
    service = PostService(db)

    try:
        await service.soft_delete(post_id, current_user.user_id)
    except PostNotFoundError:
        raise http_post_not_found()
    except NotPostOwnerError:
        raise http_not_post_owner()

    # Publish post.deleted event
    try:
        from app.events.publisher import publish_event

        await publish_event("post.deleted", {
            "post_id": str(post_id),
            "author_id": str(current_user.user_id),
        })
    except Exception:
        pass
