"""Interaction API endpoints - likes and comments."""

from uuid import UUID

from fastapi import APIRouter, Query, status

from app.api.deps import AuthenticatedUser, DBSession, OptionalUser
from app.core.exceptions import (
    CommentNotFoundError,
    NotCommentOwnerError,
    PostNotFoundError,
    RateLimitExceededError,
    http_comment_not_found,
    http_not_comment_owner,
    http_post_not_found,
    http_rate_limit_exceeded,
)
from app.schemas.interaction import (
    CommentCreate,
    CommentListResponse,
    CommentResponse,
    CommentUpdate,
    LikeStatusResponse,
)
from app.services.interaction_service import InteractionService
from app.services.rate_limiter import rate_limiter

router = APIRouter()


# --- Likes ---


@router.post("/{post_id}/like", response_model=LikeStatusResponse)
async def like_post(
    post_id: UUID,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> LikeStatusResponse:
    """
    Like a post (idempotent — liking twice has no effect).

    Rate limited: max likes per hour per user.
    """
    try:
        await rate_limiter.check_like_rate_limit(str(current_user.user_id))
    except RateLimitExceededError as e:
        raise http_rate_limit_exceeded(e.action, e.retry_after)

    service = InteractionService(db)

    try:
        result = await service.like_post(post_id, current_user.user_id)
    except PostNotFoundError:
        raise http_post_not_found()

    # Publish post.liked event (for future quality scoring service)
    try:
        from app.events.publisher import publish_event
        from app.services.post_service import PostService

        post_service = PostService(db)
        post = await post_service.get_by_id(post_id)
        if post:
            await publish_event("post.liked", {
                "post_id": str(post_id),
                "author_id": str(post.author_id),
                "liker_id": str(current_user.user_id),
                "like_count": result.like_count,
            })
    except Exception:
        pass

    return result


@router.delete("/{post_id}/like", response_model=LikeStatusResponse)
async def unlike_post(
    post_id: UUID,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> LikeStatusResponse:
    """Unlike a post."""
    service = InteractionService(db)

    try:
        return await service.unlike_post(post_id, current_user.user_id)
    except PostNotFoundError:
        raise http_post_not_found()


@router.get("/{post_id}/like-status", response_model=LikeStatusResponse)
async def get_like_status(
    post_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> LikeStatusResponse:
    """Check if current user liked a post and get total count."""
    service = InteractionService(db)
    user_id = current_user.user_id if current_user else None
    return await service.get_like_status(post_id, user_id)


# --- Comments ---


@router.post(
    "/{post_id}/comments",
    response_model=CommentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_comment(
    post_id: UUID,
    data: CommentCreate,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> CommentResponse:
    """
    Add a comment to a post.

    Set parent_id for threaded replies. Rate limited.
    """
    try:
        await rate_limiter.check_comment_rate_limit(str(current_user.user_id))
    except RateLimitExceededError as e:
        raise http_rate_limit_exceeded(e.action, e.retry_after)

    service = InteractionService(db)

    try:
        return await service.add_comment(post_id, current_user.user_id, data)
    except PostNotFoundError:
        raise http_post_not_found()
    except CommentNotFoundError:
        raise http_comment_not_found()


@router.get("/{post_id}/comments", response_model=CommentListResponse)
async def list_comments(
    post_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
) -> CommentListResponse:
    """List comments for a post (top-level with nested replies)."""
    service = InteractionService(db)
    return await service.list_comments(post_id, limit=limit, offset=offset)


@router.patch("/comments/{comment_id}", response_model=CommentResponse)
async def update_comment(
    comment_id: UUID,
    data: CommentUpdate,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> CommentResponse:
    """Edit a comment (owner only)."""
    service = InteractionService(db)

    try:
        return await service.update_comment(comment_id, current_user.user_id, data)
    except CommentNotFoundError:
        raise http_comment_not_found()
    except NotCommentOwnerError:
        raise http_not_comment_owner()


@router.delete("/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_comment(
    comment_id: UUID,
    db: DBSession,
    current_user: AuthenticatedUser,
) -> None:
    """Soft-delete a comment (owner only)."""
    service = InteractionService(db)

    try:
        await service.delete_comment(comment_id, current_user.user_id)
    except CommentNotFoundError:
        raise http_comment_not_found()
    except NotCommentOwnerError:
        raise http_not_comment_owner()
