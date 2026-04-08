"""Custom exceptions and exception handlers."""

from typing import Any, Optional

from fastapi import HTTPException, status


class ContentServiceError(Exception):
    """Base exception for Content Service."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class PostNotFoundError(ContentServiceError):
    """Post does not exist."""

    def __init__(self, post_id: str):
        super().__init__(f"Post not found: {post_id}")
        self.post_id = post_id


class NotPostOwnerError(ContentServiceError):
    """User is not the owner of the post."""

    def __init__(self, post_id: str, user_id: str):
        super().__init__(f"User {user_id} is not the owner of post {post_id}")
        self.post_id = post_id
        self.user_id = user_id


class CommentNotFoundError(ContentServiceError):
    """Comment does not exist."""

    def __init__(self, comment_id: str):
        super().__init__(f"Comment not found: {comment_id}")
        self.comment_id = comment_id


class NotCommentOwnerError(ContentServiceError):
    """User is not the owner of the comment."""

    def __init__(self, comment_id: str, user_id: str):
        super().__init__(f"User {user_id} is not the owner of comment {comment_id}")
        self.comment_id = comment_id
        self.user_id = user_id


class CategoryNotFoundError(ContentServiceError):
    """Category does not exist."""

    def __init__(self, category_id: str):
        super().__init__(f"Category not found: {category_id}")
        self.category_id = category_id


class InvalidMediaError(ContentServiceError):
    """Media validation failed."""

    def __init__(self, reason: str):
        super().__init__(f"Invalid media: {reason}")
        self.reason = reason


class RateLimitExceededError(ContentServiceError):
    """Rate limit has been exceeded."""

    def __init__(self, action: str, retry_after: int):
        super().__init__(f"Rate limit exceeded for {action}")
        self.action = action
        self.retry_after = retry_after


class EventProcessingError(ContentServiceError):
    """Failed to process an event."""

    def __init__(self, event_id: str, reason: str):
        super().__init__(f"Failed to process event {event_id}: {reason}")
        self.event_id = event_id
        self.reason = reason


# HTTP Exception helpers


def http_post_not_found() -> HTTPException:
    """Return 404 for post not found."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "POST_NOT_FOUND", "message": "Post not found"},
    )


def http_not_post_owner() -> HTTPException:
    """Return 403 for non-owner access."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "NOT_POST_OWNER", "message": "You are not the owner of this post"},
    )


def http_comment_not_found() -> HTTPException:
    """Return 404 for comment not found."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "COMMENT_NOT_FOUND", "message": "Comment not found"},
    )


def http_not_comment_owner() -> HTTPException:
    """Return 403 for non-owner comment access."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "NOT_COMMENT_OWNER", "message": "You are not the owner of this comment"},
    )


def http_category_not_found() -> HTTPException:
    """Return 404 for category not found."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "CATEGORY_NOT_FOUND", "message": "Category not found"},
    )


def http_invalid_media(reason: str) -> HTTPException:
    """Return 400 for invalid media."""
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"code": "INVALID_MEDIA", "message": reason},
    )


def http_rate_limit_exceeded(action: str, retry_after: int) -> HTTPException:
    """Return 429 for rate limit exceeded."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "code": "RATE_LIMIT_EXCEEDED",
            "message": f"Rate limit exceeded for {action}",
            "retry_after": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )


def http_forbidden() -> HTTPException:
    """Return 403 for forbidden access."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "FORBIDDEN", "message": "Access denied"},
    )
