"""Interaction service - likes and comments business logic."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import CommentNotFoundError, NotCommentOwnerError, PostNotFoundError
from app.models.comment import Comment
from app.models.like import Like
from app.models.post import Post
from app.schemas.interaction import (
    CommentCreate,
    CommentListResponse,
    CommentResponse,
    CommentUpdate,
    LikeStatusResponse,
)


class InteractionService:
    """Service for likes and comments."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # --- Likes ---

    async def like_post(self, post_id: UUID, user_id: UUID) -> LikeStatusResponse:
        """
        Like a post (idempotent).

        Uses upsert to handle duplicate likes gracefully.
        Increments the denormalized like_count on the post.
        """
        # Verify post exists
        post = await self.db.get(Post, post_id)
        if not post or post.deleted_at is not None:
            raise PostNotFoundError(str(post_id))

        # Upsert like (idempotent)
        stmt = (
            insert(Like)
            .values(post_id=post_id, user_id=user_id)
            .on_conflict_do_nothing(constraint="uq_like_post_user")
        )
        result = await self.db.execute(stmt)

        if result.rowcount > 0:
            # New like — increment counter
            await self.db.execute(
                update(Post)
                .where(Post.id == post_id)
                .values(like_count=Post.like_count + 1)
            )

        await self.db.commit()

        # Get updated count
        count = await self._get_like_count(post_id)

        return LikeStatusResponse(is_liked=True, like_count=count)

    async def unlike_post(self, post_id: UUID, user_id: UUID) -> LikeStatusResponse:
        """
        Unlike a post (idempotent).

        Decrements the denormalized like_count on the post.
        """
        # Verify post exists
        post = await self.db.get(Post, post_id)
        if not post or post.deleted_at is not None:
            raise PostNotFoundError(str(post_id))

        # Delete like
        result = await self.db.execute(
            delete(Like).where(
                Like.post_id == post_id,
                Like.user_id == user_id,
            )
        )

        if result.rowcount > 0:
            # Was liked — decrement counter (floor at 0)
            await self.db.execute(
                update(Post)
                .where(Post.id == post_id, Post.like_count > 0)
                .values(like_count=Post.like_count - 1)
            )

        await self.db.commit()

        count = await self._get_like_count(post_id)

        return LikeStatusResponse(is_liked=False, like_count=count)

    async def get_like_status(
        self, post_id: UUID, user_id: UUID | None = None
    ) -> LikeStatusResponse:
        """Get like status and count for a post."""
        count = await self._get_like_count(post_id)
        is_liked = False

        if user_id:
            result = await self.db.execute(
                select(Like.id).where(
                    Like.post_id == post_id,
                    Like.user_id == user_id,
                )
            )
            is_liked = result.scalar_one_or_none() is not None

        return LikeStatusResponse(is_liked=is_liked, like_count=count)

    async def _get_like_count(self, post_id: UUID) -> int:
        """Get accurate like count from the likes table."""
        result = await self.db.execute(
            select(func.count()).select_from(Like).where(Like.post_id == post_id)
        )
        return result.scalar() or 0

    # --- Comments ---

    async def add_comment(
        self, post_id: UUID, author_id: UUID, data: CommentCreate
    ) -> CommentResponse:
        """Add a comment to a post."""
        # Verify post exists
        post = await self.db.get(Post, post_id)
        if not post or post.deleted_at is not None:
            raise PostNotFoundError(str(post_id))

        # Verify parent comment exists if replying
        if data.parent_id:
            parent = await self.db.get(Comment, data.parent_id)
            if not parent or parent.deleted_at is not None or parent.post_id != post_id:
                raise CommentNotFoundError(str(data.parent_id))

        comment = Comment(
            post_id=post_id,
            author_id=author_id,
            parent_id=data.parent_id,
            body=data.body,
        )

        self.db.add(comment)

        # Increment post comment counter
        await self.db.execute(
            update(Post)
            .where(Post.id == post_id)
            .values(comment_count=Post.comment_count + 1)
        )

        await self.db.commit()
        await self.db.refresh(comment)

        return self._comment_to_response(comment)

    async def list_comments(
        self,
        post_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> CommentListResponse:
        """List top-level comments for a post with nested replies."""
        # Count total top-level comments
        count_result = await self.db.execute(
            select(func.count())
            .select_from(Comment)
            .where(
                Comment.post_id == post_id,
                Comment.parent_id.is_(None),
                Comment.deleted_at.is_(None),
            )
        )
        total = count_result.scalar() or 0

        # Fetch top-level comments with replies eagerly loaded
        result = await self.db.execute(
            select(Comment)
            .where(
                Comment.post_id == post_id,
                Comment.parent_id.is_(None),
                Comment.deleted_at.is_(None),
            )
            .order_by(Comment.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        comments = result.scalars().all()

        items = [self._comment_to_response(c) for c in comments]
        has_more = (offset + len(items)) < total

        return CommentListResponse(
            items=items,
            total=total,
            has_more=has_more,
        )

    async def update_comment(
        self, comment_id: UUID, author_id: UUID, data: CommentUpdate
    ) -> CommentResponse:
        """Update a comment (owner only)."""
        comment = await self.db.get(Comment, comment_id)
        if not comment or comment.deleted_at is not None:
            raise CommentNotFoundError(str(comment_id))
        if comment.author_id != author_id:
            raise NotCommentOwnerError(str(comment_id), str(author_id))

        await self.db.execute(
            update(Comment)
            .where(Comment.id == comment_id)
            .values(body=data.body)
        )
        await self.db.commit()
        await self.db.refresh(comment)

        return self._comment_to_response(comment)

    async def delete_comment(self, comment_id: UUID, author_id: UUID) -> None:
        """Soft delete a comment (owner only)."""
        comment = await self.db.get(Comment, comment_id)
        if not comment or comment.deleted_at is not None:
            raise CommentNotFoundError(str(comment_id))
        if comment.author_id != author_id:
            raise NotCommentOwnerError(str(comment_id), str(author_id))

        await self.db.execute(
            update(Comment)
            .where(Comment.id == comment_id)
            .values(deleted_at=datetime.now(timezone.utc))
        )

        # Decrement post comment counter
        await self.db.execute(
            update(Post)
            .where(Post.id == comment.post_id, Post.comment_count > 0)
            .values(comment_count=Post.comment_count - 1)
        )

        await self.db.commit()

    def _comment_to_response(self, comment: Comment) -> CommentResponse:
        """Convert comment model to response with nested replies."""
        replies = []
        if hasattr(comment, "replies") and comment.replies:
            replies = [
                self._comment_to_response(reply)
                for reply in comment.replies
                if reply.deleted_at is None
            ]

        return CommentResponse(
            id=comment.id,
            post_id=comment.post_id,
            author_id=comment.author_id,
            parent_id=comment.parent_id,
            body=comment.body,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
            replies=replies,
        )
