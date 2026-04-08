"""Post service - business logic for post CRUD operations."""

from datetime import datetime, timezone
from uuid import UUID

from pydantic import HttpUrl
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.exceptions import NotPostOwnerError, PostNotFoundError
from app.models.like import Like
from app.models.post import Post, post_tags
from app.models.tag import Tag
from app.schemas.post import (
    PostCreate,
    PostListResponse,
    PostResponse,
    PostSummaryResponse,
    PostUpdate,
)


class PostService:
    """Service for post CRUD operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _build_media_url(self, media_key: str | None) -> HttpUrl | None:
        """Build full media URL from storage key."""
        if not media_key:
            return None
        base = settings.cdn_base_url.rstrip("/")
        return HttpUrl(f"{base}/{media_key}")

    async def create(
        self,
        author_id: UUID,
        data: PostCreate,
        media_key: str,
        media_type: str,
        thumbnail_key: str | None = None,
    ) -> Post:
        """Create a new post."""
        now = datetime.now(timezone.utc)

        post = Post(
            author_id=author_id,
            title=data.title,
            description=data.description,
            category_id=data.category_id,
            media_key=media_key,
            media_type=media_type,
            thumbnail_key=thumbnail_key,
            status=data.status,
            published_at=now if data.status == "published" else None,
        )

        # Add tags if provided
        if data.tag_ids:
            result = await self.db.execute(
                select(Tag).where(Tag.id.in_(data.tag_ids), Tag.is_active.is_(True))
            )
            tags = result.scalars().all()
            post.tags = list(tags)

        self.db.add(post)
        await self.db.commit()
        await self.db.refresh(post)

        return post

    async def get_by_id(self, post_id: UUID) -> Post | None:
        """Get post by ID (excludes soft-deleted)."""
        result = await self.db.execute(
            select(Post)
            .options(selectinload(Post.category), selectinload(Post.tags))
            .where(Post.id == post_id, Post.deleted_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def list_published(
        self,
        limit: int = 20,
        offset: int = 0,
        category_id: UUID | None = None,
        tag_ids: list[UUID] | None = None,
        sort: str = "recent",
        author_id: UUID | None = None,
    ) -> PostListResponse:
        """List published posts with filtering and sorting."""
        query = (
            select(Post)
            .options(selectinload(Post.category), selectinload(Post.tags))
            .where(
                Post.status == "published",
                Post.deleted_at.is_(None),
            )
        )

        # Filters
        if category_id:
            query = query.where(Post.category_id == category_id)
        if author_id:
            query = query.where(Post.author_id == author_id)
        if tag_ids:
            query = query.join(post_tags).where(post_tags.c.tag_id.in_(tag_ids))

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Sorting
        if sort == "popular":
            query = query.order_by(Post.like_count.desc(), Post.published_at.desc())
        elif sort == "trending":
            # Simple trending: likes relative to recency
            # Posts with more likes AND more recent get priority
            query = query.order_by(
                (Post.like_count * 1.0 / (
                    func.extract("epoch", func.now() - Post.published_at) / 3600 + 1
                )).desc()
            )
        else:  # recent
            query = query.order_by(Post.published_at.desc())

        # Pagination
        query = query.limit(limit).offset(offset)

        result = await self.db.execute(query)
        posts = result.scalars().all()

        items = [self._to_summary(post) for post in posts]
        has_more = (offset + len(items)) < total

        return PostListResponse(
            items=items,
            total=total,
            has_more=has_more,
        )

    async def list_by_author(
        self,
        author_id: UUID,
        include_drafts: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> PostListResponse:
        """List posts by a specific author."""
        query = (
            select(Post)
            .options(selectinload(Post.category), selectinload(Post.tags))
            .where(Post.author_id == author_id, Post.deleted_at.is_(None))
        )

        if not include_drafts:
            query = query.where(Post.status == "published")

        # Count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.order_by(Post.created_at.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        posts = result.scalars().all()

        items = [self._to_summary(post) for post in posts]
        has_more = (offset + len(items)) < total

        return PostListResponse(
            items=items,
            total=total,
            has_more=has_more,
        )

    async def update(self, post_id: UUID, author_id: UUID, data: PostUpdate) -> Post:
        """Update post (owner only)."""
        post = await self.get_by_id(post_id)
        if not post:
            raise PostNotFoundError(str(post_id))
        if post.author_id != author_id:
            raise NotPostOwnerError(str(post_id), str(author_id))

        update_data = data.model_dump(exclude_unset=True)

        # Handle tag updates separately
        tag_ids = update_data.pop("tag_ids", None)
        if tag_ids is not None:
            result = await self.db.execute(
                select(Tag).where(Tag.id.in_(tag_ids), Tag.is_active.is_(True))
            )
            post.tags = list(result.scalars().all())

        # Handle status transitions
        if "status" in update_data:
            new_status = update_data["status"]
            if new_status == "published" and post.published_at is None:
                update_data["published_at"] = datetime.now(timezone.utc)

        if update_data:
            await self.db.execute(
                update(Post)
                .where(Post.id == post_id)
                .values(**update_data)
            )

        await self.db.commit()
        await self.db.refresh(post)
        return post

    async def soft_delete(self, post_id: UUID, author_id: UUID) -> None:
        """Soft delete a post (owner only)."""
        post = await self.get_by_id(post_id)
        if not post:
            raise PostNotFoundError(str(post_id))
        if post.author_id != author_id:
            raise NotPostOwnerError(str(post_id), str(author_id))

        await self.db.execute(
            update(Post)
            .where(Post.id == post_id)
            .values(
                deleted_at=datetime.now(timezone.utc),
                status="removed",
            )
        )
        await self.db.commit()

    async def soft_delete_by_author(self, author_id: UUID) -> int:
        """
        Soft delete all posts by an author.

        Called when user.deleted event is received.
        Returns count of affected posts.
        """
        result = await self.db.execute(
            update(Post)
            .where(
                Post.author_id == author_id,
                Post.deleted_at.is_(None),
            )
            .values(
                deleted_at=datetime.now(timezone.utc),
                status="removed",
            )
        )
        await self.db.commit()
        return result.rowcount  # type: ignore

    async def increment_view(self, post_id: UUID) -> None:
        """Increment view counter (fire-and-forget, no commit needed by caller)."""
        await self.db.execute(
            update(Post)
            .where(Post.id == post_id)
            .values(view_count=Post.view_count + 1)
        )
        await self.db.commit()

    def to_response(
        self, post: Post, is_liked: bool = False
    ) -> PostResponse:
        """Convert post model to full response."""
        from app.schemas.category import CategoryResponse, TagResponse

        return PostResponse(
            id=post.id,
            author_id=post.author_id,
            title=post.title,
            description=post.description,
            category=CategoryResponse(
                id=post.category.id,
                name=post.category.name,
                slug=post.category.slug,
                description=post.category.description,
                display_order=post.category.display_order,
                is_active=post.category.is_active,
                tags=[],  # Don't nest category tags in post response
                created_at=post.category.created_at,
            ),
            tags=[
                TagResponse(
                    id=tag.id,
                    name=tag.name,
                    slug=tag.slug,
                    category_id=tag.category_id,
                    post_count=tag.post_count,
                    is_active=tag.is_active,
                )
                for tag in post.tags
            ],
            media_url=self._build_media_url(post.media_key),
            media_type=post.media_type,
            thumbnail_url=self._build_media_url(post.thumbnail_key),
            status=post.status,
            view_count=post.view_count,
            like_count=post.like_count,
            comment_count=post.comment_count,
            is_liked=is_liked,
            published_at=post.published_at,
            created_at=post.created_at,
            updated_at=post.updated_at,
        )

    def _to_summary(self, post: Post, is_liked: bool = False) -> PostSummaryResponse:
        """Convert post to lightweight summary for feeds."""
        return PostSummaryResponse(
            id=post.id,
            author_id=post.author_id,
            title=post.title,
            category_name=post.category.name if post.category else "Unknown",
            thumbnail_url=self._build_media_url(post.thumbnail_key),
            media_type=post.media_type,
            like_count=post.like_count,
            comment_count=post.comment_count,
            view_count=post.view_count,
            is_liked=is_liked,
            published_at=post.published_at,
            created_at=post.created_at,
        )
