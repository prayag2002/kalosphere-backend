"""Category service - business logic for categories and tags."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category
from app.models.tag import Tag
from app.schemas.category import CategoryListResponse, CategoryResponse, TagResponse


class CategoryService:
    """Service for category and tag operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_categories(self, active_only: bool = True) -> CategoryListResponse:
        """List all categories with their tags."""
        query = select(Category).order_by(Category.display_order, Category.name)
        if active_only:
            query = query.where(Category.is_active.is_(True))

        result = await self.db.execute(query)
        categories = result.scalars().all()

        items = [self._to_response(cat) for cat in categories]

        return CategoryListResponse(
            categories=items,
            total=len(items),
        )

    async def get_by_id(self, category_id: UUID) -> Category | None:
        """Get category by ID."""
        return await self.db.get(Category, category_id)

    async def get_tags_for_category(
        self, category_id: UUID, active_only: bool = True
    ) -> list[TagResponse]:
        """Get all tags belonging to a category."""
        query = (
            select(Tag)
            .where(Tag.category_id == category_id)
            .order_by(Tag.name)
        )
        if active_only:
            query = query.where(Tag.is_active.is_(True))

        result = await self.db.execute(query)
        tags = result.scalars().all()

        return [
            TagResponse(
                id=tag.id,
                name=tag.name,
                slug=tag.slug,
                category_id=tag.category_id,
                post_count=tag.post_count,
                is_active=tag.is_active,
            )
            for tag in tags
        ]

    async def get_tags_by_ids(self, tag_ids: list[UUID]) -> list[Tag]:
        """Get multiple tags by their IDs."""
        if not tag_ids:
            return []

        result = await self.db.execute(
            select(Tag).where(Tag.id.in_(tag_ids), Tag.is_active.is_(True))
        )
        return list(result.scalars().all())

    def _to_response(self, category: Category) -> CategoryResponse:
        """Convert Category model to response schema."""
        return CategoryResponse(
            id=category.id,
            name=category.name,
            slug=category.slug,
            description=category.description,
            display_order=category.display_order,
            is_active=category.is_active,
            tags=[
                TagResponse(
                    id=tag.id,
                    name=tag.name,
                    slug=tag.slug,
                    category_id=tag.category_id,
                    post_count=tag.post_count,
                    is_active=tag.is_active,
                )
                for tag in category.tags
                if tag.is_active
            ],
            created_at=category.created_at,
        )
