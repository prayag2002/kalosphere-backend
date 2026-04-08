"""Category API endpoints."""

from uuid import UUID

from fastapi import APIRouter

from app.api.deps import DBSession
from app.core.exceptions import http_category_not_found
from app.schemas.category import CategoryListResponse, TagResponse
from app.services.category_service import CategoryService

router = APIRouter()


@router.get("", response_model=CategoryListResponse)
async def list_categories(
    db: DBSession,
) -> CategoryListResponse:
    """List all active categories with their tags (subcategories)."""
    service = CategoryService(db)
    return await service.list_categories()


@router.get("/{category_id}/tags", response_model=list[TagResponse])
async def list_category_tags(
    category_id: UUID,
    db: DBSession,
) -> list[TagResponse]:
    """List all active tags (subcategories) for a given category."""
    service = CategoryService(db)

    # Verify category exists
    category = await service.get_by_id(category_id)
    if not category or not category.is_active:
        raise http_category_not_found()

    return await service.get_tags_for_category(category_id)
