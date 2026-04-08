"""Aggregated v1 API router."""

from fastapi import APIRouter

from app.api.v1.categories import router as categories_router
from app.api.v1.interactions import router as interactions_router
from app.api.v1.posts import router as posts_router

api_router = APIRouter()

api_router.include_router(
    posts_router,
    prefix="/posts",
    tags=["posts"],
)

api_router.include_router(
    interactions_router,
    prefix="/posts",
    tags=["interactions"],
)

api_router.include_router(
    categories_router,
    prefix="/categories",
    tags=["categories"],
)
