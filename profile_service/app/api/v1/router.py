"""Aggregated v1 API router."""

from fastapi import APIRouter

from app.api.v1.profiles import router as profiles_router

api_router = APIRouter()

api_router.include_router(
    profiles_router,
    prefix="/profiles",
    tags=["profiles"],
)
