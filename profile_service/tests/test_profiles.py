"""Tests for profile endpoints."""

import pytest
from httpx import AsyncClient

from app.models.preferences import UserPreferences
from app.models.profile import Profile
from app.schemas.profile import ProfileCreate
from app.services.profile_service import ProfileService


class TestHealthCheck:
    """Test health check endpoint."""

    async def test_health_check(self, client: AsyncClient):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestGetMyProfile:
    """Test GET /api/v1/profiles/me endpoint."""

    async def test_get_my_profile_not_found(self, client: AsyncClient):
        response = await client.get("/api/v1/profiles/me")
        assert response.status_code == 404

    async def test_get_my_profile_success(
        self, client: AsyncClient, db_session, test_user
    ):
        # Create profile
        service = ProfileService(db_session)
        await service.create(
            ProfileCreate(
                user_id=test_user.user_id,
                username="testuser",
                bio="Test bio",
            )
        )

        response = await client.get("/api/v1/profiles/me")
        assert response.status_code == 200

        data = response.json()
        assert data["username"] == "testuser"
        assert data["bio"] == "Test bio"
        # Private response includes score
        assert "reputation_score" in data


class TestUpdateMyProfile:
    """Test PATCH /api/v1/profiles/me endpoint."""

    async def test_update_username(
        self, client: AsyncClient, db_session, test_user
    ):
        # Create profile
        service = ProfileService(db_session)
        await service.create(
            ProfileCreate(
                user_id=test_user.user_id,
                username="oldname",
                bio=None,
            )
        )

        response = await client.patch(
            "/api/v1/profiles/me",
            json={"username": "newname"},
        )
        assert response.status_code == 200
        assert response.json()["username"] == "newname"

    async def test_update_bio(
        self, client: AsyncClient, db_session, test_user
    ):
        service = ProfileService(db_session)
        await service.create(
            ProfileCreate(
                user_id=test_user.user_id,
                username="testuser",
                bio=None,
            )
        )

        response = await client.patch(
            "/api/v1/profiles/me",
            json={"bio": "Updated bio"},
        )
        assert response.status_code == 200
        assert response.json()["bio"] == "Updated bio"


class TestPreferences:
    """Test preferences endpoints."""

    async def test_get_preferences(
        self, client: AsyncClient, db_session, test_user
    ):
        # Create profile (which also creates preferences)
        service = ProfileService(db_session)
        await service.create(
            ProfileCreate(
                user_id=test_user.user_id,
                username="testuser",
                bio=None,
            )
        )

        response = await client.get("/api/v1/profiles/me/preferences")
        assert response.status_code == 200

        data = response.json()
        assert data["theme"] == "system"
        assert data["email_notifications"] is True

    async def test_update_preferences(
        self, client: AsyncClient, db_session, test_user
    ):
        service = ProfileService(db_session)
        await service.create(
            ProfileCreate(
                user_id=test_user.user_id,
                username="testuser",
                bio=None,
            )
        )

        response = await client.patch(
            "/api/v1/profiles/me/preferences",
            json={"theme": "dark", "email_notifications": False},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["theme"] == "dark"
        assert data["email_notifications"] is False
