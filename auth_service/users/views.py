"""
users/views.py
Auth-related views: Register (with email verification), VerifyEmail, Logout.
- Uses Django settings via django.conf.settings (safe: we use getattr with defaults).
- Uses rest_framework_simplejwt AccessToken for short-lived verification tokens.
- Type-checked for mypy (casts where necessary).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, cast

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, Token

from .models import User
from .serializers import RegisterSerializer

logger = logging.getLogger(__name__)


class RegisterView(generics.CreateAPIView[User]):
    """
    API endpoint for user registration.
    - Creates a new user (is_email_verified = False by default)
    - Generates a short-lived email verification token and sends an email
    - Does not block user creation if email sending fails (returns 201 but includes a note)
    """

    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user: User = serializer.save()

        # Build verification token
        token = AccessToken.for_user(user)
        token["type"] = "email_verification"

        # Token lifetime: use settings.EMAIL_VERIFICATION_LIFETIME if present, else 1 hour
        lifetime = getattr(settings, "EMAIL_VERIFICATION_LIFETIME", timedelta(hours=1))
        try:
            # preferred API (may exist depending on simplejwt version)
            token.set_exp(lifetime=lifetime)
        except Exception:
            # fallback: compute numeric exp manually
            exp_dt = timezone.now() + (lifetime if isinstance(lifetime, timedelta) else timedelta(hours=1))
            token["exp"] = int(exp_dt.timestamp())

        # Frontend URL to include in the email. fallback to local dev server.
        # frontend_base = getattr(settings, "FRONTEND_URL", "http://127.0.0.1:8000")
        # verification_link = f"{frontend_base.rstrip('/')}/verify-email?token={str(token)}"
        verification_link = f"http://127.0.0.1:8000/api/auth/verify-email/?token={str(token)}"


        # Email metadata (use settings.DEFAULT_FROM_EMAIL if set)
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@kalosphere.com")
        subject = "Verify your Kalosphere account"
        message = (
            f"Hi {user.username},\n\n"
            f"Please verify your Kalosphere account by clicking the link below:\n\n{verification_link}\n\n"
            "If you didn't request this, please ignore this message.\n"
        )

        # Try to send email. If it fails, log and return success response anyway.
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[user.email],
                fail_silently=False,
            )
            email_status = "Verification email sent"
        except Exception as exc:
            # Log the exception for later debugging (do not leak internal details to client)
            logger.exception("Failed to send verification email to %s: %s", user.email, exc)
            email_status = "Account created, but failed to send verification email"

        return Response(
            {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "detail": email_status,
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyEmailView(APIView):
    """
    Verify the email address.
    Expects a query param: ?token=<jwt>
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        token_str: str | None = request.query_params.get("token")
        if not token_str:
            return Response({"detail": "Token missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # AccessToken accepts a token-like value at runtime; cast to satisfy mypy.
            token = AccessToken(cast(Token, token_str))

            # Optional extra check: ensure the token type is what we issued
            if token.get("type") != "email_verification":
                return Response({"detail": "Invalid token type"}, status=status.HTTP_400_BAD_REQUEST)

            user_id = token.get("user_id")
            if not user_id:
                return Response({"detail": "Invalid token payload"}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.get(id=user_id)
            if user.is_email_verified:
                return Response({"detail": "Email already verified"}, status=status.HTTP_200_OK)

            user.is_email_verified = True
            user.save(update_fields=["is_email_verified"])

            return Response({"detail": "Email successfully verified"}, status=status.HTTP_200_OK)

        except Exception as exc:
            logger.debug("VerifyEmailView failed token parsing/validation: %s", exc)
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    Blacklist a refresh token (logout).
    Clients should POST: { "refresh": "<refresh_token>" }
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        refresh_token: str | None = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # RefreshToken expects a str at runtime; cast to appease type checker
            token = RefreshToken(cast(Token, refresh_token))
            token.blacklist()
        except Exception:
            return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
