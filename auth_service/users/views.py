"""
users/views.py
Auth-related views: Register, VerifyEmail, ResendVerification, Login, Logout.
- Handles email verification with JWT tokens.
- Blocks login if email is not verified.
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
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, Token

from .models import User
from .serializers import RegisterSerializer

logger = logging.getLogger(__name__)


# ---------------------------
# Helper: send verification email
# ---------------------------
def send_verification_email(user: User) -> None:
    """
    Generates a short-lived verification token and sends it by email.
    """
    token = AccessToken.for_user(user)
    token["type"] = "email_verification"

    lifetime = getattr(settings, "EMAIL_VERIFICATION_LIFETIME", timedelta(hours=1))
    try:
        token.set_exp(lifetime=lifetime)
    except Exception:
        exp_dt = timezone.now() + (
            lifetime if isinstance(lifetime, timedelta) else timedelta(hours=1)
        )
        token["exp"] = int(exp_dt.timestamp())

    verification_link = f"http://127.0.0.1:8000/api/auth/verify-email/?token={str(token)}"

    subject = "Verify your Kalosphere account"
    message = (
        f"Hi {user.username},\n\n"
        f"Please verify your Kalosphere account by clicking the link below:\n\n{verification_link}\n\n"
        "If you didn't request this, please ignore this message.\n"
    )
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@kalosphere.com")

    send_mail(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=[user.email],
        fail_silently=False,
    )


# ---------------------------
# Views
# ---------------------------

class RegisterView(generics.CreateAPIView[User]):
    """Register a user and send verification email."""

    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user: User = serializer.save()

        try:
            send_verification_email(user)
            email_status = "Verification email sent"
        except Exception as exc:
            logger.exception("Failed to send verification email: %s", exc)
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


class ResendVerificationView(APIView):
    """Resend the email verification link."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        email: str | None = request.data.get("email")
        if not email:
            return Response({"detail": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if user.is_email_verified:
            return Response({"detail": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            send_verification_email(user)
            return Response({"detail": "Verification email resent"}, status=status.HTTP_200_OK)
        except Exception as exc:
            logger.exception("Failed to resend verification email: %s", exc)
            return Response({"detail": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmailView(APIView):
    """Verify email address with a token."""

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        token_str: str | None = request.query_params.get("token")
        if not token_str:
            return Response({"detail": "Token missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = AccessToken(cast(Token, token_str))
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
            logger.debug("VerifyEmailView failed: %s", exc)
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


class CustomLoginView(TokenObtainPairView):
    """Custom login that blocks unverified users."""

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        response = super().post(request, *args, **kwargs)
        # If login was successful, check if user is verified
        if response.status_code == 200:
            user = User.objects.get(email=request.data.get("email"))
            if not user.is_email_verified:
                return Response(
                    {"detail": "Email not verified. Please verify your email."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        return response


class LogoutView(APIView):
    """Logout by blacklisting refresh token."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        refresh_token: str | None = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(cast(Token, refresh_token))
            token.blacklist()
        except Exception:
            return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
