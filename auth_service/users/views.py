"""
users/views.py
Auth-related views: Register, VerifyEmail, ResendVerification, Login, Logout.
- Handles email verification with JWT tokens.
- Blocks login if email is not verified.
"""

from __future__ import annotations

import logging
import secrets
import requests
from datetime import timedelta
from typing import Any, cast

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from .models import User, PasswordResetToken, MFACode
from .serializers import (
    RegisterSerializer, ForgotPasswordSerializer, ResetPasswordSerializer,
    ChangePasswordSerializer, AccountDeactivationSerializer, TOTPSetupSerializer,
    TOTPVerifySerializer, PhoneNumberSerializer, MFACodeSerializer,
    UserProfileSerializer, SocialLoginSerializer
)

logger = logging.getLogger(__name__)


def get_authenticated_user(request: Request) -> User:
    """Get authenticated user with proper type checking."""
    user = request.user
    if not hasattr(user, 'email') or not hasattr(user, 'id'):
        raise ValueError("User not properly authenticated")
    return user  # type: ignore[return-value]


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

class RegisterView(generics.CreateAPIView):
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
    """Custom login that blocks unverified users and handles account locking."""

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        email = request.data.get("email")
        password = request.data.get("password")
        
        if not email or not password:
            return Response(
                {"detail": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        
        # Check if account is locked
        if user.is_account_locked():
            return Response(
                {"detail": "Account is locked due to multiple failed login attempts."},
                status=status.HTTP_423_LOCKED,
            )
        
        # Check if email is verified
        if not user.is_email_verified:
            return Response(
                {"detail": "Email not verified. Please verify your email."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        
        # Authenticate user
        if not user.check_password(password):
            user.increment_failed_login()
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        
        # Reset failed login attempts on successful login
        user.reset_failed_logins()
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        return Response({
            "access": str(access),
            "refresh": str(refresh),
            "user": {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "mfa_enabled": user.mfa_enabled,
            }
        })


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


# ---------------------------
# Password Reset Views
# ---------------------------

class ForgotPasswordView(APIView):
    """Send password reset email."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data["email"]
        user = User.objects.get(email=email)
        
        # Generate reset token
        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timedelta(minutes=settings.PASSWORD_RESET_LIFETIME)
        
        # Create or update reset token
        PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
        PasswordResetToken.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )
        
        # Send reset email
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        subject = "Reset your Kalosphere password"
        message = (
            f"Hi {user.username},\n\n"
            f"You requested a password reset. Click the link below to reset your password:\n\n"
            f"{reset_link}\n\n"
            f"This link will expire in {settings.PASSWORD_RESET_LIFETIME} minutes.\n"
            f"If you didn't request this, please ignore this message.\n"
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            return Response(
                {"detail": "Password reset email sent."},
                status=status.HTTP_200_OK
            )
        except Exception as exc:
            logger.exception("Failed to send password reset email: %s", exc)
            return Response(
                {"detail": "Failed to send email."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResetPasswordView(APIView):
    """Reset password with token."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]
        
        # Get token object
        token_obj = PasswordResetToken.objects.get(token=token)
        user = token_obj.user
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Mark token as used
        token_obj.mark_as_used()
        
        return Response(
            {"detail": "Password reset successfully."},
            status=status.HTTP_200_OK
        )


# ---------------------------
# Password Management Views
# ---------------------------

class ChangePasswordView(APIView):
    """Change password for authenticated users."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        new_password = serializer.validated_data["new_password"]
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        return Response(
            {"detail": "Password changed successfully."},
            status=status.HTTP_200_OK
        )


# ---------------------------
# Account Management Views
# ---------------------------

class AccountDeactivationView(APIView):
    """Deactivate user account."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = AccountDeactivationSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        try:
            user = get_authenticated_user(request)
            user.deactivate_account()
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(
            {"detail": "Account deactivated successfully."},
            status=status.HTTP_200_OK
        )


class UserProfileView(APIView):
    """Get and update user profile."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        try:
            user = get_authenticated_user(request)
            serializer = UserProfileSerializer(user)
            return Response(serializer.data)
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        try:
            user = get_authenticated_user(request)
            serializer = UserProfileSerializer(
                user, 
                data=request.data, 
                partial=True,
                context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# ---------------------------
# Multi-Factor Authentication Views
# ---------------------------

class TOTPSetupView(APIView):
    """Setup TOTP for MFA."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Get TOTP setup information."""
        try:
            user = get_authenticated_user(request)
            if not user.totp_secret:
                user.generate_totp_secret()
            
            qr_code = user.generate_totp_qr_code()
            backup_codes = user.generate_backup_codes()
            
            return Response({
                "secret": user.totp_secret,
                "qr_code": qr_code,
                "backup_codes": backup_codes,
                "uri": user.get_totp_uri()
            })
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Verify TOTP setup."""
        serializer = TOTPSetupSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        try:
            user = get_authenticated_user(request)
            user.mfa_enabled = True
            user.save(update_fields=["mfa_enabled"])
            
            return Response(
                {"detail": "TOTP MFA enabled successfully."},
                status=status.HTTP_200_OK
            )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class TOTPDisableView(APIView):
    """Disable TOTP MFA."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        try:
            user = get_authenticated_user(request)
            user.mfa_enabled = False
            user.totp_secret = ""
            user.backup_codes = []
            user.save(update_fields=["mfa_enabled", "totp_secret", "backup_codes"])
            
            return Response(
                {"detail": "TOTP MFA disabled successfully."},
                status=status.HTTP_200_OK
            )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class TOTPVerifyView(APIView):
    """Verify TOTP token."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = TOTPVerifySerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        return Response(
            {"detail": "TOTP verification successful."},
            status=status.HTTP_200_OK
        )


class PhoneNumberSetupView(APIView):
    """Setup phone number for SMS MFA."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = PhoneNumberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = get_authenticated_user(request)
            phone_number = serializer.validated_data["phone_number"]
            
            # Generate and send SMS code
            code = secrets.randbelow(10**settings.MFA_CODE_LENGTH)
            code_str = str(code).zfill(settings.MFA_CODE_LENGTH)
            
            expires_at = timezone.now() + timedelta(minutes=settings.MFA_CODE_LIFETIME)
            MFACode.objects.create(
                user=user,
                code=code_str,
                code_type="sms",
                expires_at=expires_at
            )
            
            # Send SMS (implement with Twilio)
            self._send_sms(phone_number, code_str)
            
            user.phone_number = phone_number
            user.save(update_fields=["phone_number"])
            
            return Response(
                {"detail": "SMS code sent to your phone number."},
                status=status.HTTP_200_OK
            )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def _send_sms(self, phone_number: str, code: str) -> None:
        """Send SMS using Twilio."""
        try:
            from twilio.rest import Client
            
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            client.messages.create(
                body=f"Your Kalosphere verification code is: {code}",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
        except Exception as exc:
            logger.exception("Failed to send SMS: %s", exc)


class PhoneNumberVerifyView(APIView):
    """Verify phone number with SMS code."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = MFACodeSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        try:
            user = get_authenticated_user(request)
            user.is_phone_verified = True
            user.save(update_fields=["is_phone_verified"])
            
            return Response(
                {"detail": "Phone number verified successfully."},
                status=status.HTTP_200_OK
            )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class EmailMFASetupView(APIView):
    """Setup email MFA."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        try:
            user = get_authenticated_user(request)
            
            # Generate and send email code
            code = secrets.randbelow(10**settings.MFA_CODE_LENGTH)
            code_str = str(code).zfill(settings.MFA_CODE_LENGTH)
            
            expires_at = timezone.now() + timedelta(minutes=settings.MFA_CODE_LIFETIME)
            MFACode.objects.create(
                user=user,
                code=code_str,
                code_type="email",
                expires_at=expires_at
            )
            
            # Send email
            subject = "Your Kalosphere verification code"
            message = (
                f"Hi {user.username},\n\n"
                f"Your verification code is: {code_str}\n\n"
                f"This code will expire in {settings.MFA_CODE_LIFETIME} minutes.\n"
            )
            
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[str(user.email)],
                    fail_silently=False,
                )
                return Response(
                    {"detail": "Verification code sent to your email."},
                    status=status.HTTP_200_OK
                )
            except Exception as exc:
                logger.exception("Failed to send email MFA code: %s", exc)
                return Response(
                    {"detail": "Failed to send email."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class EmailMFAVerifyView(APIView):
    """Verify email MFA code."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = MFACodeSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        try:
            user = get_authenticated_user(request)
            user.email_mfa_enabled = True
            user.save(update_fields=["email_mfa_enabled"])
            
            return Response(
                {"detail": "Email MFA enabled successfully."},
                status=status.HTTP_200_OK
            )
        except ValueError:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# ---------------------------
# Social Authentication Views
# ---------------------------

class SocialLoginView(APIView):
    """Handle social login (Google, GitHub)."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = SocialLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        provider = serializer.validated_data["provider"]
        access_token = serializer.validated_data["access_token"]
        
        # Get user info from provider
        user_info = self._get_user_info(provider, access_token)
        if not user_info:
            return Response(
                {"detail": "Invalid access token."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get or create user
        user = self._get_or_create_user(provider, user_info)
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        return Response({
            "access": str(access),
            "refresh": str(refresh),
            "user": {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "mfa_enabled": user.mfa_enabled,
            }
        })

    def _get_user_info(self, provider: str, access_token: str) -> dict[str, Any] | None:
        """Get user info from social provider."""
        try:
            if provider == "google":
                response = requests.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    params={"access_token": access_token}
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "id": data["id"],
                        "email": data["email"],
                        "name": data.get("name", ""),
                        "picture": data.get("picture", "")
                    }
            
            elif provider == "github":
                response = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {access_token}"}
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "id": str(data["id"]),
                        "email": data.get("email", ""),
                        "name": data.get("name", data.get("login", "")),
                        "picture": data.get("avatar_url", "")
                    }
        except Exception as exc:
            logger.exception("Failed to get user info from %s: %s", provider, exc)
        
        return None

    def _get_or_create_user(self, provider: str, user_info: dict[str, Any]) -> User:
        """Get or create user from social provider info."""
        email = user_info["email"]
        provider_id = user_info["id"]
        name = user_info["name"]
        
        # Try to find existing user
        try:
            if provider == "google":
                user = User.objects.get(google_id=provider_id)
            elif provider == "github":
                user = User.objects.get(github_id=provider_id)
        except User.DoesNotExist:
            pass
        else:
            return user
        
        # Try to find by email
        try:
            user = User.objects.get(email=email)
            # Link social account
            if provider == "google":
                user.google_id = provider_id
            elif provider == "github":
                user.github_id = provider_id
            user.save()
            return user
        except User.DoesNotExist:
            pass
        
        # Create new user
        username = name.replace(" ", "_").lower()[:50]
        # Ensure username is unique
        counter = 1
        original_username = username
        while User.objects.filter(username=username).exists():
            username = f"{original_username}_{counter}"
            counter += 1
        
        user = User.objects.create_user(
            email=email,
            username=username,
            password=None,  # No password for social users
            is_email_verified=True
        )
        
        if provider == "google":
            user.google_id = provider_id
        elif provider == "github":
            user.github_id = provider_id
        
        user.save()
        return user
