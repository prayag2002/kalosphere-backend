import uuid
from typing import Any, Optional
import pyotp
import qrcode
import io
import base64

from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import timedelta


class UserManager(BaseUserManager["User"]):
    """
    Custom manager for User model.
    Handles creation of normal users and superusers.
    """

    def create_user(
        self,
        email: str,
        username: str,
        password: Optional[str] = None,
        **extra_fields: Any,
    ) -> "User":
        """
        Create and return a regular user.
        - Normalizes the email
        - Hashes the password
        - Persists the user in the database
        """
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user: "User" = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self,
        email: str,
        username: str,
        password: Optional[str] = None,
        **extra_fields: Any,
    ) -> "User":
        """
        Create and return a superuser.
        - Adds staff and superuser privileges
        - Validates required flags
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)


class TimeStampedModel(models.Model):
    """
    Abstract base model that adds created_at and updated_at timestamps.
    Every major model should inherit this in a large project.
    """

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    """
    Custom User model for Kalosphere.
    - UUID primary key for security & scalability
    - Email is the login identifier
    - Username is unique handle
    - Includes staff/admin flags
    - Includes email verification flag
    - Supports multi-factor authentication
    - Includes account locking for brute force protection
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=50, unique=True, db_index=True)

    # Account status & roles
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    # Account locking for brute force protection
    is_locked = models.BooleanField(default=False)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Multi-factor authentication
    mfa_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True)
    backup_codes = models.JSONField(default=list, blank=True)
    
    # Phone number for SMS OTP
    phone_number = models.CharField(max_length=20, blank=True)
    is_phone_verified = models.BooleanField(default=False)
    
    # Email MFA settings
    email_mfa_enabled = models.BooleanField(default=False)
    
    # OAuth providers
    google_id = models.CharField(max_length=100, blank=True, unique=True, null=True)
    github_id = models.CharField(max_length=100, blank=True, unique=True, null=True)

    # Attach manager
    objects: UserManager = UserManager()

    # Use email for login instead of username
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self) -> str:
        """String representation for debugging/admin."""
        return f"{self.username} <{self.email}>"

    def is_account_locked(self) -> bool:
        """Check if account is currently locked."""
        if not self.is_locked:
            return False
        
        if self.locked_until and timezone.now() > self.locked_until:
            # Unlock account if lock period has expired
            self.is_locked = False
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=['is_locked', 'failed_login_attempts', 'locked_until'])
            return False
        
        return True

    def increment_failed_login(self) -> None:
        """Increment failed login attempts and lock account if threshold reached."""
        from django.conf import settings
        
        self.failed_login_attempts += 1
        max_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
        lock_duration = getattr(settings, 'ACCOUNT_LOCK_DURATION', 30)  # minutes
        
        if self.failed_login_attempts >= max_attempts:
            self.is_locked = True
            self.locked_until = timezone.now() + timedelta(minutes=lock_duration)
        
        self.save(update_fields=['failed_login_attempts', 'is_locked', 'locked_until'])

    def reset_failed_logins(self) -> None:
        """Reset failed login attempts after successful login."""
        if self.failed_login_attempts > 0:
            self.failed_login_attempts = 0
            self.is_locked = False
            self.locked_until = None
            self.save(update_fields=['failed_login_attempts', 'is_locked', 'locked_until'])

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret for the user."""
        secret = pyotp.random_base32()
        self.totp_secret = secret
        self.save(update_fields=['totp_secret'])
        return secret

    def get_totp_uri(self) -> str:
        """Get TOTP URI for QR code generation."""
        if not self.totp_secret:
            self.generate_totp_secret()
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name="Kalosphere"
        )

    def generate_totp_qr_code(self) -> str:
        """Generate QR code for TOTP setup."""
        uri = self.get_totp_uri()
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()

    def verify_totp(self, token: str) -> bool:
        """Verify TOTP token."""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate backup codes for MFA."""
        import secrets
        codes = [secrets.token_hex(4).upper() for _ in range(count)]
        self.backup_codes = codes
        self.save(update_fields=['backup_codes'])
        return codes

    def verify_backup_code(self, code: str) -> bool:
        """Verify and consume a backup code."""
        if not self.backup_codes or code not in self.backup_codes:
            return False
        
        self.backup_codes.remove(code)
        self.save(update_fields=['backup_codes'])
        return True

    def deactivate_account(self) -> None:
        """Deactivate user account."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def activate_account(self) -> None:
        """Activate user account."""
        self.is_active = True
        self.save(update_fields=['is_active'])


class PasswordResetToken(TimeStampedModel):
    """Model for password reset tokens."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=255, unique=True, db_index=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not used)."""
        return not self.is_expired() and not self.is_used
    
    def mark_as_used(self) -> None:
        """Mark token as used."""
        self.is_used = True
        self.save(update_fields=['is_used'])


class MFACode(TimeStampedModel):
    """Model for MFA codes (email and SMS)."""
    
    CODE_TYPES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_codes')
    code = models.CharField(max_length=10)
    code_type = models.CharField(max_length=10, choices=CODE_TYPES)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'code_type', 'is_used']),
        ]
    
    def is_expired(self) -> bool:
        """Check if code has expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if code is valid (not expired and not used)."""
        return not self.is_expired() and not self.is_used
    
    def mark_as_used(self) -> None:
        """Mark code as used."""
        self.is_used = True
        self.save(update_fields=['is_used'])
