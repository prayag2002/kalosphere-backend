import uuid
from typing import Any, Optional

from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from django.utils import timezone


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
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=50, unique=True, db_index=True)

    # Account status & roles
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    # Attach manager
    objects: UserManager = UserManager()

    # Use email for login instead of username
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self) -> str:
        """String representation for debugging/admin."""
        return f"{self.username} <{self.email}>"
