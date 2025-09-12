from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom admin panel for User model.
    Extends Django's built-in UserAdmin but adapts it to our custom fields.
    """

    # Fields to display in the user list
    list_display = ("email", "username", "is_staff", "is_active", "is_email_verified")
    list_filter = ("is_staff", "is_active", "is_email_verified")

    # Fields available when editing a user
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("username",)}),
        (_("Permissions"), {"fields": ("is_active", "is_staff", "is_superuser", "is_email_verified", "groups", "user_permissions")}),
        (_("Important dates"), {"fields": ("last_login", "created_at", "updated_at")}),
    )

    # Fields for the add user form
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "username", "password1", "password2", "is_staff", "is_active"),
        }),
    )

    search_fields = ("email", "username")
    ordering = ("email",)
