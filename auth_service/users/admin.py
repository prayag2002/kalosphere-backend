from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):  # type: ignore[misc]
    """
    Custom admin panel for User model.
    Extends Django's built-in UserAdmin but adapts it to our custom User.
    """

    # Which fields show in the admin list view
    list_display = ("email", "username", "is_staff", "is_active", "is_email_verified")
    list_filter = ("is_staff", "is_active", "is_email_verified")

    # Which fields are shown on the user detail page
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("username",)}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_email_verified",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "created_at", "updated_at")}),
    )

    # Fields for the add-user form
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "username",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )

    search_fields = ("email", "username")
    ordering = ("email",)

    # Use email as the unique identifier
    def get_fieldsets(self, request, obj=None):
        if not obj:
            return self.add_fieldsets
        return super().get_fieldsets(request, obj)

    def get_add_fieldsets(self, request):
        return self.add_fieldsets
