from typing import Any
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    - Validates input
    - Enforces Django password rules
    - Creates a User instance via UserManager
    """

    password: serializers.CharField = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = ("id", "email", "username", "password")
        extra_kwargs = {
            "email": {"required": True},
            "username": {"required": True},
        }

    def create(self, validated_data: dict[str, Any]) -> User:
        """
        Create and return a new User with a hashed password.
        """
        return User.objects.create_user(
            email=validated_data["email"],
            username=validated_data["username"],
            password=validated_data["password"],
        )
