from typing import Any
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.conf import settings
from .models import User, PasswordResetToken, MFACode


class RegisterSerializer(serializers.ModelSerializer["User"]):
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


class ForgotPasswordSerializer(serializers.Serializer):
    """Serializer for forgot password request."""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value: str) -> str:
        """Validate that user exists."""
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value


class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for password reset."""
    
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    confirm_password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    
    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Validate that passwords match."""
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs
    
    def validate_token(self, value: str) -> str:
        """Validate reset token."""
        try:
            token_obj = PasswordResetToken.objects.get(token=value)
            if not token_obj.is_valid():
                raise serializers.ValidationError("Invalid or expired token.")
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password (authenticated users)."""
    
    current_password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    confirm_password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    
    def validate_current_password(self, value: str) -> str:
        """Validate current password."""
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value
    
    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Validate that passwords match."""
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs


class AccountDeactivationSerializer(serializers.Serializer):
    """Serializer for account deactivation."""
    
    password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    confirm_deactivation = serializers.BooleanField(required=True)
    
    def validate_password(self, value: str) -> str:
        """Validate password."""
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Password is incorrect.")
        return value
    
    def validate_confirm_deactivation(self, value: bool) -> bool:
        """Validate confirmation."""
        if not value:
            raise serializers.ValidationError("You must confirm account deactivation.")
        return value


class TOTPSetupSerializer(serializers.Serializer):
    """Serializer for TOTP setup."""
    
    token = serializers.CharField(required=True, max_length=6)
    
    def validate_token(self, value: str) -> str:
        """Validate TOTP token."""
        user = self.context["request"].user
        if not user.verify_totp(value):
            raise serializers.ValidationError("Invalid TOTP token.")
        return value


class TOTPVerifySerializer(serializers.Serializer):
    """Serializer for TOTP verification."""
    
    token = serializers.CharField(required=True, max_length=6)
    backup_code = serializers.CharField(required=False, max_length=8)
    
    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Validate TOTP token or backup code."""
        user = self.context["request"].user
        token = attrs.get("token")
        backup_code = attrs.get("backup_code")
        
        if backup_code:
            if not user.verify_backup_code(backup_code):
                raise serializers.ValidationError("Invalid backup code.")
        elif not user.verify_totp(token):
            raise serializers.ValidationError("Invalid TOTP token.")
        
        return attrs


class PhoneNumberSerializer(serializers.Serializer):
    """Serializer for phone number verification."""
    
    phone_number = serializers.CharField(required=True, max_length=20)
    
    def validate_phone_number(self, value: str) -> str:
        """Validate phone number format."""
        import phonenumbers
        try:
            parsed = phonenumbers.parse(value, None)
            if not phonenumbers.is_valid_number(parsed):
                raise serializers.ValidationError("Invalid phone number.")
        except phonenumbers.NumberParseException:
            raise serializers.ValidationError("Invalid phone number format.")
        return value


class MFACodeSerializer(serializers.Serializer):
    """Serializer for MFA code verification."""
    
    code = serializers.CharField(required=True, max_length=10)
    code_type = serializers.ChoiceField(choices=MFACode.CODE_TYPES, required=True)
    
    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Validate MFA code."""
        user = self.context["request"].user
        code = attrs["code"]
        code_type = attrs["code_type"]
        
        try:
            mfa_code = MFACode.objects.get(
                user=user,
                code=code,
                code_type=code_type,
                is_used=False
            )
            if not mfa_code.is_valid():
                raise serializers.ValidationError("Invalid or expired code.")
            mfa_code.mark_as_used()
        except MFACode.DoesNotExist:
            raise serializers.ValidationError("Invalid code.")
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer["User"]):
    """Serializer for user profile."""
    
    class Meta:
        model = User
        fields = (
            "id", "email", "username", "is_email_verified", 
            "mfa_enabled", "email_mfa_enabled", "is_phone_verified",
            "created_at", "updated_at"
        )
        read_only_fields = ("id", "created_at", "updated_at")


class SocialLoginSerializer(serializers.Serializer):
    """Serializer for social login."""
    
    provider = serializers.ChoiceField(choices=["google", "github"], required=True)
    access_token = serializers.CharField(required=True)
