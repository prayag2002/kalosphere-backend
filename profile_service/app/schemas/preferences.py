"""User preferences schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PreferencesUpdate(BaseModel):
    """Schema for updating preferences."""

    theme: Literal["light", "dark", "system"] | None = None
    email_notifications: bool | None = None
    push_notifications: bool | None = None
    show_online_status: bool | None = None
    allow_messages_from: Literal["everyone", "followers", "none"] | None = None


class PreferencesResponse(BaseModel):
    """Current user preferences."""

    model_config = ConfigDict(from_attributes=True)

    theme: str = Field(default="system")
    email_notifications: bool = Field(default=True)
    push_notifications: bool = Field(default=True)
    show_online_status: bool = Field(default=True)
    allow_messages_from: str = Field(default="everyone")

    @classmethod
    def from_jsonb(cls, data: dict) -> "PreferencesResponse":
        """Create from JSONB preferences dict with defaults."""
        return cls(
            theme=data.get("theme", "system"),
            email_notifications=data.get("email_notifications", True),
            push_notifications=data.get("push_notifications", True),
            show_online_status=data.get("show_online_status", True),
            allow_messages_from=data.get("allow_messages_from", "everyone"),
        )
