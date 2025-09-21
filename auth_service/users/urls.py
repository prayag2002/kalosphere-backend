from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    LogoutView, RegisterView, ResendVerificationView, VerifyEmailView,
    CustomLoginView, ForgotPasswordView, ResetPasswordView, ChangePasswordView,
    AccountDeactivationView, UserProfileView, TOTPSetupView, TOTPDisableView,
    TOTPVerifyView, PhoneNumberSetupView, PhoneNumberVerifyView,
    EmailMFASetupView, EmailMFAVerifyView, SocialLoginView
)

urlpatterns = [
    # Basic Authentication
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", CustomLoginView.as_view(), name="login"),        
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify_email"),
    path("resend-verification/", ResendVerificationView.as_view(), name="resend_verification"),
    
    # Password Management
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot_password"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset_password"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    
    # Account Management
    path("deactivate-account/", AccountDeactivationView.as_view(), name="deactivate_account"),
    path("profile/", UserProfileView.as_view(), name="user_profile"),
    
    # Multi-Factor Authentication - TOTP
    path("mfa/totp/setup/", TOTPSetupView.as_view(), name="totp_setup"),
    path("mfa/totp/disable/", TOTPDisableView.as_view(), name="totp_disable"),
    path("mfa/totp/verify/", TOTPVerifyView.as_view(), name="totp_verify"),
    
    # Multi-Factor Authentication - SMS
    path("mfa/sms/setup/", PhoneNumberSetupView.as_view(), name="sms_setup"),
    path("mfa/sms/verify/", PhoneNumberVerifyView.as_view(), name="sms_verify"),
    
    # Multi-Factor Authentication - Email
    path("mfa/email/setup/", EmailMFASetupView.as_view(), name="email_mfa_setup"),
    path("mfa/email/verify/", EmailMFAVerifyView.as_view(), name="email_mfa_verify"),
    
    # Social Authentication
    path("social-login/", SocialLoginView.as_view(), name="social_login"),
]
