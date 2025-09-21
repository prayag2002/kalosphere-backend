# Kalosphere Auth Service API Documentation

## Overview

This is a comprehensive authentication service built with Django REST Framework that provides all essential authentication features including multi-factor authentication, social login, password management, and security features.

## Base URL
```
http://127.0.0.1:8000/api/auth/
```

## Authentication

Most endpoints require JWT authentication. Include the access token in the Authorization header:
```
Authorization: Bearer <access_token>
```

## API Endpoints

### 1. Basic Authentication

#### Register User
- **POST** `/register/`
- **Description**: Register a new user and send email verification
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "username": "username",
    "password": "securepassword123"
  }
  ```
- **Response**: 201 Created
  ```json
  {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "detail": "Verification email sent"
  }
  ```

#### Login
- **POST** `/login/`
- **Description**: Authenticate user and return JWT tokens
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword123"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "access": "access_token",
    "refresh": "refresh_token",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "username": "username",
      "mfa_enabled": false
    }
  }
  ```

#### Refresh Token
- **POST** `/refresh/`
- **Description**: Get new access token using refresh token
- **Body**:
  ```json
  {
    "refresh": "refresh_token"
  }
  ```

#### Logout
- **POST** `/logout/`
- **Description**: Blacklist refresh token
- **Body**:
  ```json
  {
    "refresh": "refresh_token"
  }
  ```

#### Verify Email
- **GET** `/verify-email/?token=<verification_token>`
- **Description**: Verify email address with token

#### Resend Verification
- **POST** `/resend-verification/`
- **Description**: Resend email verification
- **Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```

### 2. Password Management

#### Forgot Password
- **POST** `/forgot-password/`
- **Description**: Send password reset email
- **Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```

#### Reset Password
- **POST** `/reset-password/`
- **Description**: Reset password with token
- **Body**:
  ```json
  {
    "token": "reset_token",
    "new_password": "newpassword123",
    "confirm_password": "newpassword123"
  }
  ```

#### Change Password
- **POST** `/change-password/`
- **Description**: Change password for authenticated users
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "current_password": "oldpassword123",
    "new_password": "newpassword123",
    "confirm_password": "newpassword123"
  }
  ```

### 3. Account Management

#### User Profile
- **GET** `/profile/`
- **Description**: Get user profile information
- **Headers**: `Authorization: Bearer <access_token>`

- **PATCH** `/profile/`
- **Description**: Update user profile
- **Headers**: `Authorization: Bearer <access_token>`

#### Deactivate Account
- **POST** `/deactivate-account/`
- **Description**: Deactivate user account
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "password": "currentpassword",
    "confirm_deactivation": true
  }
  ```

### 4. Multi-Factor Authentication (MFA)

#### TOTP Setup
- **GET** `/mfa/totp/setup/`
- **Description**: Get TOTP setup information (QR code, secret, backup codes)
- **Headers**: `Authorization: Bearer <access_token>`
- **Response**:
  ```json
  {
    "secret": "base32_secret",
    "qr_code": "base64_encoded_qr_image",
    "backup_codes": ["CODE1", "CODE2", ...],
    "uri": "otpauth://totp/..."
  }
  ```

- **POST** `/mfa/totp/setup/`
- **Description**: Verify TOTP setup and enable MFA
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "token": "123456"
  }
  ```

#### TOTP Disable
- **POST** `/mfa/totp/disable/`
- **Description**: Disable TOTP MFA
- **Headers**: `Authorization: Bearer <access_token>`

#### TOTP Verify
- **POST** `/mfa/totp/verify/`
- **Description**: Verify TOTP token or backup code
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "token": "123456",
    "backup_code": "BACKUP1"  // Optional
  }
  ```

#### SMS MFA Setup
- **POST** `/mfa/sms/setup/`
- **Description**: Setup phone number for SMS MFA
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "phone_number": "+1234567890"
  }
  ```

#### SMS MFA Verify
- **POST** `/mfa/sms/verify/`
- **Description**: Verify SMS code
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "code": "123456",
    "code_type": "sms"
  }
  ```

#### Email MFA Setup
- **POST** `/mfa/email/setup/`
- **Description**: Send email MFA code
- **Headers**: `Authorization: Bearer <access_token>`

#### Email MFA Verify
- **POST** `/mfa/email/verify/`
- **Description**: Verify email MFA code
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "code": "123456",
    "code_type": "email"
  }
  ```

### 5. Social Authentication

#### Social Login
- **POST** `/social-login/`
- **Description**: Login with Google or GitHub
- **Body**:
  ```json
  {
    "provider": "google",  // or "github"
    "access_token": "oauth_access_token"
  }
  ```

## Security Features

### 1. Account Locking
- Accounts are automatically locked after 5 failed login attempts
- Lock duration: 30 minutes (configurable)
- Lock is automatically released after the duration expires

### 2. Password Validation
- Minimum 8 characters
- Cannot be entirely numeric
- Cannot be too common
- Cannot be too similar to user attributes

### 3. JWT Token Management
- Access tokens: 15 minutes (configurable)
- Refresh tokens: 7 days (configurable)
- Token rotation enabled
- Blacklisting support

### 4. Rate Limiting
- Integrated with django-axes for brute force protection
- Configurable limits and cooldown periods

## Environment Variables

Create a `.env` file with the following variables:

```env
# Django Settings
DJANGO_SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (PostgreSQL)
DB_NAME=auth_service_db
DB_USER=postgres
DB_PASS=postgres
DB_HOST=localhost
DB_PORT=5432

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com

# Twilio (for SMS)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=your-twilio-number

# Security Settings
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_DURATION=30
MFA_CODE_LIFETIME=5
MFA_CODE_LENGTH=6
PASSWORD_RESET_LIFETIME=60

# JWT Settings
ACCESS_TOKEN_LIFETIME_MINUTES=15
REFRESH_TOKEN_LIFETIME_DAYS=7
```

## Installation and Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Migrations**:
   ```bash
   python manage.py migrate
   ```

3. **Create Superuser**:
   ```bash
   python manage.py createsuperuser
   ```

4. **Start Development Server**:
   ```bash
   python manage.py runserver
   ```

## Testing the API

### Using curl

1. **Register a user**:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/auth/register/ \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "username": "testuser", "password": "testpass123"}'
   ```

2. **Login**:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "testpass123"}'
   ```

3. **Get profile** (replace TOKEN with actual access token):
   ```bash
   curl -X GET http://127.0.0.1:8000/api/auth/profile/ \
     -H "Authorization: Bearer TOKEN"
   ```

## Features Implemented

✅ **Basic Authentication**
- User registration with email verification
- Login/logout with JWT tokens
- Email verification system

✅ **Password Management**
- Forgot password (send reset link)
- Reset password (with token)
- Change password (authenticated users)

✅ **Account Management**
- Account deactivation
- User profile management

✅ **Security Features**
- Account locking after multiple failed logins
- Brute force protection with django-axes
- Password validation

✅ **Multi-Factor Authentication**
- TOTP (Time-based One-Time Password) with QR codes
- Email code-based MFA
- SMS OTP-based MFA (with Twilio)
- Backup codes for TOTP

✅ **Social Authentication**
- Google OAuth2 login
- GitHub OAuth2 login
- Automatic user creation and linking

✅ **Additional Features**
- CORS support
- Comprehensive error handling
- Type hints throughout
- Database migrations
- Environment-based configuration

## Production Considerations

1. **Database**: Switch to PostgreSQL for production
2. **Email**: Configure proper SMTP settings
3. **SMS**: Set up Twilio account and configure credentials
4. **Security**: Use strong secret keys and enable HTTPS
5. **Monitoring**: Add logging and monitoring
6. **Caching**: Implement Redis for caching
7. **Load Balancing**: Consider using a reverse proxy

This authentication service provides enterprise-grade security features and is ready for production use with proper configuration.
