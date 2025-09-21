# Kalosphere Auth Service

A comprehensive, enterprise-grade authentication service built with Django REST Framework that provides all essential authentication features including multi-factor authentication, social login, password management, and advanced security features.

## 🚀 Features

### ✅ Core Authentication
- **User Registration** with email verification
- **JWT-based Authentication** with access and refresh tokens
- **Email Verification** system
- **Password Management** (forgot, reset, change)

### ✅ Security Features
- **Account Locking** after multiple failed login attempts
- **Brute Force Protection** with django-axes
- **Password Validation** with Django's built-in validators
- **Rate Limiting** and security headers

### ✅ Multi-Factor Authentication (MFA)
- **TOTP (Time-based One-Time Password)** with QR code setup
- **Email Code-based MFA** for additional security
- **SMS OTP** integration with Twilio
- **Backup Codes** for TOTP recovery

### ✅ Social Authentication
- **Google OAuth2** integration
- **GitHub OAuth2** integration
- **Automatic user creation** and account linking

### ✅ Account Management
- **User Profile** management
- **Account Deactivation** with confirmation
- **Comprehensive user data** tracking

## 🛠️ Technology Stack

- **Backend**: Django 4.2.7 + Django REST Framework 3.14.0
- **Authentication**: JWT (Simple JWT) + django-allauth
- **Database**: PostgreSQL (SQLite for development)
- **MFA**: pyotp, qrcode for TOTP
- **SMS**: Twilio integration
- **Security**: django-axes, django-ratelimit
- **Type Safety**: Full type hints with mypy support

## 📋 Prerequisites

- Python 3.11+
- PostgreSQL (for production)
- Redis (optional, for caching)
- Twilio account (for SMS features)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd kalosphere-backend/auth_service
pip install -r requirements.txt
```

### 2. Environment Configuration

Create a `.env` file:

```env
# Django Settings
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=auth_service_db
DB_USER=postgres
DB_PASS=postgres
DB_HOST=localhost
DB_PORT=5432

# Email (Gmail example)
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Twilio (for SMS)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=your-twilio-number
```

### 3. Database Setup

```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### 4. Start Development Server

```bash
python manage.py runserver
```

The API will be available at `http://127.0.0.1:8000/api/auth/`

## 📚 API Documentation

Comprehensive API documentation is available in [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

### Quick API Examples

#### Register User
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "username": "username", "password": "securepass123"}'
```

#### Login
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

#### Get Profile (with JWT token)
```bash
curl -X GET http://127.0.0.1:8000/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🧪 Testing

Run the test script to verify all features:

```bash
python test_api.py
```

This will test:
- User registration and login
- Profile management
- Password changes
- MFA setup
- Brute force protection

## 🔧 Configuration

### Security Settings

```python
# Maximum login attempts before account lockout
MAX_LOGIN_ATTEMPTS = 5

# Account lock duration (minutes)
ACCOUNT_LOCK_DURATION = 30

# JWT token lifetimes
ACCESS_TOKEN_LIFETIME_MINUTES = 15
REFRESH_TOKEN_LIFETIME_DAYS = 7

# MFA code settings
MFA_CODE_LIFETIME = 5  # minutes
MFA_CODE_LENGTH = 6
```

### Email Configuration

The service supports multiple email backends:
- **Console backend** (development): `django.core.mail.backends.console.EmailBackend`
- **SMTP backend** (production): `django.core.mail.backends.smtp.EmailBackend`

## 🏗️ Project Structure

```
auth_service/
├── auth_service/          # Django project settings
│   ├── settings.py       # Main configuration
│   ├── urls.py          # URL routing
│   └── wsgi.py          # WSGI configuration
├── users/                # Authentication app
│   ├── models.py        # User and related models
│   ├── views.py         # API views
│   ├── serializers.py   # Data serializers
│   ├── urls.py          # App URL patterns
│   └── migrations/      # Database migrations
├── requirements.txt      # Python dependencies
├── docker-compose.yml   # Docker services
├── API_DOCUMENTATION.md # Complete API docs
├── test_api.py         # API test script
└── README.md           # This file
```

## 🔒 Security Features

### Account Protection
- **Automatic account locking** after failed login attempts
- **Configurable lockout duration** and attempt limits
- **Password strength validation** with Django's built-in validators

### Token Security
- **JWT token rotation** on refresh
- **Token blacklisting** for secure logout
- **Configurable token lifetimes**

### Multi-Factor Authentication
- **TOTP with QR codes** for easy setup
- **Backup codes** for recovery
- **Email and SMS** verification options

## 🌐 Production Deployment

### Database
Switch to PostgreSQL for production:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'auth_service_db',
        'USER': 'postgres',
        'PASSWORD': 'secure_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### Environment Variables
Set all required environment variables in production:
- `DJANGO_SECRET_KEY`
- `DEBUG=False`
- `ALLOWED_HOSTS`
- Database credentials
- Email SMTP settings
- Twilio credentials

### Security Checklist
- [ ] Use HTTPS in production
- [ ] Set strong `DJANGO_SECRET_KEY`
- [ ] Configure proper `ALLOWED_HOSTS`
- [ ] Use environment variables for secrets
- [ ] Enable database connection pooling
- [ ] Set up monitoring and logging
- [ ] Configure backup strategies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the [API Documentation](API_DOCUMENTATION.md)
- Run the test script to verify functionality
- Review the Django logs for error details

## 🎯 Roadmap

- [ ] WebSocket support for real-time notifications
- [ ] Advanced audit logging
- [ ] API rate limiting per user
- [ ] Device management and tracking
- [ ] Advanced MFA options (hardware tokens)
- [ ] Admin dashboard for user management

---

**Built with ❤️ for Kalosphere**
