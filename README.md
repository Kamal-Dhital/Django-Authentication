# Django Authentication System

A comprehensive Django authentication system with REST API support, email verification, password reset functionality, Google OAuth2 integration, and enhanced user profiles with modern features.

## ✨ Features

### Core Authentication

- **User Registration** with Email Verification
- **Login/Logout** with Token-based Authentication
- **Password Reset** via Email (Code & Link methods)
- **Google OAuth2 Integration**
- **Email Verification System**
- **Comprehensive Error Handling**

### Enhanced User Profiles

- **Profile Completion Tracking** (0-100% completion)
- **Rich Profile Fields**: Bio, date of birth, gender, location, website
- **Social Media Integration**: Facebook, Twitter, LinkedIn, Instagram, GitHub profiles
- **User Preferences**: Language, timezone, notification settings
- **Profile Image Upload** with validation and processing
- **Age Calculation** from date of birth
- **User Search Functionality**

### API Documentation

- **OpenAPI 3.0 Specification** with complete schemas
- **Swagger UI** for interactive API exploration
- **ReDoc Documentation** for beautiful API docs
- **Categorized Endpoints** for better organization
- **Example Requests/Responses** for all endpoints

## 🚀 Quick Start

1. **Create and activate virtual environment:**

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Run migrations:**

```bash
python manage.py migrate
```

5. **Create a superuser (optional):**

```bash
python manage.py createsuperuser
```

6. **Run the development server:**

```bash
python manage.py runserver
```

7. **Access the API documentation:**

- Swagger UI: http://localhost:8000/docs/
- ReDoc: http://localhost:8000/redoc/
- Schema: http://localhost:8000/schema/

## 📡 API Endpoints

### 🔐 Authentication

- `POST /auth/register/` - User registration
- `POST /auth/login/` - User login
- `POST /auth/logout/` - User logout

### ✉️ Email Verification

- `POST /auth/verify-email/` - Verify email address
- `POST /auth/resend-verification/` - Resend verification email

### 🔒 Password Management

- `POST /auth/password-reset/request/` - Request password reset
- `POST /auth/password-reset/verify/` - Reset password with code
- `POST /auth/change-password/` - Change password (authenticated)

### 👤 User Management

- `GET /auth/profile/` - Get user profile
- `PUT /auth/profile/` - Update user profile
- `GET /auth/status/` - Get user status
- `GET /auth/search/?query=<search_term>` - Search users (authenticated)

### 🌐 Google OAuth

- `GET /auth/google-auth/` - Initiate Google OAuth
- `POST /auth/google-auth/` - Complete Google OAuth

### 📚 Documentation

- `GET /` - API root with endpoint list
- `GET /docs/` - Swagger UI documentation
- `GET /redoc/` - ReDoc documentation
- `GET /schema/` - OpenAPI schema

## 🏗️ User Profile Model

The enhanced `CustomUser` model includes:

### Basic Information

- `email` (primary identifier)
- `username` (optional, auto-generated if not provided)
- `first_name`, `last_name`
- `phone`
- `avatar` (profile image with validation)

### Profile Fields

- `bio` (500 character biography)
- `date_of_birth` (with automatic age calculation)
- `gender` (male, female, other, prefer_not_to_say)
- `location` (city, country)
- `website`

### Social Media Profiles

- `facebook_profile`
- `twitter_profile`
- `linkedin_profile`
- `instagram_profile`
- `github_profile`

### Preferences

- `language` (preferred language code)
- `timezone`
- `receive_notifications` (boolean)

### Computed Properties

- `age` (calculated from date_of_birth)
- `profile_completion_percentage` (0-100% based on filled fields)
- `get_full_name()` method

## 🔧 Environment Variables

Create a `.env` file with the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (optional, defaults to SQLite)
DATABASE_URL=sqlite:///db.sqlite3

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=your-email@gmail.com

# Google OAuth2 (optional)
GOOGLE_OAUTH2_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH2_CLIENT_SECRET=your-google-client-secret

# Site Configuration
FRONTEND_URL=http://localhost:3000
SITE_NAME=Your Site Name
```

## 📖 API Documentation

### Interactive Documentation

- **Swagger UI**: http://localhost:8000/docs/

  - Interactive API explorer
  - Try endpoints directly in browser
  - Complete request/response examples

- **ReDoc**: http://localhost:8000/redoc/
  - Beautiful, responsive documentation
  - Detailed schema information
  - Easy navigation

### API Schema

- **OpenAPI 3.0**: http://localhost:8000/schema/
  - Machine-readable API specification
  - Use with code generation tools
  - Import into Postman, Insomnia, etc.

## 🧪 Testing the API

### Example: User Registration

```bash
curl -X POST "http://localhost:8000/auth/register/" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "password_confirm": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Example: Login

```bash
curl -X POST "http://localhost:8000/auth/login/" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### Example: Profile Update (with authentication)

```bash
curl -X PUT "http://localhost:8000/auth/profile/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_TOKEN_HERE" \
  -d '{
    "bio": "Software developer passionate about Django",
    "location": "San Francisco, CA",
    "website": "https://example.com",
    "github_profile": "https://github.com/username"
  }'
```

## 🎯 Key Features Implemented

### 1. **Enhanced Profile System**

- 13 profile fields for comprehensive user information
- Automatic profile completion percentage calculation
- Image upload with validation and processing

### 2. **Advanced Authentication**

- Token-based authentication with DRF
- Email verification with customizable templates
- Multiple password reset methods (code/link)
- Google OAuth2 integration

### 3. **User Search & Discovery**

- Search across username, email, and names
- Case-insensitive search functionality
- Authenticated endpoint for privacy

### 4. **Developer Experience**

- Comprehensive OpenAPI documentation
- Interactive API testing with Swagger UI
- Organized endpoint categorization
- Detailed error responses

### 5. **Image Processing**

- Profile image validation (size, format, dimensions)
- Automatic image resizing and compression
- Unique filename generation
- Secure file handling

## 🛠️ Project Structure

```
authentication_system/
├── __init__.py
├── admin.py              # Django admin configuration
├── apps.py               # App configuration
├── models.py             # Enhanced CustomUser model
├── serializers.py        # DRF serializers with validation
├── views.py              # API views with OpenAPI docs
├── urls.py               # URL routing
├── permissions.py        # Custom permissions
├── utils.py              # Helper functions
├── image_utils.py        # Image processing utilities
├── signals.py            # Django signals
├── migrations/           # Database migrations
└── templates/            # Email templates
    └── authentication_system/
        └── emails/
            ├── verification_email.html
            ├── verification_email.txt
            ├── password_reset_email.html
            └── password_reset_email.txt
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📞 Support

For questions or issues:

1. Check the API documentation at `/docs/`
2. Review the OpenAPI schema at `/schema/`
3. Create an issue in the repository
