import uuid
import secrets
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from datetime import timedelta
from typing import Any, Optional


class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier
    instead of username.
    """
    def create_user(self, email: str, password: Optional[str] = None, **extra_fields: Any):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields.setdefault('username', email.split('@')[0])
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: Optional[str] = None, **extra_fields: Any):
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Uses email as the primary identifier instead of username.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, verbose_name='Email Address')
    username = models.CharField(max_length=150, unique=True, blank=True, null=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    phone = models.CharField(max_length=20, blank=True, null=True)

    # Profile fields
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True, null=True, help_text="User biography")
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=20, blank=True, null=True,
                             choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other'), ('prefer_not_to_say', 'Prefer not to say')])
    location = models.CharField(max_length=100, blank=True, null=True, help_text="City, Country")
    website = models.URLField(max_length=200, blank=True, null=True)

    # Social media profiles
    facebook_profile = models.URLField(max_length=255, blank=True, null=True)
    twitter_profile = models.URLField(max_length=255, blank=True, null=True)
    linkedin_profile = models.URLField(max_length=255, blank=True, null=True)
    instagram_profile = models.URLField(max_length=255, blank=True, null=True)
    github_profile = models.URLField(max_length=255, blank=True, null=True)

    # Preferences
    language = models.CharField(max_length=10, blank=True, null=True, default='en',
                               help_text="Preferred language code")
    timezone = models.CharField(max_length=50, blank=True, null=True, default='UTC')
    receive_notifications = models.BooleanField(default=True)

    # Email verification fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    email_verification_code_expires = models.DateTimeField(blank=True, null=True)

    # Password reset fields
    password_reset_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_code_expires = models.DateTimeField(blank=True, null=True)
    password_reset_token = models.CharField(max_length=100, blank=True, null=True)
    password_reset_token_expires = models.DateTimeField(blank=True, null=True)

    # Social auth tracking
    is_social_account = models.BooleanField(default=False)
    social_provider = models.CharField(max_length=50, blank=True, null=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip() or self.email

    @property
    def profile_completion_percentage(self):
        """
        Calculate the percentage of profile completion based on filled fields.
        Returns an integer between 0-100 representing the completion percentage.
        """
        # Define fields that contribute to profile completion
        profile_fields = [
            'first_name', 'last_name', 'phone', 'avatar', 'bio',
            'date_of_birth', 'gender', 'location', 'website',
            'facebook_profile', 'twitter_profile', 'linkedin_profile',
            'instagram_profile', 'github_profile'
        ]

        # Calculate how many are filled
        filled_fields = sum(1 for field in profile_fields if getattr(self, field))

        # Calculate percentage (avatar and basic info are weighted more)
        total_fields = len(profile_fields)
        percentage = int((filled_fields / total_fields) * 100)

        return min(100, percentage)  # Cap at 100%

    def get_full_name(self):
        """Return user's full name or email if not set."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        return self.email.split('@')[0]

    def generate_verification_code(self):
        """Generate a 6-digit verification code for email verification."""
        self.email_verification_code = str(secrets.randbelow(900000) + 100000)
        self.email_verification_code_expires = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires'])
        return self.email_verification_code

    def verify_email_code(self, code):
        """Verify the email verification code."""
        if (self.email_verification_code == code and
            self.email_verification_code_expires and
            timezone.now() <= self.email_verification_code_expires):
            self.is_email_verified = True
            self.email_verification_code = None
            self.email_verification_code_expires = None
            self.save(update_fields=[
                'is_email_verified',
                'email_verification_code',
                'email_verification_code_expires'
            ])
            return True
        return False

    def generate_password_reset_code(self):
        """Generate a 6-digit code for password reset."""
        self.password_reset_code = str(secrets.randbelow(900000) + 100000)
        self.password_reset_code_expires = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['password_reset_code', 'password_reset_code_expires'])
        return self.password_reset_code

    def generate_password_reset_token(self):
        """Generate a secure token for password reset links."""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_token_expires = timezone.now() + timedelta(hours=1)
        self.save(update_fields=['password_reset_token', 'password_reset_token_expires'])
        return self.password_reset_token

    def verify_password_reset_code(self, code):
        """Verify the password reset code."""
        return (self.password_reset_code == code and
                self.password_reset_code_expires and
                timezone.now() <= self.password_reset_code_expires)

    def verify_password_reset_token(self, token):
        """Verify the password reset token."""
        return (self.password_reset_token == token and
                self.password_reset_token_expires and
                timezone.now() <= self.password_reset_token_expires)

    def clear_password_reset_data(self):
        """Clear all password reset related data."""
        self.password_reset_code = None
        self.password_reset_code_expires = None
        self.password_reset_token = None
        self.password_reset_token_expires = None
        self.save(update_fields=[
            'password_reset_code',
            'password_reset_code_expires',
            'password_reset_token',
            'password_reset_token_expires'
        ])

    def can_login(self):
        """Check if user can login (must be verified and active)."""
        return self.is_active and self.is_email_verified


class UserSession(models.Model):
    """Track user sessions for security purposes."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-last_activity']

    def __str__(self):
        return f"{self.user.email} - {self.ip_address}"
