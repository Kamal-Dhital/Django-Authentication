import os
import logging
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.contrib.auth import get_user_model
from decouple import config

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the client's real IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def send_verification_email(user, code):
    """
    Send email verification code to user.

    Args:
        user: CustomUser instance
        code: 6-digit verification code

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        subject = 'Verify Your Email Address'

        # Email context
        context = {
            'user': user,
            'code': code,
            'site_name': getattr(settings, 'SITE_NAME', 'Authentication System'),
            'frontend_url': config('FRONTEND_URL', default='http://localhost:3000'),
        }

        # Render email templates
        html_message = render_to_string('authentication_system/emails/verification_email.html', context)
        plain_message = render_to_string('authentication_system/emails/verification_email.txt', context)

        # Fallback to simple message if templates don't exist
        if not html_message.strip():
            html_message = f"""
            <h2>Verify Your Email Address</h2>
            <p>Hello {user.first_name or user.email},</p>
            <p>Thank you for registering! Please use the following verification code:</p>
            <h3 style="color: #007bff; font-size: 24px; letter-spacing: 2px;">{code}</h3>
            <p>This code will expire in 15 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            """

        if not plain_message.strip():
            plain_message = f"""
            Verify Your Email Address

            Hello {user.first_name or user.email},

            Thank you for registering! Please use the following verification code: {code}

            This code will expire in 15 minutes.

            If you didn't request this, please ignore this email.
            """

        result = send_mail(
            subject=subject,
            message=plain_message,
            from_email=config('DEFAULT_FROM_EMAIL', default=settings.DEFAULT_FROM_EMAIL),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Verification email sent to {user.email}")
        return bool(result)

    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        return False


def send_password_reset_email(user, code=None, token=None):
    """
    Send password reset email with either code or token.

    Args:
        user: CustomUser instance
        code: 6-digit reset code (optional)
        token: Secure reset token (optional)

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        subject = 'Reset Your Password'

        # Determine reset method
        reset_method = 'code' if code else 'token'
        frontend_url = config('FRONTEND_URL', default='http://localhost:3000')
        reset_url = f"{frontend_url}/reset-password"

        if token:
            reset_url += f"?token={token}"

        # Email context
        context = {
            'user': user,
            'code': code,
            'token': token,
            'reset_url': reset_url,
            'reset_method': reset_method,
            'site_name': getattr(settings, 'SITE_NAME', 'Authentication System'),
            'frontend_url': frontend_url,
        }

        # Render email templates
        html_message = render_to_string('authentication_system/emails/password_reset_email.html', context)
        plain_message = render_to_string('authentication_system/emails/password_reset_email.txt', context)

        # Fallback to simple message if templates don't exist
        if not html_message.strip():
            if code:
                html_message = f"""
                <h2>Reset Your Password</h2>
                <p>Hello {user.first_name or user.email},</p>
                <p>You requested a password reset. Please use the following code:</p>
                <h3 style="color: #dc3545; font-size: 24px; letter-spacing: 2px;">{code}</h3>
                <p>This code will expire in 15 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
                """
            else:
                html_message = f"""
                <h2>Reset Your Password</h2>
                <p>Hello {user.first_name or user.email},</p>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="{reset_url}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
                """

        if not plain_message.strip():
            if code:
                plain_message = f"""
                Reset Your Password

                Hello {user.first_name or user.email},

                You requested a password reset. Please use the following code: {code}

                This code will expire in 15 minutes.

                If you didn't request this, please ignore this email.
                """
            else:
                plain_message = f"""
                Reset Your Password

                Hello {user.first_name or user.email},

                You requested a password reset. Click the link below to reset your password:
                {reset_url}

                This link will expire in 1 hour.

                If you didn't request this, please ignore this email.
                """

        result = send_mail(
            subject=subject,
            message=plain_message,
            from_email=config('DEFAULT_FROM_EMAIL', default=settings.DEFAULT_FROM_EMAIL),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Password reset email sent to {user.email}")
        return bool(result)

    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        return False


def send_welcome_email(user):
    """
    Send welcome email after successful verification.

    Args:
        user: CustomUser instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        subject = 'Welcome! Your Account is Verified'

        context = {
            'user': user,
            'site_name': getattr(settings, 'SITE_NAME', 'Authentication System'),
            'frontend_url': config('FRONTEND_URL', default='http://localhost:3000'),
        }

        # Simple welcome message
        html_message = f"""
        <h2>Welcome to {context['site_name']}!</h2>
        <p>Hello {user.first_name or user.email},</p>
        <p>Your email has been successfully verified and your account is now active.</p>
        <p>You can now log in and start using our services.</p>
        <p><a href="{context['frontend_url']}/login" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Login Now</a></p>
        <p>Thank you for joining us!</p>
        """

        plain_message = f"""
        Welcome to {context['site_name']}!

        Hello {user.first_name or user.email},

        Your email has been successfully verified and your account is now active.
        You can now log in and start using our services.

        Login at: {context['frontend_url']}/login

        Thank you for joining us!
        """

        result = send_mail(
            subject=subject,
            message=plain_message,
            from_email=config('DEFAULT_FROM_EMAIL', default=settings.DEFAULT_FROM_EMAIL),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Welcome email sent to {user.email}")
        return bool(result)

    except Exception as e:
        logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")
        return False


class EmailThrottle:
    """Simple email throttling to prevent spam."""

    _email_counts = {}

    @classmethod
    def can_send_email(cls, email, max_emails=5, time_window=3600):
        """
        Check if we can send email to this address.

        Args:
            email: Email address
            max_emails: Maximum emails allowed in time window
            time_window: Time window in seconds (default 1 hour)

        Returns:
            bool: True if email can be sent, False otherwise
        """
        import time

        current_time = time.time()

        if email not in cls._email_counts:
            cls._email_counts[email] = []

        # Remove old entries
        cls._email_counts[email] = [
            timestamp for timestamp in cls._email_counts[email]
            if current_time - timestamp < time_window
        ]

        # Check if under limit
        if len(cls._email_counts[email]) < max_emails:
            cls._email_counts[email].append(current_time)
            return True

        return False


def validate_password_strength(password):
    """
    Validate password strength.

    Args:
        password: Password string

    Returns:
        tuple: (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character."

    return True, "Password is strong."


def generate_username_from_email(email):
    """
    Generate a unique username from email address.

    Args:
        email: Email address

    Returns:
        str: Unique username
    """
    import re

    # Extract base username from email
    base_username = email.split('@')[0]

    # Clean username (remove special chars, keep alphanumeric and underscore)
    base_username = re.sub(r'[^\w]', '_', base_username)

    # Ensure it starts with a letter
    if not base_username[0].isalpha():
        base_username = 'user_' + base_username

    # Check if username exists and make it unique
    username = base_username
    counter = 1

    while User.objects.filter(username=username).exists():
        username = f"{base_username}_{counter}"
        counter += 1

    return username
