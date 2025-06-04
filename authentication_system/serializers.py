from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .utils import validate_password_strength, generate_username_from_email
from .image_utils import validate_image, process_profile_image
from drf_spectacular.utils import extend_schema_field
from typing import Dict, Any, Optional

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""

    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm', 'first_name', 'last_name', 'phone')
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'phone': {'required': False},
        }

    def validate_email(self, value: str) -> str:
        """Validate email format and uniqueness."""
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Please enter a valid email address.")

        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("A user with this email already exists.")

        return value.lower()

    def validate_password(self, value: str) -> str:
        """Validate password strength."""
        is_valid, error_message = validate_password_strength(value)
        if not is_valid:
            raise serializers.ValidationError(error_message)
        return value

    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': "Password fields didn't match."
            })
        return attrs

    def create(self, validated_data: Dict[str, Any]) -> User:
        """Create new user with hashed password."""
        validated_data.pop('password_confirm')

        # Generate unique username from email
        validated_data['username'] = generate_username_from_email(validated_data['email'])

        user = User.objects.create_user(**validated_data)
        return user


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)

    def validate_code(self, value: str) -> str:
        """Validate code format."""
        if not value.isdigit():
            raise serializers.ValidationError("Verification code must be 6 digits.")
        return value

    def validate(self, attrs):
        """Validate email and code combination."""
        email = attrs.get('email')
        code = attrs.get('code')

        try:
            user = User.objects.get(email=email.lower())
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or verification code.")

        if user.is_email_verified:
            raise serializers.ValidationError("Email is already verified.")

        if not user.verify_email_code(code):
            raise serializers.ValidationError("Invalid or expired verification code.")

        attrs['user'] = user
        return attrs


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        """Validate login credentials."""
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Get user by email
            try:
                user = User.objects.get(email=email.lower())
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")

            # Check if user can login (active and verified)
            if not user.can_login():
                if not user.is_active:
                    raise serializers.ValidationError("Account is deactivated.")
                if not user.is_email_verified:
                    raise serializers.ValidationError("Email verification required. Please check your email.")

            # Authenticate user
            user = authenticate(request=self.context.get('request'), username=email.lower(), password=password)
            if not user:
                raise serializers.ValidationError("Invalid email or password.")

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError("Must include email and password.")


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""

    email = serializers.EmailField()
    reset_method = serializers.ChoiceField(
        choices=[('code', 'Code'), ('link', 'Link')],
        default='code'
    )

    def validate_email(self, value: str) -> str:
        """Validate email exists."""
        try:
            user = User.objects.get(email=value.lower())
        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            pass
        return value.lower()


class PasswordResetVerifySerializer(serializers.Serializer):
    """Serializer for password reset verification and new password setting."""

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6, required=False)
    token = serializers.CharField(max_length=100, required=False)
    new_password = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        style={'input_type': 'password'}
    )

    def validate_new_password(self, value: str) -> str:
        """Validate new password strength."""
        is_valid, error_message = validate_password_strength(value)
        if not is_valid:
            raise serializers.ValidationError(error_message)
        return value

    def validate(self, attrs):
        """Validate reset method and credentials."""
        email = attrs.get('email')
        code = attrs.get('code')
        token = attrs.get('token')
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')

        # Check password confirmation
        if new_password != new_password_confirm:
            raise serializers.ValidationError({
                'new_password_confirm': "Password fields didn't match."
            })

        # Must provide either code or token
        if not code and not token:
            raise serializers.ValidationError("Either code or token must be provided.")

        if code and token:
            raise serializers.ValidationError("Provide either code or token, not both.")

        try:
            user = User.objects.get(email=email.lower())
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid reset credentials.")

        # Verify reset method
        if code:
            if not user.verify_password_reset_code(code):
                raise serializers.ValidationError("Invalid or expired reset code.")
        elif token:
            if not user.verify_password_reset_token(token):
                raise serializers.ValidationError("Invalid or expired reset token.")

        attrs['user'] = user
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile management."""

    full_name = serializers.SerializerMethodField(read_only=True)
    age = serializers.SerializerMethodField(read_only=True)
    profile_completion = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = (
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'phone', 'avatar', 'is_email_verified',
            'is_social_account', 'social_provider', 'created_at', 'last_login',
            # Basic profile fields
            'bio', 'date_of_birth', 'age', 'gender', 'location', 'website',
            # Social media profiles
            'facebook_profile', 'twitter_profile', 'linkedin_profile',
            'instagram_profile', 'github_profile',
            # Preferences
            'language', 'timezone', 'receive_notifications',
            # Stats
            'profile_completion'
        )
        read_only_fields = (
            'id', 'email', 'is_email_verified', 'is_social_account',
            'social_provider', 'created_at', 'last_login', 'age', 'profile_completion'
        )

    def validate_username(self, value: str) -> str:
        """Validate username uniqueness."""
        if value:
            # Check if this is an update (self.instance) or create operation
            query = User.objects.filter(username=value)
            if self.instance:
                query = query.exclude(pk=self.instance.pk)

            if query.exists():
                raise serializers.ValidationError("A user with this username already exists.")
        return value

    @extend_schema_field(serializers.CharField())
    def get_full_name(self, obj: User) -> str:
        """Get the user's full name."""
        return obj.get_full_name()

    @extend_schema_field(serializers.IntegerField(allow_null=True))
    def get_age(self, obj: User) -> Optional[int]:
        """Calculate age from date of birth."""
        if obj.date_of_birth:
            from django.utils import timezone
            from datetime import date

            today = date.today()
            birth_date = obj.date_of_birth
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            return age
        return None

    @extend_schema_field(serializers.IntegerField())
    def get_profile_completion(self, obj: User) -> int:
        """Return the profile completion percentage."""
        return obj.profile_completion_percentage

    def validate_avatar(self, value: Any) -> Any:
        """Validate and process the uploaded avatar image."""
        if value:
            is_valid, error_message = validate_image(value)
            if not is_valid:
                raise serializers.ValidationError(error_message)

            # Process the image before saving
            username = self.instance.username if self.instance else 'user'
            return process_profile_image(value, username)
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password."""

    current_password = serializers.CharField(style={'input_type': 'password'})
    new_password = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        style={'input_type': 'password'}
    )

    def validate_current_password(self, value: str) -> str:
        """Validate current password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value: str) -> str:
        """Validate new password strength."""
        is_valid, error_message = validate_password_strength(value)
        if not is_valid:
            raise serializers.ValidationError(error_message)
        return value

    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': "Password fields didn't match."
            })
        return attrs


class GoogleAuthSerializer(serializers.Serializer):
    """Serializer for Google OAuth authentication."""

    access_token = serializers.CharField()

    def validate_access_token(self, value: str) -> str:
        """Validate Google access token."""
        # This will be validated in the view using Google's API
        if not value:
            raise serializers.ValidationError("Access token is required.")
        return value


class GoogleAuthCodeSerializer(serializers.Serializer):
    """Serializer for Google OAuth code authentication."""

    code = serializers.CharField(
        help_text="Authorization code from Google OAuth flow"
    )

    def validate_code(self, value: str) -> str:
        """Validate Google authorization code."""
        if not value:
            raise serializers.ValidationError("Authorization code is required.")
        return value


class ResendVerificationSerializer(serializers.Serializer):
    """Serializer for resending verification email."""

    email = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        """Validate email exists and is not verified."""
        try:
            user = User.objects.get(email=value.lower())
            if user.is_email_verified:
                raise serializers.ValidationError("Email is already verified.")
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")
        return value.lower()
