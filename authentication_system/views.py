from django.contrib.auth import get_user_model
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
import requests

from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from .serializers import (
    UserRegistrationSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetVerifySerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    ResendVerificationSerializer,
    GoogleAuthCodeSerializer
)
from .permissions import IsEmailVerified, IsOwnerOrReadOnly
from .utils import send_verification_email, send_password_reset_email

from django.db.models import Q
from rest_framework import filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter

User = get_user_model()


class RegisterView(APIView):
    """User registration endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Authentication'],
        summary='Register a new user',
        description='Create a new user account with email verification. A verification code will be sent to the provided email address.',
        request=UserRegistrationSerializer,
        responses={
            201: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'user_id': {'type': 'string'},
                    'verification_required': {'type': 'boolean'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'email': {'type': 'array', 'items': {'type': 'string'}},
                    'password': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Registration Request',
                value={
                    'email': 'user@example.com',
                    'password': 'SecurePassword123!',
                    'password_confirm': 'SecurePassword123!',
                    'first_name': 'John',
                    'last_name': 'Doe'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Send verification email
            verification_code = user.generate_verification_code()
            send_verification_email(user, verification_code)

            return Response({
                'message': 'Registration successful',
                'user_id': str(user.id),
                'verification_required': True
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """Email verification endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Email Verification'],
        summary='Verify email address',
        description='Verify user email address using the verification code sent during registration.',
        request=EmailVerificationSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'user_id': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'code': {'type': 'array', 'items': {'type': 'string'}},
                    'email': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Email Verification Request',
                value={
                    'email': 'user@example.com',
                    'code': '123456'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            # The serializer already validated everything and provided the user
            user = serializer.validated_data['user']

            return Response({
                'message': 'Email verified successfully',
                'user_id': str(user.id),
                'email': user.email
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """User login endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Authentication'],
        summary='User login',
        description='Authenticate user with email and password. Returns an authentication token.',
        request=LoginSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'token': {'type': 'string'},
                    'user_id': {'type': 'string'},
                    'email': {'type': 'string'},
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'non_field_errors': {'type': 'array', 'items': {'type': 'string'}},
                    'email': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Login Request',
                value={
                    'email': 'user@example.com',
                    'password': 'SecurePassword123!'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Create or get token
            token, created = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user_id': str(user.id),
                'email': user.email,
                'message': 'Login successful'
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """User logout endpoint."""
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        tags=['Authentication'],
        summary='User logout',
        description='Logout the authenticated user and invalidate their token.',
        request=None,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            },
            401: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            }
        }
    )
    def post(self, request):
        try:
            # Delete the user's token
            Token.objects.filter(user=request.user).delete()
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Logout failed'
            }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    """Password reset request endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Password Reset'],
        summary='Request password reset',
        description='Request a password reset email. A reset code will be sent if the email is registered.',
        request=PasswordResetRequestSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'email': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            }
        },
        examples=[
            OpenApiExample(
                'Password Reset Request',
                value={
                    'email': 'user@example.com'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                reset_code = user.generate_password_reset_code()
                send_password_reset_email(user, code=reset_code)
            except User.DoesNotExist:
                pass  # Don't reveal if email exists

            return Response({
                'message': 'If your email is registered, you will receive password reset instructions.'
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerifyView(APIView):
    """Password reset verification endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Password Reset'],
        summary='Verify password reset',
        description='Complete password reset using the verification code sent via email.',
        request=PasswordResetVerifySerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            },
            404: {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Password Reset Verification Request',
                value={
                    'email': 'user@example.com',
                    'code': '123456',
                    'new_password': 'NewSecurePassword123!',
                    'password_confirm': 'NewSecurePassword123!'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = PasswordResetVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            try:
                user = User.objects.get(email=email)
                if user.verify_password_reset_code(code):
                    user.set_password(new_password)
                    user.save()

                    # Clear any existing tokens
                    Token.objects.filter(user=user).delete()

                    return Response({
                        'message': 'Password reset successful'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Invalid or expired reset code'
                    }, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """Change password endpoint for authenticated users."""
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        tags=['User Management'],
        summary='Change password',
        description='Change password for authenticated user. User will need to log in again after password change.',
        request=ChangePasswordSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'old_password': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'new_password': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            },
            401: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Change Password Request',
                value={
                    'old_password': 'CurrentPassword123!',
                    'new_password': 'NewSecurePassword123!',
                    'password_confirm': 'NewSecurePassword123!'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            new_password = serializer.validated_data['new_password']

            user.set_password(new_password)
            user.save()

            # Clear tokens to force re-login
            Token.objects.filter(user=user).delete()

            return Response({
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """User profile endpoint."""
    permission_classes = [permissions.IsAuthenticated, IsEmailVerified]

    @extend_schema(
        tags=['User Management'],
        summary='Get user profile',
        description='Retrieve authenticated user profile information.',
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'email': {'type': 'string'},
                    'username': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'full_name': {'type': 'string'},
                    'phone': {'type': 'string'},
                    'avatar': {'type': 'string', 'format': 'uri'},
                    'is_email_verified': {'type': 'boolean'},
                    'is_active': {'type': 'boolean'},
                    'created_at': {'type': 'string', 'format': 'date-time'},
                    'last_login': {'type': 'string', 'format': 'date-time'},
                    # Basic profile fields
                    'bio': {'type': 'string'},
                    'date_of_birth': {'type': 'string', 'format': 'date'},
                    'age': {'type': 'integer'},
                    'gender': {'type': 'string'},
                    'location': {'type': 'string'},
                    'website': {'type': 'string', 'format': 'uri'},
                    # Social media profiles
                    'facebook_profile': {'type': 'string', 'format': 'uri'},
                    'twitter_profile': {'type': 'string', 'format': 'uri'},
                    'linkedin_profile': {'type': 'string', 'format': 'uri'},
                    'instagram_profile': {'type': 'string', 'format': 'uri'},
                    'github_profile': {'type': 'string', 'format': 'uri'},
                    # Preferences
                    'language': {'type': 'string'},
                    'timezone': {'type': 'string'},
                    'receive_notifications': {'type': 'boolean'}
                }
            },
            401: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            },
            403: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            }
        }
    )
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        tags=['User Management'],
        summary='Update user profile',
        description='Update authenticated user profile information.',
        request=UserProfileSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'email': {'type': 'string'},
                    'username': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'full_name': {'type': 'string'},
                    'phone': {'type': 'string'},
                    'avatar': {'type': 'string', 'format': 'uri'},
                    'is_email_verified': {'type': 'boolean'},
                    'is_active': {'type': 'boolean'},
                    'created_at': {'type': 'string', 'format': 'date-time'},
                    'last_login': {'type': 'string', 'format': 'date-time'},
                    # Basic profile fields
                    'bio': {'type': 'string'},
                    'date_of_birth': {'type': 'string', 'format': 'date'},
                    'age': {'type': 'integer'},
                    'gender': {'type': 'string'},
                    'location': {'type': 'string'},
                    'website': {'type': 'string', 'format': 'uri'},
                    # Social media profiles
                    'facebook_profile': {'type': 'string', 'format': 'uri'},
                    'twitter_profile': {'type': 'string', 'format': 'uri'},
                    'linkedin_profile': {'type': 'string', 'format': 'uri'},
                    'instagram_profile': {'type': 'string', 'format': 'uri'},
                    'github_profile': {'type': 'string', 'format': 'uri'},
                    # Preferences
                    'language': {'type': 'string'},
                    'timezone': {'type': 'string'},
                    'receive_notifications': {'type': 'boolean'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'email': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'first_name': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'username': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'website': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'date_of_birth': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            },
            401: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            },
            403: {
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Profile Update Request',
                value={
                    'first_name': 'John',
                    'last_name': 'Doe'
                },
                request_only=True
            )
        ]
    )
    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationView(APIView):
    """Resend verification email endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Email Verification'],
        summary='Resend verification email',
        description='Resend email verification code to the specified email address.',
        request=ResendVerificationSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            },
            404: {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Resend Verification Request',
                value={
                    'email': 'user@example.com'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                if user.is_email_verified:
                    return Response({
                        'message': 'Email is already verified'
                    }, status=status.HTTP_400_BAD_REQUEST)

                verification_code = user.generate_verification_code()
                send_verification_email(user, verification_code)

                return Response({
                    'message': 'Verification email sent'
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=['User Management'],
    summary='Get user status',
    description='Get current user status information including verification status.',
    responses={
        200: {
            'type': 'object',
            'properties': {
                'user_id': {'type': 'string'},
                'email': {'type': 'string'},
                'username': {'type': 'string'},
                'is_email_verified': {'type': 'boolean'},
                'is_active': {'type': 'boolean'},
                'first_name': {'type': 'string'},
                'last_name': {'type': 'string'},
                'avatar': {'type': 'string', 'format': 'uri'},
                'location': {'type': 'string'},
                'language': {'type': 'string'},
                'timezone': {'type': 'string'}
            }
        },
        401: {
            'type': 'object',
            'properties': {
                'detail': {'type': 'string'}
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_status(request):
    """Get user status information."""
    user = request.user
    return Response({
        'user_id': str(user.id),
        'email': user.email,
        'username': user.username,
        'is_email_verified': user.is_email_verified,
        'is_active': user.is_active,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None,
        'location': user.location,
        'language': user.language,
        'timezone': user.timezone
    }, status=status.HTTP_200_OK)


@extend_schema(
    tags=['Authentication'],
    summary='Refresh authentication token',
    description='Refresh the user authentication token. Invalidates the old token and creates a new one.',
    request=None,
    responses={
        200: {
            'type': 'object',
            'properties': {
                'token': {'type': 'string'},
                'message': {'type': 'string'}
            }
        },
        401: {
            'type': 'object',
            'properties': {
                'detail': {'type': 'string'}
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def refresh_token(request):
    """Refresh user token."""
    # Delete old token and create new one
    Token.objects.filter(user=request.user).delete()
    token = Token.objects.create(user=request.user)

    return Response({
        'token': token.key,
        'message': 'Token refreshed successfully'
    }, status=status.HTTP_200_OK)


class GoogleAuthView(APIView):
    """Google OAuth2 authentication endpoint."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=['Google OAuth'],
        summary='Initiate Google OAuth2 login',
        description='Get Google OAuth2 authorization URL to redirect user for authentication.',
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'auth_url': {'type': 'string'},
                    'message': {'type': 'string'}
                }
            }
        }
    )
    def get(self, request):
        """Initiate Google OAuth2 login flow."""
        from urllib.parse import urlencode
        from django.conf import settings

        google_auth_url = 'https://accounts.google.com/o/oauth2/auth'
        redirect_uri = request.build_absolute_uri('/auth/google-auth/callback/')

        params = {
            'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE),
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': 'consent'
        }

        auth_url = f"{google_auth_url}?{urlencode(params)}"

        return Response({
            'auth_url': auth_url,
            'message': 'Redirect to this URL for Google authentication'
        }, status=status.HTTP_200_OK)

    @extend_schema(
        tags=['Google OAuth'],
        summary='Complete Google OAuth2 authentication',
        description='Complete Google OAuth2 authentication using authorization code received from Google.',
        request=GoogleAuthCodeSerializer,
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'token': {'type': 'string'},
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'string'},
                            'email': {'type': 'string'},
                            'first_name': {'type': 'string'},
                            'last_name': {'type': 'string'},
                            'is_email_verified': {'type': 'boolean'}
                        }
                    },
                    'created': {'type': 'boolean'},
                    'message': {'type': 'string'}
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        examples=[
            OpenApiExample(
                'Google Auth Request',
                value={
                    'code': 'authorization_code_from_google'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        """Complete Google OAuth2 authentication with authorization code."""
        auth_code = request.data.get('code')
        if not auth_code:
            return Response({
                'error': 'Authorization code is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Exchange authorization code for access token
            token_data = self._exchange_code_for_token(auth_code, request)

            # Get user info from Google
            user_info = self._get_google_user_info(token_data['access_token'])

            # Create or get user
            user, created = self._get_or_create_user(user_info)

            # Create or get token
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_email_verified': user.is_email_verified,
                },
                'created': created,
                'message': 'Google authentication successful'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': f'Google authentication failed: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    def _exchange_code_for_token(self, code, request):
        """Exchange authorization code for access token."""
        from django.conf import settings

        token_url = 'https://oauth2.googleapis.com/token'
        redirect_uri = request.build_absolute_uri('/auth/google-auth/callback/')

        data = {
            'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        }

        response = requests.post(token_url, data=data)
        response.raise_for_status()
        return response.json()

    def _get_google_user_info(self, access_token):
        """Get user information from Google using access token."""
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.get(user_info_url, headers=headers)
        response.raise_for_status()
        return response.json()

    def _get_or_create_user(self, user_info):
        """Get or create user from Google user info."""
        email = user_info.get('email')
        if not email:
            raise ValueError('Email not provided by Google')

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', ''),
                'is_email_verified': True,  # Google emails are pre-verified
                'is_active': True,
            }
        )

        # Update user info if user already exists
        if not created:
            user.first_name = user_info.get('given_name', user.first_name)
            user.last_name = user_info.get('family_name', user.last_name)
            user.is_email_verified = True
            user.save()

        return user, created


@extend_schema(
    tags=['User Management'],
    summary='Search for users',
    description='Search for users by username, email, first name, or last name.',
    parameters=[
        OpenApiParameter(name='query', description='Search query', required=True, type=str),
    ],
    responses={
        200: UserProfileSerializer(many=True),
        400: {'type': 'object', 'properties': {'detail': {'type': 'string'}}},
        401: {'type': 'object', 'properties': {'detail': {'type': 'string'}}},
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_users(request):
    """
    Search for users by username, email, first name, or last name.
    Query parameter: 'query' - search term
    """
    query = request.GET.get('query', '')

    if len(query) < 3:
        return Response(
            {"detail": "Search query must be at least 3 characters long."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Search using case-insensitive lookups
    users = User.objects.filter(
        Q(username__icontains=query) |
        Q(email__icontains=query) |
        Q(first_name__icontains=query) |
        Q(last_name__icontains=query)
    ).exclude(id=request.user.id)[:20]  # Limit to 20 results for performance, excluding the requesting user

    serializer = UserProfileSerializer(users, many=True)
    return Response(serializer.data)
