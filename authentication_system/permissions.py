from rest_framework.permissions import BasePermission


class IsEmailVerified(BasePermission):
    """Custom permission to only allow access to users with verified emails."""
    message = 'Email verification required.'

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            getattr(request.user, 'is_email_verified', True)
        )


class IsOwnerOrReadOnly(BasePermission):
    """Custom permission to only allow owners of an object to edit it."""

    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        return obj == request.user
