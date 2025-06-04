"""
URL configuration for demo_project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from drf_spectacular.utils import extend_schema


@extend_schema(
    summary="API Root",
    description="Get the list of available API endpoints",
    responses={200: {
        'type': 'object',
        'properties': {
            'message': {'type': 'string'},
            'endpoints': {'type': 'object'}
        }
    }},
    tags=['API Root']
)
@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request):
    """
    API root endpoint with available endpoints.
    """
    return Response({
        'message': 'Authentication System API',
        'endpoints': {
            'authentication': '/auth/',
            'admin': '/admin/',
            'google_auth': '/social-auth/login/google-oauth2/',
            'api_docs': '/docs/',
            'api_schema': '/schema/',
            'redoc': '/redoc/',
        },
    }, status=status.HTTP_200_OK)


urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # API Root
    path('', api_root, name='api_root'),
    path('api/', api_root, name='api_root_api'),

    # Authentication System
    path('auth/', include('authentication_system.urls')),

    # Social Authentication
    path('social-auth/', include('social_django.urls', namespace='social')),

    # API Documentation
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
