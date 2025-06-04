from django.urls import path
from . import views

app_name = 'authentication_system'

urlpatterns = [
    # Authentication endpoints
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', views.ResendVerificationView.as_view(), name='resend-verification'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    # Google OAuth2
    path('google-auth/', views.GoogleAuthView.as_view(), name='google-auth'),

    # Password reset endpoints
    path('password-reset/request/', views.PasswordResetRequestView.as_view(), name='forgot-password'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='reset-password'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),

    # User profile
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('status/', views.user_status, name='user-status'),

    # User search
    path('search/', views.search_users, name='search-users'),
]
