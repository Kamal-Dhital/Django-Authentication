from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import CustomUser, UserSession


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin interface for CustomUser model.
    """
    list_display = (
        'email', 'username', 'full_name', 'is_email_verified',
        'is_social_account', 'is_active', 'created_at', 'last_login'
    )
    list_filter = (
        'is_active', 'is_staff', 'is_superuser', 'is_email_verified',
        'is_social_account', 'social_provider', 'created_at', 'last_login'
    )
    search_fields = ('email', 'username', 'first_name', 'last_name', 'phone')
    ordering = ('-created_at',)
    readonly_fields = (
        'id', 'created_at', 'updated_at', 'last_login', 'last_login_ip',
        'email_verification_code', 'email_verification_code_expires',
        'password_reset_code', 'password_reset_code_expires',
        'password_reset_token', 'password_reset_token_expires'
    )

    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'email', 'username', 'password')
        }),
        ('Personal Information', {
            'fields': ('first_name', 'last_name', 'phone', 'avatar')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Email Verification', {
            'fields': (
                'is_email_verified', 'email_verification_code',
                'email_verification_code_expires'
            ),
            'classes': ('collapse',)
        }),
        ('Password Reset', {
            'fields': (
                'password_reset_code', 'password_reset_code_expires',
                'password_reset_token', 'password_reset_token_expires'
            ),
            'classes': ('collapse',)
        }),
        ('Social Authentication', {
            'fields': ('is_social_account', 'social_provider'),
            'classes': ('collapse',)
        }),
        ('Timestamps & Security', {
            'fields': ('created_at', 'updated_at', 'last_login', 'last_login_ip'),
            'classes': ('collapse',)
        }),
    )

    add_fieldsets = (
        ('Create New User', {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'first_name', 'last_name')
        }),
    )

    def full_name(self, obj):
        """Display full name."""
        return obj.full_name or obj.email
    full_name.short_description = 'Full Name'

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related()

    actions = ['mark_as_verified', 'mark_as_unverified', 'reset_verification_code']

    def mark_as_verified(self, request, queryset):
        """Mark selected users as email verified."""
        count = queryset.update(
            is_email_verified=True,
            email_verification_code=None,
            email_verification_code_expires=None
        )
        self.message_user(request, f'{count} users marked as verified.')
    mark_as_verified.short_description = 'Mark selected users as email verified'

    def mark_as_unverified(self, request, queryset):
        """Mark selected users as email unverified."""
        count = queryset.update(is_email_verified=False)
        self.message_user(request, f'{count} users marked as unverified.')
    mark_as_unverified.short_description = 'Mark selected users as email unverified'

    def reset_verification_code(self, request, queryset):
        """Reset verification codes for selected users."""
        count = 0
        for user in queryset:
            if not user.is_email_verified:
                user.generate_verification_code()
                count += 1
        self.message_user(request, f'Verification codes reset for {count} users.')
    reset_verification_code.short_description = 'Reset verification codes for unverified users'


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """
    Admin interface for UserSession model.
    """
    list_display = (
        'user_email', 'ip_address', 'is_active', 'created_at', 'last_activity'
    )
    list_filter = ('is_active', 'created_at', 'last_activity')
    search_fields = ('user__email', 'ip_address', 'session_key')
    readonly_fields = (
        'id', 'user', 'session_key', 'ip_address', 'user_agent',
        'created_at', 'last_activity'
    )
    ordering = ('-last_activity',)

    def user_email(self, obj):
        """Display user email with link."""
        if obj.user:
            url = reverse('admin:authentication_system_customuser_change', args=[obj.user.pk])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return '-'
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'

    def has_add_permission(self, request):
        """Disable adding sessions manually."""
        return False

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    actions = ['deactivate_sessions']

    def deactivate_sessions(self, request, queryset):
        """Deactivate selected sessions."""
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} sessions deactivated.')
    deactivate_sessions.short_description = 'Deactivate selected sessions'


# Custom admin site configuration
admin.site.site_header = 'Authentication System Admin'
admin.site.site_title = 'Auth Admin'
admin.site.index_title = 'Authentication System Administration'
