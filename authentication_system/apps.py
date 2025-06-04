from django.apps import AppConfig


class AuthenticationSystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authentication_system'
    verbose_name = 'Authentication System'

    def ready(self):
        # Import signal handlers
        try:
            import authentication_system.signals  # noqa F401
        except ImportError:
            pass
