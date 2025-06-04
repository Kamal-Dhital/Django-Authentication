from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from .models import UserSession
from .utils import get_client_ip

User = get_user_model()


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    """
    Signal handler for user creation and updates.
    """
    if created:
        # Log user creation
        import logging
        logger = logging.getLogger('authentication_system')
        logger.info(f"New user created: {instance.email}")


@receiver(post_save, sender=Session)
def create_user_session(sender, instance, created, **kwargs):
    """
    Create UserSession when Django session is created.
    """
    if created:
        try:
            # Get session data
            session_data = instance.get_decoded()
            user_id = session_data.get('_auth_user_id')

            if user_id:
                user = User.objects.get(pk=user_id)

                # Create UserSession record
                UserSession.objects.create(
                    user=user,
                    session_key=instance.session_key,
                    ip_address='0.0.0.0',  # Will be updated by middleware
                    user_agent='Unknown'   # Will be updated by middleware
                )
        except Exception as e:
            # Log error but don't break the flow
            import logging
            logger = logging.getLogger('authentication_system')
            logger.error(f"Error creating UserSession: {str(e)}")


@receiver(post_delete, sender=Session)
def delete_user_session(sender, instance, **kwargs):
    """
    Delete UserSession when Django session is deleted.
    """
    try:
        UserSession.objects.filter(session_key=instance.session_key).delete()
    except Exception as e:
        # Log error but don't break the flow
        import logging
        logger = logging.getLogger('authentication_system')
        logger.error(f"Error deleting UserSession: {str(e)}")
