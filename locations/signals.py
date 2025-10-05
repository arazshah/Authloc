"""
Signals for location cache invalidation.
"""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from core.cache_utils import cache_version_manager
from .models import Location


@receiver(post_save, sender=Location)
@receiver(post_delete, sender=Location)
def invalidate_location_cache(sender, instance: Location, **kwargs):
    """Invalidate location cache when locations are modified."""
    cache_version_manager.increment_version('locations')
