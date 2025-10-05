"""Signal handlers for the search application."""

from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import PopularSearchTerm, SearchQueryLog


@receiver(post_save, sender=SearchQueryLog)
def update_popular_terms(sender, instance: SearchQueryLog, created: bool, **kwargs):
    """Maintain `PopularSearchTerm` aggregates whenever a query is logged."""
    if created:
        PopularSearchTerm.update_from_log(instance)
