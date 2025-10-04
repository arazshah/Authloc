"""Celery tasks for the `permissions` app."""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from .services import expire_user_roles

logger = logging.getLogger(__name__)


@shared_task(name="permissions.expire_user_roles")
def expire_user_roles_task(hours: int | None = None) -> int:
    """Deactivate time-bound roles whose validity has elapsed."""

    reference = timezone.now()
    if hours is not None:
        reference -= timedelta(hours=hours)
    expired_count = expire_user_roles(reference_time=reference)
    logger.info("Expired %s user roles via scheduled task.", expired_count)
    return expired_count
