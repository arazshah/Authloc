from __future__ import annotations

from typing import Iterable, Sequence

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import FieldPermission, LocationAccess
from .permission_checker import PermissionChecker


def _invalidate_users(user_ids: Iterable):
    unique_ids = {user_id for user_id in user_ids if user_id}
    if not unique_ids:
        return

    def _on_commit():
        for user_id in unique_ids:
            PermissionChecker.invalidate_for_user(user_id)

    transaction.on_commit(_on_commit)


@receiver(post_save, sender=LocationAccess)
@receiver(post_delete, sender=LocationAccess)
def invalidate_location_access_cache(sender, instance: LocationAccess, **kwargs):
    _invalidate_users([instance.user_id])


def _users_for_role(role_id) -> Sequence:
    if not role_id:
        return []
    return (
        LocationAccess.objects.filter(role_id=role_id)
        .values_list("user_id", flat=True)
        .distinct()
    )


@receiver(post_save, sender=FieldPermission)
@receiver(post_delete, sender=FieldPermission)
def invalidate_field_permission_cache(sender, instance: FieldPermission, **kwargs):
    user_ids = _users_for_role(instance.role_id)
    _invalidate_users(user_ids)
