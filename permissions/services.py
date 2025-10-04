"""Service layer for RBAC operations."""
from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from locations.models import Location

from .models import Role, RoleAssignmentRequest, UserRole

User = get_user_model()


class RoleAssignmentError(ValidationError):
    """Raised when role assignment cannot be completed."""


def _validate_validity_window(valid_from, valid_until) -> None:
    if valid_from and valid_until and valid_from > valid_until:
        raise RoleAssignmentError({"valid_until": "valid_until must be after valid_from."})


@transaction.atomic
def assign_role_to_user(
    *,
    role: Role,
    user: User,
    location: Optional[Location] = None,
    valid_from=None,
    valid_until=None,
    assigned_by: Optional[User] = None,
    reason: str = "",
    metadata: Optional[dict] = None,
) -> UserRole:
    _validate_validity_window(valid_from, valid_until)

    metadata = metadata or {}

    try:
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            location=location,
            valid_from=valid_from,
            valid_until=valid_until,
            defaults={
                "assigned_by": assigned_by,
                "reason": reason,
                "metadata": metadata,
                "is_active": True,
                "created_by": assigned_by,
                "updated_by": assigned_by,
            },
        )
    except IntegrityError as exc:  # pragma: no cover - defensive safeguard
        raise RoleAssignmentError("Unable to assign role due to integrity constraints.") from exc

    if not created:
        updates = set()
        if not user_role.is_active:
            user_role.is_active = True
            updates.add("is_active")
        if assigned_by and user_role.assigned_by_id != getattr(assigned_by, "pk", None):
            user_role.assigned_by = assigned_by
            updates.add("assigned_by")
        if reason:
            user_role.reason = reason
            updates.add("reason")
        if metadata:
            user_role.metadata = metadata
            updates.add("metadata")
        if updates:
            user_role.updated_by = assigned_by
            user_role.updated_at = timezone.now()
            updates.update({"updated_by", "updated_at"})
            user_role.save(update_fields=sorted(updates))
    return user_role


def bulk_assign_roles(
    *,
    role: Role,
    assignments: Iterable[dict],
    assigned_by: Optional[User] = None,
) -> List[UserRole]:
    created_roles: List[UserRole] = []
    for payload in assignments:
        user = payload["user"]
        location = payload.get("location")
        valid_from = payload.get("valid_from")
        valid_until = payload.get("valid_until")
        reason = payload.get("reason", "")
        metadata = payload.get("metadata")
        created_roles.append(
            assign_role_to_user(
                role=role,
                user=user,
                location=location,
                valid_from=valid_from,
                valid_until=valid_until,
                assigned_by=assigned_by,
                reason=reason,
                metadata=metadata,
            )
        )
    return created_roles


def _ensure_sequence(value: Iterable[UserRole]) -> Sequence[UserRole]:
    if isinstance(value, Sequence):
        return value
    return list(value)


@transaction.atomic
def create_role_assignment_request(
    *,
    user: User,
    role: Role,
    requested_by: Optional[User],
    location: Optional[Location] = None,
    valid_from=None,
    valid_until=None,
    reason: str = "",
    metadata: Optional[dict] = None,
) -> RoleAssignmentRequest:
    _validate_validity_window(valid_from, valid_until)

    metadata = metadata or {}
    request = RoleAssignmentRequest.objects.create(
        user=user,
        role=role,
        location=location,
        valid_from=valid_from,
        valid_until=valid_until,
        requested_by=requested_by,
        reason=reason,
        metadata=metadata,
    )
    return request


def expire_user_roles(*, reference_time=None, reason: str | None = None, updated_by: Optional[User] = None) -> int:
    """Deactivate roles whose `valid_until` has passed."""

    reference_time = reference_time or timezone.now()
    reason = reason or "Role assignment expired."
    roles = UserRole.objects.select_for_update().filter(
        is_active=True,
        valid_until__isnull=False,
        valid_until__lt=reference_time,
    )
    roles = _ensure_sequence(roles)
    for user_role in roles:
        user_role.deactivate(reason=reason, updated_by=updated_by)
    return len(roles)


__all__ = [
    "assign_role_to_user",
    "bulk_assign_roles",
    "create_role_assignment_request",
    "expire_user_roles",
    "RoleAssignmentError",
]
