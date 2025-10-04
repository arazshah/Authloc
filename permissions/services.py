"""Service layer for RBAC operations and permission orchestration."""
from __future__ import annotations

import logging
import time
from typing import Iterable, List, Optional, Sequence

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from locations.models import Location

from audit.utils import record_permission_audit
from .models import LocationAccess, Role, RoleAssignmentRequest, UserRole
from .permission_checker import PermissionChecker

User = get_user_model()

logger = logging.getLogger(__name__)


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
    "grant_location_access",
    "bulk_grant_location_access",
    "revoke_location_access",
    "bulk_revoke_location_access",
    "check_location_access",
    "RoleAssignmentError",
]


def _observe(action: str, start_time: float) -> None:
    elapsed = time.perf_counter() - start_time
    logger.debug("permission.service.%s duration=%.6f", action, elapsed)


def grant_location_access(
    *,
    user,
    role: Role,
    location: Optional[Location],
    granted_by=None,
    reason: str = "",
    can_read: bool = True,
    can_create: bool = False,
    can_update: bool = False,
    can_delete: bool = False,
    can_admin: bool = False,
    accessible_fields: Optional[Iterable[str]] = None,
    restricted_fields: Optional[Iterable[str]] = None,
    inherit_to_children: bool = True,
    valid_from=None,
    valid_until=None,
) -> LocationAccess:
    start = time.perf_counter()
    accessible_fields = list(accessible_fields or [])
    restricted_fields = list(restricted_fields or [])

    if accessible_fields and restricted_fields and set(accessible_fields) & set(restricted_fields):
        raise RoleAssignmentError(
            {"restricted_fields": "restricted_fields cannot overlap with accessible_fields."}
        )

    if valid_from and valid_until and valid_from > valid_until:
        raise RoleAssignmentError({"valid_until": "valid_until must be after valid_from."})

    with transaction.atomic():
        access, created = LocationAccess.objects.select_for_update().get_or_create(
            user=user,
            role=role,
            location=location,
            valid_from=valid_from,
            valid_until=valid_until,
            defaults={
                "can_read": can_read,
                "can_create": can_create,
                "can_update": can_update,
                "can_delete": can_delete,
                "can_admin": can_admin,
                "accessible_fields": accessible_fields,
                "restricted_fields": restricted_fields,
                "inherit_to_children": inherit_to_children,
                "granted_by": granted_by,
                "reason": reason,
                "is_active": True,
                "created_by": granted_by,
                "updated_by": granted_by,
            },
        )

        update_fields = set()
        if not created:
            for field, value in (
                ("can_read", can_read),
                ("can_create", can_create),
                ("can_update", can_update),
                ("can_delete", can_delete),
                ("can_admin", can_admin),
                ("accessible_fields", accessible_fields),
                ("restricted_fields", restricted_fields),
                ("inherit_to_children", inherit_to_children),
                ("reason", reason),
            ):
                if value is not None and getattr(access, field) != value:
                    setattr(access, field, value)
                    update_fields.add(field)
            if not access.is_active:
                access.is_active = True
                update_fields.add("is_active")
            if granted_by is not None and access.granted_by_id != getattr(granted_by, "pk", None):
                access.granted_by = granted_by
                update_fields.add("granted_by")
            if update_fields:
                access.updated_by = granted_by
                update_fields.update({"updated_at", "updated_by"})
                access.save(update_fields=sorted(update_fields))

    PermissionChecker.invalidate_for_user(getattr(user, "pk", user))
    record_permission_audit(
        action="grant",
        actor=granted_by,
        subject=user,
        role=role,
        location=location,
        payload={
            "can_read": can_read,
            "can_create": can_create,
            "can_update": can_update,
            "can_delete": can_delete,
            "can_admin": can_admin,
            "accessible_fields": accessible_fields,
            "restricted_fields": restricted_fields,
            "inherit_to_children": inherit_to_children,
            "reason": reason,
        },
    )
    _observe("grant_location_access", start)
    return access


def bulk_grant_location_access(*, grants: Iterable[dict], granted_by=None) -> List[LocationAccess]:
    start = time.perf_counter()
    granted: List[LocationAccess] = []
    for payload in grants:
        access = grant_location_access(granted_by=granted_by, **payload)
        granted.append(access)
    _observe("bulk_grant_location_access", start)
    return granted


def revoke_location_access(
    *,
    user,
    role: Role,
    location: Optional[Location],
    revoked_by=None,
    reason: str = "",
) -> int:
    start = time.perf_counter()
    with transaction.atomic():
        qs = LocationAccess.objects.select_for_update().filter(
            user=user,
            role=role,
            is_active=True,
        )
        if location is None:
            qs = qs.filter(location__isnull=True)
        else:
            qs = qs.filter(Q(location=location) | Q(location__isnull=True, inherit_to_children=True))

        affected = list(qs)
        for access in affected:
            access.deactivate(reason=reason, updated_by=revoked_by)

    if affected:
        PermissionChecker.invalidate_for_user(getattr(user, "pk", user))
        record_permission_audit(
            action="revoke",
            actor=revoked_by,
            subject=user,
            role=role,
            location=location,
            payload={"reason": reason},
        )
    _observe("revoke_location_access", start)
    return len(affected)


def bulk_revoke_location_access(*, revocations: Iterable[dict], revoked_by=None) -> int:
    start = time.perf_counter()
    count = 0
    for payload in revocations:
        count += revoke_location_access(revoked_by=revoked_by, **payload)
    _observe("bulk_revoke_location_access", start)
    return count


def check_location_access(*, user, location: Optional[Location], action: str) -> bool:
    checker = PermissionChecker(user)
    return checker.can_access_location(location, action)
