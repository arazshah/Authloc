"""Utility helpers for the role-based access control system."""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set

from django.db.models import Q
from django.utils import timezone

from locations.models import Location

from .constants import ALL_PERMISSIONS_TEMPLATE, SYSTEM_ROLE_CODES
from .models import Role, UserRole

PermissionMap = Dict[str, Set[str]]
SerializedPermissionMap = Dict[str, List[str]]


def _normalize_permissions(permissions: Optional[Mapping[str, Iterable[str]]]) -> PermissionMap:
    normalized: PermissionMap = defaultdict(set)
    if not permissions:
        return normalized
    for resource, actions in permissions.items():
        if not actions:
            continue
        normalized[str(resource)].update(str(action) for action in actions)
    return normalized


def merge_permissions(*permission_sets: Mapping[str, Iterable[str]]) -> SerializedPermissionMap:
    """Merge multiple permission mappings into a deduplicated dict of sorted lists."""

    merged: PermissionMap = defaultdict(set)
    for permission_set in permission_sets:
        if not permission_set:
            continue
        for resource, actions in permission_set.items():
            if not actions:
                continue
            merged[str(resource)].update(str(action) for action in actions)
    return {resource: sorted(actions) for resource, actions in merged.items()}


def _collect_role_permissions(role: Optional[Role], visited: Optional[Set[str]] = None) -> PermissionMap:
    visited = visited or set()
    if not role or role.pk is None:
        return defaultdict(set)
    cache_key = str(role.pk)
    if cache_key in visited:
        return defaultdict(set)
    visited.add(cache_key)

    permissions = _normalize_permissions(role.permissions)
    if role.parent_role_id:
        parent_permissions = _collect_role_permissions(role.parent_role, visited)
        for resource, actions in parent_permissions.items():
            permissions[resource].update(actions)
    return permissions


def _location_scope_ids(location: Location) -> Set:
    identifiers: Set = set()
    if not location.pk:
        return identifiers
    identifiers.add(location.pk)
    ancestor_ids = location.get_ancestors(include_self=True).values_list("pk", flat=True)
    identifiers.update(ancestor_ids)
    return identifiers


def get_user_roles(
    user,
    location: Optional[Location] = None,
    at: Optional[timezone.datetime] = None,
) -> List[UserRole]:
    """Return active roles for ``user`` optionally scoped to ``location``."""

    if user is None:
        return []

    qs = (
        UserRole.objects.select_related("role", "location", "assigned_by")
        .filter(user=user)
        .active(at)
    )

    if location:
        scoped_ids = _location_scope_ids(location)
        if scoped_ids:
            qs = qs.filter(
                Q(location__isnull=True)
                | Q(location__in=list(scoped_ids))
            )
        else:
            qs = qs.filter(location__isnull=True)

    return list(qs)


def _aggregate_permissions(roles: Sequence[Role]) -> SerializedPermissionMap:
    aggregated: MutableMapping[str, Set[str]] = defaultdict(set)
    for role in roles:
        role_permissions = _collect_role_permissions(role)
        for resource, actions in role_permissions.items():
            aggregated[resource].update(actions)
    return {resource: sorted(actions) for resource, actions in aggregated.items()}


def _full_access_permissions() -> SerializedPermissionMap:
    template = deepcopy(ALL_PERMISSIONS_TEMPLATE)
    return {resource: list(actions) for resource, actions in template.items()}


def get_effective_permissions(
    user,
    location: Optional[Location] = None,
) -> SerializedPermissionMap:
    """Return the merged permissions for ``user`` at ``location`` (if provided)."""

    user_roles = get_user_roles(user, location=location)
    if not user_roles:
        return {}

    roles = [user_role.role for user_role in user_roles if user_role.role is not None]
    if not roles:
        return {}

    if any((role.code or "") == SYSTEM_ROLE_CODES["SUPER_ADMIN"] for role in roles):
        return _full_access_permissions()

    return _aggregate_permissions(roles)


def has_permission(
    user,
    resource: str,
    action: str,
    location: Optional[Location] = None,
) -> bool:
    """Check whether ``user`` can perform ``action`` on ``resource`` within ``location`` scope."""

    permissions = get_effective_permissions(user, location=location)
    if not permissions:
        return False

    actions = permissions.get(resource)
    if not actions:
        return False
    return action in actions

