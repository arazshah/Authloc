"""
Role definitions caching utilities.

Provides efficient caching for role definitions and permissions to improve
authorization performance.
"""

import logging
from typing import Dict, List, Optional, Any

from django.conf import settings
from django.utils import timezone

from core.cache_utils import cache_manager, cache_key_generator, cache_version_manager
from .models import Role

logger = logging.getLogger(__name__)

CACHE_TIMEOUT_ROLE_DEFINITIONS = getattr(settings, 'CACHE_TIMEOUT_ROLE_DEFINITIONS', 24 * 60 * 60)  # 24 hours default


def cache_role_definitions(include_inactive: bool = False) -> Dict[str, Any]:
    """
    Cache all role definitions for fast access.

    Args:
        include_inactive: Whether to include inactive roles

    Returns:
        Dictionary containing all role definitions
    """
    cache_key = cache_key_generator.generate_cache_key('role_definitions', include_inactive)
    version = cache_version_manager.get_current_version('roles')

    def _build_role_definitions():
        """Build comprehensive role definitions data."""
        roles = Role.objects.all()
        if not include_inactive:
            roles = roles.filter(is_active=True)

        # Prefetch related data
        roles = roles.prefetch_related('children').order_by('priority', 'name')

        role_map = {}
        system_roles = []
        non_system_roles = []

        for role in roles:
            role_data = {
                'id': str(role.pk),
                'name': role.name,
                'code': role.code,
                'description': role.description,
                'permissions': role.permissions or {},
                'is_system_role': role.is_system_role,
                'priority': role.priority,
                'parent_id': str(role.parent.pk) if role.parent else None,
                'children_ids': [str(child.pk) for child in role.children.all()],
                'is_active': role.is_active,
                'created_at': role.created_at.isoformat() if role.created_at else None,
                'updated_at': role.updated_at.isoformat() if role.updated_at else None,
            }

            role_map[str(role.pk)] = role_data

            if role.is_system_role:
                system_roles.append(role_data)
            else:
                non_system_roles.append(role_data)

        # Build role hierarchy
        hierarchy = {}
        for role_id, role_data in role_map.items():
            hierarchy[role_id] = _build_role_hierarchy(role_id, role_map)

        result = {
            'roles': role_map,
            'system_roles': system_roles,
            'non_system_roles': non_system_roles,
            'hierarchy': hierarchy,
            'total_count': len(role_map),
            'system_count': len(system_roles),
            'non_system_count': len(non_system_roles),
            'cached_at': timezone.now().isoformat(),
            'include_inactive': include_inactive,
        }

        return result

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_build_role_definitions,
        timeout=CACHE_TIMEOUT_ROLE_DEFINITIONS,
        version=version
    )


def _build_role_hierarchy(role_id: str, role_map: Dict[str, Any]) -> Dict[str, Any]:
    """Build hierarchy data for a specific role."""
    if role_id not in role_map:
        return {}

    role_data = role_map[role_id]

    hierarchy = {
        'role': role_data,
        'ancestors': [],
        'descendants': [],
        'effective_permissions': role_data['permissions'].copy(),
    }

    # Build ancestors
    current_id = role_data.get('parent_id')
    while current_id and current_id in role_map:
        ancestor = role_map[current_id]
        hierarchy['ancestors'].insert(0, ancestor)  # Insert at beginning for root-first order

        # Merge permissions (parent permissions override)
        if ancestor.get('permissions'):
            hierarchy['effective_permissions'].update(ancestor['permissions'])

        current_id = ancestor.get('parent_id')

    # Build descendants
    def _collect_descendants(parent_id: str) -> List[Dict[str, Any]]:
        descendants = []
        for child_id in role_map[parent_id].get('children_ids', []):
            if child_id in role_map:
                child_data = role_map[child_id]
                descendants.append(child_data)
                descendants.extend(_collect_descendants(child_id))
        return descendants

    hierarchy['descendants'] = _collect_descendants(role_id)

    return hierarchy


def get_role_by_code(code: str) -> Optional[Dict[str, Any]]:
    """
    Get role definition by code.

    Args:
        code: Role code

    Returns:
        Role data dictionary or None if not found
    """
    roles_data = cache_role_definitions()
    roles = roles_data.get('roles', {})

    for role_data in roles.values():
        if role_data.get('code') == code:
            return role_data

    return None


def get_role_hierarchy(role_id: str) -> Optional[Dict[str, Any]]:
    """
    Get complete hierarchy information for a role.

    Args:
        role_id: Role UUID

    Returns:
        Role hierarchy data or None if not found
    """
    roles_data = cache_role_definitions()
    hierarchy = roles_data.get('hierarchy', {})

    return hierarchy.get(role_id)


def get_effective_permissions(role_id: str) -> Dict[str, Any]:
    """
    Get effective permissions for a role (including inherited permissions).

    Args:
        role_id: Role UUID

    Returns:
        Dictionary of effective permissions
    """
    hierarchy = get_role_hierarchy(role_id)
    if not hierarchy:
        return {}

    return hierarchy.get('effective_permissions', {})


def get_roles_by_priority(min_priority: int = 0, max_priority: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get roles filtered by priority range.

    Args:
        min_priority: Minimum priority (inclusive)
        max_priority: Maximum priority (inclusive), None for no upper limit

    Returns:
        List of role data dictionaries
    """
    roles_data = cache_role_definitions()
    roles = roles_data.get('roles', {})

    filtered_roles = []
    for role_data in roles.values():
        priority = role_data.get('priority', 0)
        if priority >= min_priority and (max_priority is None or priority <= max_priority):
            filtered_roles.append(role_data)

    return sorted(filtered_roles, key=lambda x: x.get('priority', 0))


def get_system_roles() -> List[Dict[str, Any]]:
    """
    Get all system roles.

    Returns:
        List of system role data dictionaries
    """
    roles_data = cache_role_definitions()
    return roles_data.get('system_roles', [])


def get_non_system_roles() -> List[Dict[str, Any]]:
    """
    Get all non-system roles.

    Returns:
        List of non-system role data dictionaries
    """
    roles_data = cache_role_definitions()
    return roles_data.get('non_system_roles', [])


def search_roles(query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Search roles by name or code.

    Args:
        query: Search query
        limit: Maximum number of results

    Returns:
        List of matching role data
    """
    roles_data = cache_role_definitions()
    roles = roles_data.get('roles', {})

    query_lower = query.lower()
    matches = []

    for role_data in roles.values():
        if (query_lower in role_data['name'].lower() or
            query_lower in role_data.get('code', '').lower() or
            query_lower in role_data.get('description', '').lower()):
            matches.append(role_data)
            if len(matches) >= limit:
                break

    return matches


def get_role_stats() -> Dict[str, Any]:
    """
    Get role statistics.

    Returns:
        Dictionary with role statistics
    """
    roles_data = cache_role_definitions()

    roles = roles_data.get('roles', {})
    stats = {
        'total_roles': len(roles),
        'active_roles': sum(1 for role in roles.values() if role.get('is_active', False)),
        'inactive_roles': sum(1 for role in roles.values() if not role.get('is_active', False)),
        'system_roles': len(roles_data.get('system_roles', [])),
        'non_system_roles': len(roles_data.get('non_system_roles', [])),
        'roles_with_children': sum(1 for role in roles.values() if role.get('children_ids')),
        'roles_with_parents': sum(1 for role in roles.values() if role.get('parent_id')),
    }

    return stats


# Cache warming function
def warm_role_cache():
    """Warm role-related caches."""
    logger.info("Warming role cache...")

    # Cache role definitions
    roles_data = cache_role_definitions()
    logger.info(f"Cached {roles_data.get('total_count', 0)} role definitions")

    # Cache system roles
    system_roles = get_system_roles()
    logger.info(f"Cached {len(system_roles)} system roles")

    # Cache role stats
    stats = get_role_stats()
    logger.info(f"Role stats: {stats}")

    logger.info("Role cache warming completed")


# Register cache warming task
from core.cache_utils import cache_warmer
cache_warmer.register_warming_task('role_definitions', warm_role_cache, priority=1)
