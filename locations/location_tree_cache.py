"""
Location hierarchy caching utilities.

Provides efficient caching for location trees and hierarchies to improve performance
for location-based queries and navigation.
"""

import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

from django.conf import settings
from django.utils import timezone

from core.cache_utils import cache_manager, cache_key_generator, cache_version_manager
from .models import Location, LocationType

logger = logging.getLogger(__name__)

CACHE_TIMEOUT_LOCATION_TREE = getattr(settings, 'CACHE_TIMEOUT_LOCATION_TREE', 60 * 60)  # 1 hour default


def cache_location_tree(include_inactive: bool = False) -> Dict[str, Any]:
    """
    Cache complete location hierarchy tree for fast access.

    Args:
        include_inactive: Whether to include inactive locations

    Returns:
        Dictionary containing the complete location tree structure
    """
    cache_key = cache_key_generator.generate_cache_key('location_tree', include_inactive)
    version = cache_version_manager.get_current_version('locations')

    def _build_location_tree():
        """Build the complete location tree structure."""
        locations = Location.objects.all()
        if not include_inactive:
            locations = locations.filter(is_active=True)

        # Prefetch related data for performance
        locations = locations.select_related('type', 'parent').order_by('path')

        # Build tree structure
        tree = {}
        location_map = {}
        root_locations = []

        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'level': location.level,
                'path': location.path,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'parent_id': str(location.parent.pk) if location.parent else None,
                'children': [],
                'geometry': location.geometry.geojson if location.geometry else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'population': location.population,
                'postal_code': location.postal_code,
                'is_active': location.is_active,
            }

            location_map[str(location.pk)] = location_data

            if location.parent is None:
                root_locations.append(location_data)
            else:
                parent_id = str(location.parent.pk)
                if parent_id in location_map:
                    location_map[parent_id]['children'].append(location_data)

        # Build ancestry lookup
        ancestry_map = {}
        for location_id, location_data in location_map.items():
            ancestry_map[location_id] = []
            path_parts = location_data['path'].strip('/').split('/')
            for part in path_parts:
                if part and part in location_map:
                    ancestry_map[location_id].append(location_map[part])

        tree = {
            'locations': location_map,
            'roots': root_locations,
            'ancestry': ancestry_map,
            'total_count': len(location_map),
            'cached_at': timezone.now().isoformat(),
            'include_inactive': include_inactive,
        }

        return tree

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_build_location_tree,
        timeout=CACHE_TIMEOUT_LOCATION_TREE,
        version=version
    )


def get_location_ancestors(location_id: str, include_self: bool = False) -> List[Dict[str, Any]]:
    """
    Get ancestors of a location from cache.

    Args:
        location_id: Location UUID
        include_self: Whether to include the location itself

    Returns:
        List of ancestor location data
    """
    tree = cache_location_tree()
    ancestry = tree.get('ancestry', {}).get(location_id, [])

    if include_self and location_id in tree.get('locations', {}):
        ancestry = [tree['locations'][location_id]] + ancestry

    return ancestry


def get_location_descendants(location_id: str, include_self: bool = False) -> List[Dict[str, Any]]:
    """
    Get descendants of a location from cache.

    Args:
        location_id: Location UUID
        include_self: Whether to include the location itself

    Returns:
        List of descendant location data
    """
    tree = cache_location_tree()
    locations = tree.get('locations', {})

    if location_id not in locations:
        return []

    def _collect_descendants(loc_id: str, descendants: List) -> None:
        """Recursively collect descendants."""
        location_data = locations[loc_id]
        descendants.append(location_data)

        for child in location_data.get('children', []):
            child_id = child['id']
            _collect_descendants(child_id, descendants)

    descendants = []
    if include_self:
        descendants.append(locations[location_id])

    for child in locations[location_id].get('children', []):
        _collect_descendants(child['id'], descendants)

    return descendants


def get_locations_by_level(level: int) -> List[Dict[str, Any]]:
    """
    Get all locations at a specific level from cache.

    Args:
        level: Location level

    Returns:
        List of locations at the specified level
    """
    tree = cache_location_tree()
    locations = tree.get('locations', {})

    return [
        loc_data for loc_data in locations.values()
        if loc_data.get('level') == level
    ]


def get_location_path(location_id: str) -> Optional[List[str]]:
    """
    Get the full path (names) for a location.

    Args:
        location_id: Location UUID

    Returns:
        List of location names from root to the location, or None if not found
    """
    ancestors = get_location_ancestors(location_id, include_self=True)
    if not ancestors:
        return None

    return [ancestor['name'] for ancestor in ancestors]


def search_locations_by_name(query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Search locations by name (case-insensitive).

    Args:
        query: Search query
        limit: Maximum number of results

    Returns:
        List of matching locations
    """
    tree = cache_location_tree()
    locations = tree.get('locations', {})

    query_lower = query.lower()
    matches = []

    for location_data in locations.values():
        if (query_lower in location_data['name'].lower() or
            query_lower in location_data.get('name_fa', '').lower()):
            matches.append(location_data)
            if len(matches) >= limit:
                break

    return matches


def get_location_stats() -> Dict[str, Any]:
    """
    Get location statistics from cache.

    Returns:
        Dictionary with location statistics
    """
    tree = cache_location_tree()

    locations = tree.get('locations', {})
    stats = {
        'total_locations': len(locations),
        'active_locations': sum(1 for loc in locations.values() if loc.get('is_active', False)),
        'inactive_locations': sum(1 for loc in locations.values() if not loc.get('is_active', False)),
        'locations_by_level': defaultdict(int),
        'locations_by_type': defaultdict(int),
        'root_locations': len(tree.get('roots', [])),
    }

    for location_data in locations.values():
        stats['locations_by_level'][location_data.get('level', 0)] += 1
        if location_data.get('type'):
            stats['locations_by_type'][location_data['type']['code']] += 1

    # Convert defaultdicts to regular dicts
    stats['locations_by_level'] = dict(stats['locations_by_level'])
    stats['locations_by_type'] = dict(stats['locations_by_type'])

    return stats


# Cache warming function
def warm_location_cache():
    """Warm location-related caches."""
    logger.info("Warming location cache...")

    # Cache the main location tree
    tree = cache_location_tree()
    logger.info(f"Cached location tree with {tree.get('total_count', 0)} locations")

    # Cache location stats
    stats = get_location_stats()
    logger.info(f"Location stats: {stats}")

    # Cache locations by level (common queries)
    for level in range(6):  # 0-5 levels
        level_locs = get_locations_by_level(level)
        logger.info(f"Cached {len(level_locs)} locations at level {level}")

    logger.info("Location cache warming completed")


# Register cache warming task
from core.cache_utils import cache_warmer
cache_warmer.register_warming_task('location_tree', warm_location_cache, priority=2)
