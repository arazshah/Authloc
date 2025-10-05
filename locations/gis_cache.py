"""
GIS queries caching utilities.

Provides efficient caching for geographic/spatial queries to improve
performance for location-based GIS operations.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import Point, GEOSGeometry
from django.contrib.gis.measure import D

from django.conf import settings
from django.utils import timezone

from core.cache_utils import cache_manager, cache_key_generator, cache_version_manager
from locations.models import Location

logger = logging.getLogger(__name__)

CACHE_TIMEOUT_GIS_QUERIES = getattr(settings, 'CACHE_TIMEOUT_GIS_QUERIES', 30 * 60)  # 30 minutes default


def cache_locations_within_distance(
    center_point: Point,
    distance_km: float,
    location_type: Optional[str] = None,
    include_inactive: bool = False
) -> List[Dict[str, Any]]:
    """
    Cache locations within a certain distance from a point.

    Args:
        center_point: Center point for distance calculation
        distance_km: Distance in kilometers
        location_type: Optional location type code filter
        include_inactive: Whether to include inactive locations

    Returns:
        List of locations within the distance, sorted by distance
    """
    # Create a deterministic cache key from the point coordinates
    point_key = f"{center_point.x:.6f},{center_point.y:.6f}"
    cache_key = cache_key_generator.generate_cache_key(
        'gis_locations_within_distance',
        point_key,
        distance_km,
        location_type or 'all',
        include_inactive
    )
    version = cache_version_manager.get_current_version('locations')

    def _find_locations_within_distance():
        """Find locations within distance."""
        queryset = Location.objects.all()

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        if location_type:
            queryset = queryset.filter(type__code=location_type)

        # Use distance ordering for better performance
        locations = queryset.filter(
            center_point__distance_lte=(center_point, D(km=distance_km))
        ).annotate(
            distance=Distance('center_point', center_point)
        ).order_by('distance').select_related('type')

        results = []
        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'distance_km': location.distance.km if hasattr(location, 'distance') else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'geometry': location.geometry.geojson if location.geometry else None,
                'population': location.population,
                'is_active': location.is_active,
            }
            results.append(location_data)

        return results

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_find_locations_within_distance,
        timeout=CACHE_TIMEOUT_GIS_QUERIES,
        version=version
    )


def cache_locations_containing_point(point: Point, include_inactive: bool = False) -> List[Dict[str, Any]]:
    """
    Cache locations that contain a given point.

    Args:
        point: Point to check containment for
        include_inactive: Whether to include inactive locations

    Returns:
        List of locations containing the point, ordered by level (most specific first)
    """
    point_key = f"{point.x:.6f},{point.y:.6f}"
    cache_key = cache_key_generator.generate_cache_key(
        'gis_locations_containing_point',
        point_key,
        include_inactive
    )
    version = cache_version_manager.get_current_version('locations')

    def _find_containing_locations():
        """Find locations containing the point."""
        queryset = Location.objects.all()

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        # Use spatial containment query
        locations = queryset.filter(
            geometry__contains=point
        ).select_related('type').order_by('level')  # Most specific (higher level) first

        results = []
        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'level': location.level,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'geometry': location.geometry.geojson if location.geometry else None,
                'population': location.population,
                'is_active': location.is_active,
            }
            results.append(location_data)

        return results

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_find_containing_locations,
        timeout=CACHE_TIMEOUT_GIS_QUERIES,
        version=version
    )


def cache_location_intersections(location_id: str, include_inactive: bool = False) -> List[Dict[str, Any]]:
    """
    Cache locations that intersect with a given location's geometry.

    Args:
        location_id: Location UUID
        include_inactive: Whether to include inactive locations

    Returns:
        List of intersecting locations
    """
    cache_key = cache_key_generator.generate_cache_key(
        'gis_location_intersections',
        location_id,
        include_inactive
    )
    version = cache_version_manager.get_current_version('locations')

    def _find_intersecting_locations():
        """Find locations intersecting with the given location."""
        try:
            base_location = Location.objects.get(pk=location_id)
        except Location.DoesNotExist:
            return []

        queryset = Location.objects.exclude(pk=location_id)

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        # Find intersecting locations
        locations = queryset.filter(
            geometry__intersects=base_location.geometry
        ).select_related('type').order_by('level')

        results = []
        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'level': location.level,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'geometry': location.geometry.geojson if location.geometry else None,
                'population': location.population,
                'is_active': location.is_active,
            }
            results.append(location_data)

        return results

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_find_intersecting_locations,
        timeout=CACHE_TIMEOUT_GIS_QUERIES,
        version=version
    )


def cache_nearest_locations(
    center_point: Point,
    limit: int = 10,
    location_type: Optional[str] = None,
    include_inactive: bool = False
) -> List[Dict[str, Any]]:
    """
    Cache nearest locations to a point.

    Args:
        center_point: Center point
        limit: Maximum number of locations to return
        location_type: Optional location type code filter
        include_inactive: Whether to include inactive locations

    Returns:
        List of nearest locations, sorted by distance
    """
    point_key = f"{center_point.x:.6f},{center_point.y:.6f}"
    cache_key = cache_key_generator.generate_cache_key(
        'gis_nearest_locations',
        point_key,
        limit,
        location_type or 'all',
        include_inactive
    )
    version = cache_version_manager.get_current_version('locations')

    def _find_nearest_locations():
        """Find nearest locations to the point."""
        queryset = Location.objects.all()

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        if location_type:
            queryset = queryset.filter(type__code=location_type)

        # Find locations with center points and calculate distances
        locations = queryset.filter(
            center_point__isnull=False
        ).annotate(
            distance=Distance('center_point', center_point)
        ).order_by('distance')[:limit].select_related('type')

        results = []
        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'distance_km': location.distance.km if hasattr(location, 'distance') else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'geometry': location.geometry.geojson if location.geometry else None,
                'population': location.population,
                'is_active': location.is_active,
            }
            results.append(location_data)

        return results

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_find_nearest_locations,
        timeout=CACHE_TIMEOUT_GIS_QUERIES,
        version=version
    )


def cache_locations_bounds(
    bounds: Tuple[float, float, float, float],
    location_type: Optional[str] = None,
    include_inactive: bool = False
) -> List[Dict[str, Any]]:
    """
    Cache locations within bounding box.

    Args:
        bounds: (min_lon, min_lat, max_lon, max_lat) tuple
        location_type: Optional location type code filter
        include_inactive: Whether to include inactive locations

    Returns:
        List of locations within bounds
    """
    min_lon, min_lat, max_lon, max_lat = bounds
    bounds_key = f"{min_lon:.6f},{min_lat:.6f},{max_lon:.6f},{max_lat:.6f}"
    cache_key = cache_key_generator.generate_cache_key(
        'gis_locations_bounds',
        bounds_key,
        location_type or 'all',
        include_inactive
    )
    version = cache_version_manager.get_current_version('locations')

    def _find_locations_in_bounds():
        """Find locations within bounding box."""
        from django.contrib.gis.geos import Polygon

        # Create bounding box polygon
        bbox = Polygon.from_bbox(bounds)

        queryset = Location.objects.all()

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        if location_type:
            queryset = queryset.filter(type__code=location_type)

        # Find locations intersecting with bounds
        locations = queryset.filter(
            geometry__intersects=bbox
        ).select_related('type').order_by('level')

        results = []
        for location in locations:
            location_data = {
                'id': str(location.pk),
                'name': location.name,
                'name_fa': location.name_fa,
                'code': location.code,
                'level': location.level,
                'type': {
                    'code': location.type.code,
                    'name': location.type.name,
                    'level': location.type.level,
                } if location.type else None,
                'center_point': [location.center_point.x, location.center_point.y] if location.center_point else None,
                'geometry': location.geometry.geojson if location.geometry else None,
                'population': location.population,
                'is_active': location.is_active,
            }
            results.append(location_data)

        return results

    return cache_manager.get_cached_or_set(
        key=cache_key,
        callable_func=_find_locations_in_bounds,
        timeout=CACHE_TIMEOUT_GIS_QUERIES,
        version=version
    )


# Cache warming function for common GIS queries
def warm_gis_cache():
    """Warm common GIS query caches."""
    logger.info("Warming GIS cache...")

    # This would typically warm common queries like:
    # - Popular city centers
    # - Administrative boundaries
    # - Common search areas

    # For now, just log that warming is available
    logger.info("GIS cache warming completed (no specific queries to warm)")


# Register cache warming task
from core.cache_utils import cache_warmer
cache_warmer.register_warming_task('gis_queries', warm_gis_cache, priority=3)
