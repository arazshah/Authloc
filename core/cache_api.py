"""
Cache management API views.

Provides REST API endpoints for cache statistics, clearing, and warming operations.
"""

import logging
from typing import Dict, Any

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.conf import settings

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from core.cache_utils import cache_manager, cache_warmer, cache_version_manager
from core.performance_monitor import get_performance_metrics

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def cache_stats(request) -> Response:
    """
    Get comprehensive cache statistics.

    Returns cache hit/miss ratios, memory usage, and performance metrics.
    """
    try:
        stats = cache_manager.get_cache_stats()
        performance = get_performance_metrics(hours=1)

        # Add cache-specific metrics
        cache_info = {
            'cache_stats': stats,
            'performance_metrics': performance,
            'cache_configuration': {
                'default_timeout': getattr(settings, 'CACHE_TIMEOUT_USER_PERMISSIONS', 900),
                'api_timeout': getattr(settings, 'CACHE_TIMEOUT_API_RESPONSES', 600),
                'compression_threshold': getattr(settings, 'CACHE_COMPRESSION_THRESHOLD', 1024),
            },
            'cache_versions': {
                'permissions': cache_version_manager.get_current_version('permissions'),
                'locations': cache_version_manager.get_current_version('locations'),
                'roles': cache_version_manager.get_current_version('roles'),
                'audit': cache_version_manager.get_current_version('audit'),
            }
        }

        return Response(cache_info)
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return Response(
            {'error': 'Failed to retrieve cache statistics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def cache_clear(request) -> Response:
    """
    Clear cache or specific cache patterns.

    POST data:
    - pattern: Optional pattern to clear (supports wildcards)
    - namespace: Optional namespace to clear (permissions, locations, roles, audit)
    """
    try:
        pattern = request.data.get('pattern')
        namespace = request.data.get('namespace')

        if namespace:
            # Clear by namespace using version invalidation
            if namespace in ['permissions', 'locations', 'roles', 'audit']:
                cache_version_manager.increment_version(namespace)
                message = f"Invalidated cache namespace: {namespace}"
            else:
                return Response(
                    {'error': f'Invalid namespace: {namespace}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        elif pattern:
            # Clear by pattern
            cleared_count = cache_manager.invalidate_cache_pattern(pattern)
            message = f"Cleared {cleared_count} cache entries matching pattern: {pattern}"
        else:
            # Clear all caches
            success = cache_manager.clear_cache()
            message = "Cleared all caches" if success else "Failed to clear all caches"

        logger.info(f"Cache clear operation: {message}")
        return Response({'message': message})

    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return Response(
            {'error': 'Failed to clear cache'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def cache_warm(request) -> Response:
    """
    Warm specific caches or all registered caches.

    POST data:
    - tasks: Optional list of specific warming tasks to run
    """
    try:
        tasks = request.data.get('tasks', [])

        # Run cache warming
        results = cache_warmer.warm_cache(tasks if tasks else None)

        successful = sum(1 for result in results.values() if result)
        failed = len(results) - successful

        response_data = {
            'message': f'Cache warming completed. {successful} successful, {failed} failed.',
            'results': results,
            'total_tasks': len(results),
            'successful_tasks': successful,
            'failed_tasks': failed,
        }

        logger.info(f"Cache warming completed: {successful} successful, {failed} failed")
        return Response(response_data)

    except Exception as e:
        logger.error(f"Error warming cache: {e}")
        return Response(
            {'error': 'Failed to warm cache'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def performance_metrics(request) -> Response:
    """
    Get comprehensive performance metrics.

    Query parameters:
    - hours: Hours of history to analyze (default: 1)
    """
    try:
        hours = int(request.query_params.get('hours', 1))
        if hours < 1 or hours > 24:
            return Response(
                {'error': 'Hours must be between 1 and 24'},
                status=status.HTTP_400_BAD_REQUEST
            )

        metrics = get_performance_metrics(hours=hours)
        return Response(metrics)

    except ValueError:
        return Response(
            {'error': 'Invalid hours parameter'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return Response(
            {'error': 'Failed to retrieve performance metrics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def cache_invalidate_user(request) -> Response:
    """
    Invalidate cache for a specific user.

    POST data:
    - user_id: User ID to invalidate cache for
    """
    try:
        user_id = request.data.get('user_id')
        if not user_id:
            return Response(
                {'error': 'user_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Invalidate user-specific caches
        from permissions.permission_checker import PermissionChecker
        PermissionChecker.invalidate_for_user(user_id)

        # Also increment permissions version to invalidate user permissions cache
        cache_version_manager.increment_version('permissions')

        logger.info(f"Invalidated cache for user: {user_id}")
        return Response({
            'message': f'Invalidated cache for user: {user_id}'
        })

    except Exception as e:
        logger.error(f"Error invalidating user cache: {e}")
        return Response(
            {'error': 'Failed to invalidate user cache'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def cache_health(request) -> Response:
    """
    Get cache health status.

    Returns overall cache health and any issues detected.
    """
    try:
        stats = cache_manager.get_cache_stats()
        versions = {
            'permissions': cache_version_manager.get_current_version('permissions'),
            'locations': cache_version_manager.get_current_version('locations'),
            'roles': cache_version_manager.get_current_version('roles'),
            'audit': cache_version_manager.get_current_version('audit'),
        }

        # Determine health status
        health_issues = []

        if stats.get('hits', 0) == 0 and stats.get('misses', 0) > 0:
            health_issues.append('No cache hits detected - possible cache backend issues')

        if stats.get('memory_used') == 'unknown':
            health_issues.append('Unable to determine cache memory usage')

        health_status = {
            'status': 'healthy' if not health_issues else 'warning',
            'cache_stats': stats,
            'cache_versions': versions,
            'issues': health_issues,
            'timestamp': timezone.now().isoformat(),
        }

        return Response(health_status)

    except Exception as e:
        logger.error(f"Error checking cache health: {e}")
        return Response(
            {'error': 'Failed to check cache health', 'status': 'error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
