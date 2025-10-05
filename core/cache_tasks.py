"""
Celery tasks for background cache warming and maintenance.

Provides scheduled cache warming, cache cleanup, and maintenance operations.
"""

import logging
from typing import List, Optional, Dict, Any

from celery import shared_task
from django.core.management import call_command
from django.conf import settings

from core.cache_utils import cache_warmer
from permissions.permission_checker import cache_user_permissions
from locations.location_tree_cache import warm_location_cache
from permissions.role_cache import warm_role_cache

logger = logging.getLogger(__name__)


@shared_task(bind=True, name='cache.warm_all_caches')
def warm_all_caches(self) -> Dict[str, Any]:
    """
    Warm all registered caches.

    Returns:
        Dictionary with warming results
    """
    logger.info("Starting scheduled cache warming for all caches")

    try:
        results = cache_warmer.warm_cache()

        successful = sum(1 for result in results.values() if result)
        failed = len(results) - successful

        logger.info(f"Cache warming completed: {successful} successful, {failed} failed")

        return {
            'status': 'completed',
            'results': results,
            'successful': successful,
            'failed': failed,
            'total': len(results),
        }

    except Exception as e:
        logger.error(f"Error during cache warming: {e}")
        self.retry(countdown=60, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.warm_user_permissions')
def warm_user_permissions_cache(self, user_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Warm user permissions cache for specific users or all active users.

    Args:
        user_ids: Specific user IDs to warm, or None for all active users

    Returns:
        Dictionary with warming results
    """
    from authentication.models import CustomUser

    logger.info(f"Starting user permissions cache warming for users: {user_ids or 'all'}")

    try:
        if user_ids:
            users = CustomUser.objects.filter(pk__in=user_ids, is_active=True)
        else:
            # Warm for recently active users (limit to prevent long-running task)
            users = CustomUser.objects.filter(is_active=True).order_by('-last_login')[:100]

        results = {}
        for user in users:
            try:
                cache_user_permissions(user)
                results[str(user.pk)] = True
            except Exception as e:
                logger.error(f"Failed to warm permissions cache for user {user.pk}: {e}")
                results[str(user.pk)] = False

        successful = sum(1 for result in results.values() if result)
        logger.info(f"User permissions cache warming completed: {successful}/{len(results)} successful")

        return {
            'status': 'completed',
            'results': results,
            'successful': successful,
            'failed': len(results) - successful,
            'total': len(results),
        }

    except Exception as e:
        logger.error(f"Error during user permissions cache warming: {e}")
        self.retry(countdown=60, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.warm_location_cache')
def warm_location_cache_task(self) -> Dict[str, Any]:
    """
    Warm location hierarchy cache.

    Returns:
        Dictionary with warming results
    """
    logger.info("Starting location cache warming")

    try:
        warm_location_cache()
        logger.info("Location cache warming completed")

        return {
            'status': 'completed',
            'message': 'Location cache warmed successfully',
        }

    except Exception as e:
        logger.error(f"Error during location cache warming: {e}")
        self.retry(countdown=60, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.warm_role_cache')
def warm_role_cache_task(self) -> Dict[str, Any]:
    """
    Warm role definitions cache.

    Returns:
        Dictionary with warming results
    """
    logger.info("Starting role cache warming")

    try:
        warm_role_cache()
        logger.info("Role cache warming completed")

        return {
            'status': 'completed',
            'message': 'Role cache warmed successfully',
        }

    except Exception as e:
        logger.error(f"Error during role cache warming: {e}")
        self.retry(countdown=60, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.cleanup_expired')
def cleanup_expired_cache(self) -> Dict[str, Any]:
    """
    Clean up expired cache entries and optimize cache storage.

    Returns:
        Dictionary with cleanup results
    """
    logger.info("Starting cache cleanup")

    try:
        # This is mainly handled by Redis TTL, but we can add custom cleanup logic
        from core.cache_utils import cache_manager

        # Clear any old cache keys that might have accumulated
        # (This is a placeholder - actual cleanup depends on cache backend)

        # Example: Clear old audit cache keys that might be stuck
        old_patterns = [
            'audit:*',  # Clear old audit cache patterns if needed
        ]

        total_cleared = 0
        for pattern in old_patterns:
            cleared = cache_manager.invalidate_cache_pattern(pattern)
            total_cleared += cleared
            logger.info(f"Cleared {cleared} entries for pattern: {pattern}")

        logger.info(f"Cache cleanup completed: {total_cleared} entries cleared")

        return {
            'status': 'completed',
            'entries_cleared': total_cleared,
            'message': f'Cleaned up {total_cleared} expired cache entries',
        }

    except Exception as e:
        logger.error(f"Error during cache cleanup: {e}")
        self.retry(countdown=300, max_retries=2)  # Longer delay for cleanup
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.warm_intelligent')
def warm_cache_intelligently(self) -> Dict[str, Any]:
    """
    Intelligently warm caches based on usage patterns.

    Analyzes recent cache access patterns and warms frequently accessed data.

    Returns:
        Dictionary with warming results
    """
    logger.info("Starting intelligent cache warming")

    try:
        # This would analyze access patterns and warm based on usage
        # For now, just warm all caches

        results = warm_all_caches()

        logger.info("Intelligent cache warming completed")

        return {
            'status': 'completed',
            'results': results,
            'message': 'Intelligent cache warming completed (currently warms all caches)',
        }

    except Exception as e:
        logger.error(f"Error during intelligent cache warming: {e}")
        self.retry(countdown=120, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


@shared_task(bind=True, name='cache.refresh_audit_stats')
def refresh_audit_stats_cache(self) -> Dict[str, Any]:
    """
    Refresh audit statistics cache with latest data.

    Returns:
        Dictionary with refresh results
    """
    logger.info("Starting audit stats cache refresh")

    try:
        from audit.performance import query_optimizer

        # Refresh various audit statistics
        refreshes = [
            ('risk_summary_7d', lambda: query_optimizer.get_risk_score_summary(days=7)),
            ('risk_summary_1d', lambda: query_optimizer.get_risk_score_summary(days=1)),
            ('top_risky_users_7d', lambda: query_optimizer.get_top_risky_users(days=7)),
            ('top_risky_users_1d', lambda: query_optimizer.get_top_risky_users(days=1)),
        ]

        results = {}
        for name, refresh_func in refreshes:
            try:
                refresh_func()
                results[name] = True
                logger.debug(f"Refreshed audit stat: {name}")
            except Exception as e:
                logger.error(f"Failed to refresh audit stat {name}: {e}")
                results[name] = False

        successful = sum(1 for result in results.values() if result)
        logger.info(f"Audit stats cache refresh completed: {successful}/{len(results)} successful")

        return {
            'status': 'completed',
            'results': results,
            'successful': successful,
            'failed': len(results) - successful,
            'total': len(results),
        }

    except Exception as e:
        logger.error(f"Error during audit stats cache refresh: {e}")
        self.retry(countdown=60, max_retries=3)
        return {
            'status': 'failed',
            'error': str(e),
        }


# Register periodic tasks in Celery Beat schedule
# These would be configured in settings.py under CELERY_BEAT_SCHEDULE

PERIODIC_CACHE_TASKS = {
    'warm-all-caches-hourly': {
        'task': 'cache.warm_all_caches',
        'schedule': 3600.0,  # Every hour
    },
    'warm-user-permissions-daily': {
        'task': 'cache.warm_user_permissions',
        'schedule': 86400.0,  # Daily
    },
    'warm-location-cache-daily': {
        'task': 'cache.warm_location_cache',
        'schedule': 86400.0,  # Daily
    },
    'warm-role-cache-daily': {
        'task': 'cache.warm_role_cache',
        'schedule': 86400.0,  # Daily
    },
    'cleanup-expired-cache-weekly': {
        'task': 'cache.cleanup_expired_cache',
        'schedule': 604800.0,  # Weekly
    },
    'refresh-audit-stats': {
        'task': 'cache.refresh_audit_stats_cache',
        'schedule': 1800.0,  # Every 30 minutes
    },
}
