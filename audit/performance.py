"""
Performance optimization utilities for large audit datasets.

Provides caching, query optimization, and database performance enhancements
for handling large volumes of audit data efficiently.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from django.core.cache import cache
from django.db import connection, models
from django.db.models import Count, Q
from django.utils import timezone

from .models import AuditLog, SecurityAlert


class AuditQueryOptimizer:
    """
    Query optimization utilities for audit data.

    Provides optimized query patterns and caching for frequently accessed audit data.
    """

    def __init__(self):
        self.cache_timeout = 300  # 5 minutes default cache timeout

    def get_user_recent_activity(self, user_id: str, hours: int = 24, use_cache: bool = True) -> List[Dict]:
        """
        Get recent activity for a user with optimized queries and caching.

        Args:
            user_id: User ID to get activity for
            hours: Hours of activity to retrieve
            use_cache: Whether to use caching

        Returns:
            List of recent audit logs
        """
        cache_key = f"audit_user_activity_{user_id}_{hours}_{timezone.now().strftime('%Y%m%d%H')}"

        if use_cache:
            cached_data = cache.get(cache_key)
            if cached_data:
                return cached_data

        start_time = timezone.now() - timedelta(hours=hours)

        # Optimized query with select_related to reduce database hits
        logs = AuditLog.objects.filter(
            user_id=user_id,
            created_at__gte=start_time
        ).select_related('user', 'location').order_by('-created_at')[:1000]  # Limit results

        # Convert to list of dicts for caching
        activity_data = list(logs.values(
            'id', 'action', 'resource_type', 'resource_name',
            'ip_address', 'risk_score', 'is_suspicious', 'created_at',
            'user__username', 'location__name'
        ))

        if use_cache:
            cache.set(cache_key, activity_data, self.cache_timeout)

        return activity_data

    def get_risk_score_summary(self, days: int = 7, use_cache: bool = True) -> Dict:
        """
        Get risk score summary with optimized aggregation queries.

        Args:
            days: Number of days to analyze
            use_cache: Whether to use caching

        Returns:
            Risk score summary statistics
        """
        cache_key = f"audit_risk_summary_{days}_{timezone.now().strftime('%Y%m%d%H')}"

        if use_cache:
            cached_data = cache.get(cache_key)
            if cached_data:
                return cached_data

        start_date = timezone.now() - timedelta(days=days)

        # Use database aggregation for better performance
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    COUNT(*) as total_logs,
                    AVG(risk_score) as avg_risk,
                    MAX(risk_score) as max_risk,
                    MIN(risk_score) as min_risk,
                    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_count,
                    COUNT(CASE WHEN is_suspicious = true THEN 1 END) as suspicious_count
                FROM audit_auditlog
                WHERE created_at >= %s
            """, [start_date])

            row = cursor.fetchone()

        summary = {
            'total_logs': row[0],
            'avg_risk_score': round(row[1] or 0, 2),
            'max_risk_score': row[2] or 0,
            'min_risk_score': row[3] or 0,
            'high_risk_count': row[4],
            'suspicious_count': row[5],
            'analyzed_days': days,
        }

        if use_cache:
            cache.set(cache_key, summary, self.cache_timeout)

        return summary

    def get_top_risky_users(self, limit: int = 10, days: int = 7, use_cache: bool = True) -> List[Dict]:
        """
        Get users with highest risk scores using optimized queries.

        Args:
            limit: Maximum number of users to return
            days: Number of days to analyze
            use_cache: Whether to use caching

        Returns:
            List of users with risk statistics
        """
        cache_key = f"audit_top_risky_users_{limit}_{days}_{timezone.now().strftime('%Y%m%d%H')}"

        if use_cache:
            cached_data = cache.get(cache_key)
            if cached_data:
                return cached_data

        start_date = timezone.now() - timedelta(days=days)

        # Optimized query using database aggregation
        risky_users = AuditLog.objects.filter(
            created_at__gte=start_date,
            risk_score__gte=50  # Only consider logs with some risk
        ).values('user', 'username').annotate(
            high_risk_count=Count('id', filter=Q(risk_score__gte=70)),
            total_actions=Count('id'),
            avg_risk_score=models.Avg('risk_score'),
            max_risk_score=models.Max('risk_score'),
            suspicious_count=Count('id', filter=Q(is_suspicious=True))
        ).order_by('-high_risk_count', '-avg_risk_score')[:limit]

        users_data = list(risky_users)

        if use_cache:
            cache.set(cache_key, users_data, self.cache_timeout)

        return users_data

    def bulk_create_audit_logs(self, logs_data: List[Dict]) -> int:
        """
        Bulk create audit logs for better performance.

        Args:
            logs_data: List of audit log data dictionaries

        Returns:
            Number of logs created
        """
        if not logs_data:
            return 0

        # Pre-process data to add computed fields
        processed_logs = []
        for log_data in logs_data:
            # Add any computed fields here
            if 'user' in log_data and hasattr(log_data['user'], 'get_username'):
                log_data['username'] = log_data['user'].get_username()

            processed_logs.append(AuditLog(**log_data))

        # Bulk create for better performance
        created_logs = AuditLog.objects.bulk_create(
            processed_logs,
            batch_size=1000,
            ignore_conflicts=True
        )

        return len(created_logs)

    def get_paginated_audit_logs(self, page: int = 1, page_size: int = 50,
                                filters: Optional[Dict] = None) -> Tuple[List[Dict], int]:
        """
        Get paginated audit logs with optimized queries.

        Args:
            page: Page number (1-based)
            page_size: Number of items per page
            filters: Additional filters to apply

        Returns:
            Tuple of (logs_list, total_count)
        """
        filters = filters or {}
        offset = (page - 1) * page_size

        # Base queryset with select_related for optimization
        queryset = AuditLog.objects.select_related('user', 'location')

        # Apply filters
        for field, value in filters.items():
            if '__' in field:  # Complex lookup
                queryset = queryset.filter(**{field: value})
            else:
                queryset = queryset.filter(**{f"{field}__icontains": value})

        # Get total count efficiently
        total_count = queryset.count()

        # Get paginated results
        logs = queryset.order_by('-created_at')[offset:offset + page_size]

        # Convert to list of dicts
        logs_data = list(logs.values(
            'id', 'action', 'username', 'resource_type', 'resource_name',
            'ip_address', 'risk_score', 'is_suspicious', 'created_at',
            'user__email', 'location__name'
        ))

        return logs_data, total_count


class AuditCacheManager:
    """
    Cache management utilities for audit data.

    Provides intelligent caching strategies for frequently accessed audit information.
    """

    def __init__(self):
        self.default_timeout = 600  # 10 minutes

    def cache_user_session_data(self, user_id: str, session_data: Dict):
        """
        Cache user session data for performance.

        Args:
            user_id: User ID
            session_data: Session data to cache
        """
        cache_key = f"audit_session_{user_id}"
        cache.set(cache_key, session_data, self.default_timeout)

    def get_user_session_data(self, user_id: str) -> Optional[Dict]:
        """
        Get cached user session data.

        Args:
            user_id: User ID

        Returns:
            Cached session data or None
        """
        cache_key = f"audit_session_{user_id}"
        return cache.get(cache_key)

    def cache_security_metrics(self, metrics_data: Dict, duration_minutes: int = 60):
        """
        Cache security metrics for dashboard performance.

        Args:
            metrics_data: Security metrics to cache
            duration_minutes: How long to cache (in minutes)
        """
        cache_key = f"audit_security_metrics_{timezone.now().strftime('%Y%m%d%H%M')}"
        cache.set(cache_key, metrics_data, duration_minutes * 60)

    def get_security_metrics(self) -> Optional[Dict]:
        """
        Get cached security metrics.

        Returns:
            Cached security metrics or None
        """
        # Try to get the most recent cached metrics
        current_time = timezone.now()
        for i in range(60):  # Check last hour
            check_time = current_time - timedelta(minutes=i)
            cache_key = f"audit_security_metrics_{check_time.strftime('%Y%m%d%H%M')}"
            data = cache.get(cache_key)
            if data:
                return data
        return None

    def invalidate_user_cache(self, user_id: str):
        """
        Invalidate all cached data for a user.

        Args:
            user_id: User ID to invalidate cache for
        """
        cache_keys = [
            f"audit_user_activity_{user_id}_*",
            f"audit_session_{user_id}",
            f"audit_user_risk_{user_id}_*",
        ]

        # Delete pattern-based keys (simplified - in production use a cache backend that supports patterns)
        for key_pattern in cache_keys:
            # This is a simplified approach - real implementation would need pattern deletion
            cache.delete(key_pattern.replace('*', ''))

    def warmup_cache(self):
        """
        Pre-populate cache with frequently accessed data.

        This method should be called during application startup or maintenance windows.
        """
        # Cache recent security metrics
        optimizer = AuditQueryOptimizer()
        metrics = optimizer.get_risk_score_summary(days=1, use_cache=False)
        self.cache_security_metrics(metrics, duration_minutes=15)

        # Cache top risky users
        top_users = optimizer.get_top_risky_users(limit=20, days=1, use_cache=False)
        cache_key = f"audit_top_risky_users_cached_{timezone.now().strftime('%Y%m%d%H')}"
        cache.set(cache_key, top_users, 1800)  # 30 minutes


class AuditPerformanceMonitor:
    """
    Performance monitoring utilities for audit operations.

    Tracks query performance and provides optimization recommendations.
    """

    def __init__(self):
        self.slow_query_threshold = 1.0  # seconds

    def monitor_query_performance(self, query_name: str, execution_time: float,
                                query_params: Optional[Dict] = None):
        """
        Monitor and log query performance.

        Args:
            query_name: Name/identifier for the query
            execution_time: Time taken to execute (in seconds)
            query_params: Query parameters for analysis
        """
        if execution_time > self.slow_query_threshold:
            # Log slow query
            import logging
            logger = logging.getLogger('audit.performance')

            log_data = {
                'query_name': query_name,
                'execution_time': execution_time,
                'query_params': query_params or {},
                'timestamp': timezone.now().isoformat(),
            }

            logger.warning(f"Slow audit query: {query_name} took {execution_time:.2f}s", extra=log_data)

            # Store in cache for performance analysis
            slow_queries = cache.get('audit_slow_queries', [])
            slow_queries.append(log_data)

            # Keep only last 100 slow queries
            slow_queries = slow_queries[-100:]
            cache.set('audit_slow_queries', slow_queries, 86400)  # 24 hours

    def get_performance_stats(self) -> Dict:
        """
        Get performance statistics for audit operations.

        Returns:
            Performance statistics
        """
        slow_queries = cache.get('audit_slow_queries', [])

        if not slow_queries:
            return {'message': 'No slow queries recorded'}

        # Analyze slow queries
        total_slow = len(slow_queries)
        avg_time = sum(q['execution_time'] for q in slow_queries) / total_slow
        max_time = max(q['execution_time'] for q in slow_queries)

        # Group by query name
        query_counts = {}
        for query in slow_queries:
            name = query['query_name']
            query_counts[name] = query_counts.get(name, 0) + 1

        return {
            'total_slow_queries': total_slow,
            'avg_execution_time': round(avg_time, 2),
            'max_execution_time': round(max_time, 2),
            'slow_queries_by_type': query_counts,
            'time_range': f"{slow_queries[0]['timestamp']} to {slow_queries[-1]['timestamp']}" if slow_queries else None,
        }

    def get_optimization_recommendations(self) -> List[str]:
        """
        Generate optimization recommendations based on performance data.

        Returns:
            List of optimization recommendations
        """
        recommendations = []
        stats = self.get_performance_stats()

        if stats.get('total_slow_queries', 0) > 10:
            recommendations.append("Consider adding database indexes on frequently queried fields")
            recommendations.append("Implement query result caching for expensive operations")
            recommendations.append("Consider data partitioning for large audit tables")

        if stats.get('avg_execution_time', 0) > 2.0:
            recommendations.append("Queries are taking too long - review database schema and indexes")
            recommendations.append("Consider implementing read replicas for audit queries")

        # Check if we have many slow user activity queries
        query_counts = stats.get('slow_queries_by_type', {})
        if query_counts.get('user_activity', 0) > 5:
            recommendations.append("Optimize user activity queries - consider caching or pre-computed summaries")

        return recommendations


# Global instances for easy access
query_optimizer = AuditQueryOptimizer()
cache_manager = AuditCacheManager()
performance_monitor = AuditPerformanceMonitor()
