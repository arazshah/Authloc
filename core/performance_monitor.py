"""
Performance monitoring utilities for Authloc system.

Provides comprehensive monitoring of API response times, database query performance,
cache hit/miss ratios, and memory usage.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from functools import wraps
from datetime import datetime, timedelta

from django.core.cache import cache
from django.db import connection
from django.utils import timezone
from django.conf import settings

from core.cache_utils import cache_manager

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Comprehensive performance monitoring system."""

    def __init__(self, max_metrics_history: int = 1000):
        self.max_metrics_history = max_metrics_history
        self._metrics = defaultdict(lambda: deque(maxlen=max_metrics_history))
        self._lock = threading.Lock()
        self._counters = defaultdict(int)

    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, Any]] = None):
        """
        Record a performance metric.

        Args:
            name: Metric name
            value: Metric value
            tags: Additional tags for the metric
        """
        with self._lock:
            metric_data = {
                'value': value,
                'timestamp': timezone.now(),
                'tags': tags or {}
            }
            self._metrics[name].append(metric_data)

    def increment_counter(self, name: str, amount: int = 1):
        """
        Increment a counter metric.

        Args:
            name: Counter name
            amount: Amount to increment
        """
        with self._lock:
            self._counters[name] += amount

    def get_metrics_summary(self, name: Optional[str] = None, hours: int = 1) -> Dict[str, Any]:
        """
        Get metrics summary for the specified time period.

        Args:
            name: Specific metric name, or None for all
            hours: Hours of history to analyze

        Returns:
            Metrics summary
        """
        cutoff_time = timezone.now() - timedelta(hours=hours)

        with self._lock:
            if name:
                metrics = list(self._metrics[name])
            else:
                # Get all metrics
                metrics = []
                for metric_name, metric_data in self._metrics.items():
                    for data in metric_data:
                        metrics.append({
                            'name': metric_name,
                            **data
                        })

            # Filter by time
            recent_metrics = [m for m in metrics if m['timestamp'] >= cutoff_time]

            if not recent_metrics:
                return {'message': f'No metrics found for the last {hours} hours'}

            # Group by name
            grouped_metrics = defaultdict(list)
            for metric in recent_metrics:
                if name:
                    grouped_metrics[name].append(metric)
                else:
                    grouped_metrics[metric['name']].append(metric)

            summary = {}
            for metric_name, metric_list in grouped_metrics.items():
                values = [m['value'] for m in metric_list]

                summary[metric_name] = {
                    'count': len(values),
                    'min': min(values),
                    'max': max(values),
                    'avg': sum(values) / len(values),
                    'p95': sorted(values)[int(len(values) * 0.95)] if values else None,
                    'p99': sorted(values)[int(len(values) * 0.99)] if values else None,
                    'time_range': f"{min(m['timestamp'] for m in metric_list)} to {max(m['timestamp'] for m in metric_list)}",
                }

            # Add counters
            if name and name in self._counters:
                summary[name]['counter'] = self._counters[name]
            elif not name:
                summary['counters'] = dict(self._counters)

            return summary

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache performance statistics.

        Returns:
            Cache statistics
        """
        return cache_manager.get_cache_stats()

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database performance statistics.

        Returns:
            Database statistics
        """
        with connection.cursor() as cursor:
            try:
                # Get active connections
                cursor.execute("""
                    SELECT count(*) as active_connections
                    FROM pg_stat_activity
                    WHERE state = 'active';
                """)
                active_connections = cursor.fetchone()[0]

                # Get slow queries (queries running > 1 second)
                cursor.execute("""
                    SELECT count(*) as slow_queries
                    FROM pg_stat_activity
                    WHERE state = 'active'
                    AND now() - query_start > interval '1 second';
                """)
                slow_queries = cursor.fetchone()[0]

                # Get database size
                cursor.execute("SELECT pg_size_pretty(pg_database_size(current_database()));")
                db_size = cursor.fetchone()[0]

                return {
                    'active_connections': active_connections,
                    'slow_queries': slow_queries,
                    'database_size': db_size,
                    'connection_pool_stats': {
                        'total': connection.settings_dict.get('CONN_MAX_AGE', 0),
                        'in_use': len(connection.queries) if hasattr(connection, 'queries') else 0,
                    }
                }
            except Exception as e:
                logger.error(f"Error getting database stats: {e}")
                return {'error': str(e)}

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get overall system health metrics.

        Returns:
            System health status
        """
        cache_stats = self.get_cache_stats()
        db_stats = self.get_database_stats()
        metrics_summary = self.get_metrics_summary(hours=1)

        health_status = {
            'cache': {
                'status': 'healthy' if cache_stats.get('hits', 0) > 0 else 'warning',
                'stats': cache_stats,
            },
            'database': {
                'status': 'healthy' if db_stats.get('active_connections', 0) < 50 else 'warning',
                'stats': db_stats,
            },
            'performance': {
                'status': 'healthy',
                'metrics': metrics_summary,
            },
            'timestamp': timezone.now().isoformat(),
        }

        # Determine overall status
        statuses = [health_status['cache']['status'],
                   health_status['database']['status'],
                   health_status['performance']['status']]

        if 'error' in statuses:
            health_status['overall_status'] = 'error'
        elif 'warning' in statuses:
            health_status['overall_status'] = 'warning'
        else:
            health_status['overall_status'] = 'healthy'

        return health_status


class PerformanceMiddleware:
    """Django middleware for automatic performance monitoring."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.monitor = PerformanceMonitor()

    def __call__(self, request):
        start_time = time.time()

        # Record request start
        self.monitor.increment_counter('requests_total')
        self.monitor.record_metric(
            'request_started',
            time.time(),
            {'path': request.path, 'method': request.method}
        )

        response = self.get_response(request)

        # Record response time
        duration = time.time() - start_time
        self.monitor.record_metric(
            'response_time',
            duration * 1000,  # Convert to milliseconds
            {
                'path': request.path,
                'method': request.method,
                'status_code': response.status_code,
            }
        )

        # Record response size
        if hasattr(response, 'content'):
            response_size = len(response.content)
            self.monitor.record_metric(
                'response_size',
                response_size,
                {'path': request.path, 'method': request.method}
            )

        # Log slow requests
        if duration > getattr(settings, 'SLOW_REQUEST_THRESHOLD', 1.0):  # 1 second default
            logger.warning(
                f"Slow request: {request.method} {request.path} took {duration:.2f}s",
                extra={
                    'request_path': request.path,
                    'request_method': request.method,
                    'duration': duration,
                    'user': getattr(request.user, 'username', 'anonymous'),
                }
            )

        return response


def monitor_database_queries():
    """Context manager to monitor database queries."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            initial_queries = len(connection.queries)

            try:
                result = func(*args, **kwargs)

                query_count = len(connection.queries) - initial_queries
                duration = time.time() - start_time

                # Record metrics
                performance_monitor.record_metric('db_query_count', query_count)
                performance_monitor.record_metric('db_query_time', duration * 1000)

                # Log slow database operations
                if duration > getattr(settings, 'SLOW_DB_THRESHOLD', 0.5):  # 500ms default
                    logger.warning(
                        f"Slow database operation in {func.__name__}: {query_count} queries took {duration:.2f}s"
                    )

                return result
            except Exception as e:
                performance_monitor.record_metric('db_errors', 1)
                raise
        return wrapper
    return decorator


def monitor_cache_operations():
    """Decorator to monitor cache operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                duration = time.time() - start_time
                performance_monitor.record_metric('cache_operation_time', duration * 1000)

                # Check if this is a cache hit/miss by function name or result
                func_name = func.__name__
                if 'get' in func_name and result is None:
                    performance_monitor.increment_counter('cache_misses')
                elif 'get' in func_name and result is not None:
                    performance_monitor.increment_counter('cache_hits')

                return result
            except Exception as e:
                performance_monitor.record_metric('cache_errors', 1)
                raise
        return wrapper
    return decorator


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


def get_performance_metrics(hours: int = 1) -> Dict[str, Any]:
    """
    Get comprehensive performance metrics.

    Args:
        hours: Hours of history to analyze

    Returns:
        Performance metrics dictionary
    """
    return {
        'metrics': performance_monitor.get_metrics_summary(hours=hours),
        'cache_stats': performance_monitor.get_cache_stats(),
        'database_stats': performance_monitor.get_database_stats(),
        'system_health': performance_monitor.get_system_health(),
        'timestamp': timezone.now().isoformat(),
    }
