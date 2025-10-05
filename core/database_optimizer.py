"""
Database query optimization utilities.

Provides database index management and query optimization helpers
for improved performance.
"""

import logging
from typing import Dict, List, Optional, Any
from django.db import connection, models
from django.db.models import QuerySet, Prefetch
from django.core.management.color import no_style

logger = logging.getLogger(__name__)


class DatabaseOptimizer:
    """Database optimization utilities."""

    @staticmethod
    def get_missing_indexes() -> List[Dict[str, Any]]:
        """
        Analyze database and suggest missing indexes based on query patterns.

        Returns:
            List of suggested indexes
        """
        suggestions = []

        # Analyze common query patterns from the codebase
        with connection.cursor() as cursor:
            # Check for indexes on frequently queried fields

            # Audit logs - common query fields
            audit_indexes = [
                ('audit_auditlog', 'created_at'),
                ('audit_auditlog', 'user_id'),
                ('audit_auditlog', 'risk_score'),
                ('audit_auditlog', 'is_suspicious'),
                ('audit_auditlog', 'action'),
                ('audit_auditlog', 'resource_type'),
            ]

            for table, column in audit_indexes:
                try:
                    cursor.execute(f"""
                        SELECT 1 FROM pg_indexes
                        WHERE tablename = %s AND indexdef LIKE %s
                        LIMIT 1
                    """, [table, f'%{column}%'])

                    if not cursor.fetchone():
                        suggestions.append({
                            'table': table,
                            'column': column,
                            'reason': f'Frequently queried field in {table}',
                            'sql': f'CREATE INDEX idx_{table}_{column} ON {table} ({column});'
                        })
                except Exception as e:
                    logger.warning(f"Error checking index for {table}.{column}: {e}")

            # Location indexes
            location_indexes = [
                ('locations_location', 'path'),
                ('locations_location', 'level'),
                ('locations_location', 'is_active'),
                ('locations_location', 'type_id'),
                ('locations_location', 'parent_id'),
            ]

            for table, column in location_indexes:
                try:
                    cursor.execute(f"""
                        SELECT 1 FROM pg_indexes
                        WHERE tablename = %s AND indexdef LIKE %s
                        LIMIT 1
                    """, [table, f'%{column}%'])

                    if not cursor.fetchone():
                        suggestions.append({
                            'table': table,
                            'column': column,
                            'reason': f'Frequently queried field in {table}',
                            'sql': f'CREATE INDEX idx_{table}_{column} ON {table} ({column});'
                        })
                except Exception as e:
                    logger.warning(f"Error checking index for {table}.{column}: {e}")

            # Permissions indexes
            permission_indexes = [
                ('permissions_userrole', 'user_id'),
                ('permissions_userrole', 'role_id'),
                ('permissions_userrole', 'is_active'),
                ('permissions_locationaccess', 'user_id'),
                ('permissions_locationaccess', 'role_id'),
                ('permissions_locationaccess', 'location_id'),
            ]

            for table, column in permission_indexes:
                try:
                    cursor.execute(f"""
                        SELECT 1 FROM pg_indexes
                        WHERE tablename = %s AND indexdef LIKE %s
                        LIMIT 1
                    """, [table, f'%{column}%'])

                    if not cursor.fetchone():
                        suggestions.append({
                            'table': table,
                            'column': column,
                            'reason': f'Frequently queried field in {table}',
                            'sql': f'CREATE INDEX idx_{table}_{column} ON {table} ({column});'
                        })
                except Exception as e:
                    logger.warning(f"Error checking index for {table}.{column}: {e}")

        return suggestions

    @staticmethod
    def create_composite_indexes() -> List[str]:
        """
        Get SQL for composite indexes that would improve query performance.

        Returns:
            List of SQL statements for composite indexes
        """
        indexes = [
            # Audit logs composite indexes
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_user_created ON audit_auditlog (user_id, created_at);",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_risk_created ON audit_auditlog (risk_score, created_at) WHERE risk_score >= 50;",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_action_resource ON audit_auditlog (action, resource_type);",

            # Location composite indexes
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_location_parent_level ON locations_location (parent_id, level);",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_location_type_active ON locations_location (type_id, is_active);",

            # Permissions composite indexes
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_role_active ON permissions_userrole (user_id, role_id, is_active);",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_location_access_user ON permissions_locationaccess (user_id, location_id, can_read);",
        ]

        return indexes

    @staticmethod
    def optimize_queryset(queryset: QuerySet, model_name: str) -> QuerySet:
        """
        Apply optimization patterns to a queryset based on the model.

        Args:
            queryset: The queryset to optimize
            model_name: Name of the model for optimization patterns

        Returns:
            Optimized queryset
        """
        if model_name == 'audit.auditlog':
            return queryset.select_related('user', 'location')
        elif model_name == 'locations.location':
            return queryset.select_related('type', 'parent')
        elif model_name == 'permissions.userrole':
            return queryset.select_related('user', 'role', 'location')
        elif model_name == 'permissions.locationaccess':
            return queryset.select_related('user', 'role', 'location')

        return queryset

    @staticmethod
    def get_query_plan(sql: str, params: Optional[List] = None) -> Dict[str, Any]:
        """
        Get PostgreSQL query execution plan for analysis.

        Args:
            sql: SQL query string
            params: Query parameters

        Returns:
            Query plan information
        """
        with connection.cursor() as cursor:
            try:
                explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}"
                cursor.execute(explain_sql, params or [])
                plan = cursor.fetchall()
                return {
                    'plan': plan,
                    'query': sql,
                    'params': params,
                }
            except Exception as e:
                logger.error(f"Error getting query plan: {e}")
                return {
                    'error': str(e),
                    'query': sql,
                    'params': params,
                }

    @staticmethod
    def analyze_slow_queries(threshold_ms: int = 1000) -> List[Dict[str, Any]]:
        """
        Analyze slow queries from PostgreSQL logs.

        Args:
            threshold_ms: Threshold in milliseconds for slow queries

        Returns:
            List of slow query information
        """
        # This would typically analyze PostgreSQL logs or use pg_stat_statements
        # For now, return a placeholder
        return [{
            'message': 'Slow query analysis requires pg_stat_statements extension and proper configuration',
            'recommendation': 'Enable pg_stat_statements and configure log_min_duration_statement'
        }]


class QueryOptimizer:
    """Query optimization decorators and utilities."""

    @staticmethod
    def select_related(*fields):
        """Decorator to automatically add select_related to model methods."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                queryset = func(*args, **kwargs)
                if hasattr(queryset, 'select_related'):
                    return queryset.select_related(*fields)
                return queryset
            return wrapper
        return decorator

    @staticmethod
    def prefetch_related(*prefetches):
        """Decorator to automatically add prefetch_related to model methods."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                queryset = func(*args, **kwargs)
                if hasattr(queryset, 'prefetch_related'):
                    return queryset.prefetch_related(*prefetches)
                return queryset
            return wrapper
        return decorator

    @staticmethod
    def optimize_for_count():
        """Decorator to optimize queryset for count operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                queryset = func(*args, **kwargs)
                if hasattr(queryset, 'only'):
                    # Only select primary key for count operations
                    return queryset.only('pk')
                return queryset
            return wrapper
        return decorator


# Utility functions
def get_database_stats() -> Dict[str, Any]:
    """
    Get database performance statistics.

    Returns:
        Database statistics
    """
    with connection.cursor() as cursor:
        try:
            # Get table sizes
            cursor.execute("""
                SELECT
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY size_bytes DESC
                LIMIT 20;
            """)
            table_sizes = cursor.fetchall()

            # Get index usage
            cursor.execute("""
                SELECT
                    schemaname,
                    tablename,
                    indexname,
                    idx_scan,
                    idx_tup_read,
                    idx_tup_fetch
                FROM pg_stat_user_indexes
                ORDER BY idx_scan DESC
                LIMIT 20;
            """)
            index_usage = cursor.fetchall()

            return {
                'table_sizes': [
                    {
                        'schema': row[0],
                        'table': row[1],
                        'size': row[2],
                        'size_bytes': row[3]
                    } for row in table_sizes
                ],
                'index_usage': [
                    {
                        'schema': row[0],
                        'table': row[1],
                        'index': row[2],
                        'scans': row[3],
                        'tuples_read': row[4],
                        'tuples_fetched': row[5]
                    } for row in index_usage
                ]
            }
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {'error': str(e)}


# Global instances
database_optimizer = DatabaseOptimizer()
query_optimizer = QueryOptimizer()
