"""
Comprehensive caching utilities for Authloc system performance optimization.

Provides multi-level caching, cache utilities, invalidation strategies,
and performance monitoring for Redis-backed Django applications.
"""

import hashlib
import json
import logging
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union
from datetime import datetime, timedelta

from django.core.cache import cache, caches
from django.db import connection
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)


class CacheKeyGenerator:
    """Generate standardized cache keys with consistent formatting."""

    @staticmethod
    def generate_cache_key(prefix: str, *args, **kwargs) -> str:
        """
        Generate a standardized cache key.

        Args:
            prefix: Cache key prefix (e.g., 'user_permissions', 'location_tree')
            *args: Positional arguments to include in key
            **kwargs: Keyword arguments to include in key (sorted by key)

        Returns:
            Formatted cache key string
        """
        key_parts = [prefix]

        # Add positional arguments
        for arg in args:
            if arg is not None:
                key_parts.append(str(arg))

        # Add keyword arguments (sorted for consistency)
        if kwargs:
            sorted_kwargs = sorted(kwargs.items())
            for key, value in sorted_kwargs:
                if value is not None:
                    key_parts.extend([key, str(value)])

        # Create final key with hash for length consistency
        key_string = ':'.join(key_parts)
        if len(key_string) > 200:  # Redis key length limit consideration
            key_hash = hashlib.md5(key_string.encode()).hexdigest()[:8]
            key_string = f"{prefix}:{key_hash}"

        return key_string

    @staticmethod
    def generate_pattern_key(prefix: str, *args, **kwargs) -> str:
        """
        Generate a pattern key for cache invalidation (with wildcards).

        Args:
            prefix: Cache key prefix
            *args: Positional arguments
            **kwargs: Keyword arguments with None values treated as wildcards

        Returns:
            Pattern key with * wildcards for partial matching
        """
        key_parts = [prefix]

        for arg in args:
            if arg is not None:
                key_parts.append(str(arg))
            else:
                key_parts.append('*')

        if kwargs:
            sorted_kwargs = sorted(kwargs.items())
            for key, value in sorted_kwargs:
                key_parts.append(key)
                if value is not None:
                    key_parts.append(str(value))
                else:
                    key_parts.append('*')

        return ':'.join(key_parts)


class CacheManager:
    """Enhanced cache manager with compression and multi-level support."""

    def __init__(self, cache_alias: str = 'default', compression_threshold: int = 1024):
        """
        Initialize cache manager.

        Args:
            cache_alias: Django cache alias to use
            compression_threshold: Size threshold for compression (bytes)
        """
        self.cache = caches[cache_alias]
        self.compression_threshold = compression_threshold

    def get_cached_or_set(
        self,
        key: str,
        callable_func: Callable,
        timeout: Optional[int] = None,
        version: Optional[int] = None,
        force_refresh: bool = False
    ) -> Any:
        """
        Get cached value or set it if not exists.

        Args:
            key: Cache key
            callable_func: Function to call if cache miss
            timeout: Cache timeout in seconds
            version: Cache version
            force_refresh: Force cache refresh even if exists

        Returns:
            Cached or computed value
        """
        if not force_refresh:
            cached_value = self.cache.get(key, version=version)
            if cached_value is not None:
                logger.debug(f"Cache hit for key: {key}")
                return cached_value

        logger.debug(f"Cache miss for key: {key}, computing value")
        start_time = time.time()
        value = callable_func()
        computation_time = time.time() - start_time

        # Log slow computations
        if computation_time > 1.0:  # More than 1 second
            logger.warning(f"Slow cache computation for key '{key}': {computation_time:.2f}s")

        # Store in cache
        self.cache.set(key, value, timeout=timeout, version=version)
        return value

    def invalidate_cache_pattern(self, pattern: str, version: Optional[int] = None) -> int:
        """
        Invalidate cache keys matching a pattern.

        Args:
            pattern: Pattern to match (supports * wildcards)
            version: Cache version

        Returns:
            Number of keys invalidated
        """
        try:
            # For Redis backend, we can use delete_pattern
            if hasattr(self.cache, '_cache') and hasattr(self.cache._cache, 'delete_pattern'):
                return self.cache._cache.delete_pattern(pattern)
            else:
                # Fallback: get all keys and delete matching ones
                # Note: This is less efficient and may not work with all backends
                logger.warning("Pattern deletion not supported by cache backend, using fallback method")
                return 0
        except Exception as e:
            logger.error(f"Error invalidating cache pattern '{pattern}': {e}")
            return 0

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache performance statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            if hasattr(self.cache, '_cache') and hasattr(self.cache._cache, 'info'):
                redis_info = self.cache._cache.info()
                return {
                    'hits': redis_info.get('keyspace_hits', 0),
                    'misses': redis_info.get('keyspace_misses', 0),
                    'total_connections': redis_info.get('connected_clients', 0),
                    'memory_used': redis_info.get('used_memory_human', 'unknown'),
                    'uptime_days': redis_info.get('uptime_in_days', 0),
                }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")

        return {
            'hits': 0,
            'misses': 0,
            'total_connections': 0,
            'memory_used': 'unknown',
            'uptime_days': 0,
        }

    def clear_cache(self, pattern: Optional[str] = None) -> bool:
        """
        Clear cache or specific pattern.

        Args:
            pattern: Optional pattern to clear, clears all if None

        Returns:
            Success status
        """
        try:
            if pattern:
                return self.invalidate_cache_pattern(pattern) > 0
            else:
                self.cache.clear()
                return True
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False


class CacheVersionManager:
    """Manage cache versioning for gradual updates."""

    VERSION_KEY_PREFIX = "cache_version"

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    def get_current_version(self, namespace: str) -> int:
        """Get current cache version for a namespace."""
        version_key = f"{self.VERSION_KEY_PREFIX}:{namespace}"
        version = self.cache_manager.cache.get(version_key, 0)
        return version

    def increment_version(self, namespace: str) -> int:
        """Increment cache version for a namespace."""
        current_version = self.get_current_version(namespace)
        new_version = current_version + 1
        version_key = f"{self.VERSION_KEY_PREFIX}:{namespace}"
        self.cache_manager.cache.set(version_key, new_version, timeout=None)  # Never expires
        logger.info(f"Incremented cache version for namespace '{namespace}' to {new_version}")
        return new_version

    def invalidate_namespace(self, namespace: str) -> bool:
        """Invalidate all caches in a namespace by incrementing version."""
        self.increment_version(namespace)
        return True


# Global instances
cache_key_generator = CacheKeyGenerator()
cache_manager = CacheManager()
cache_version_manager = CacheVersionManager(cache_manager)


# Decorators
def cached_method(timeout: int = 300, key_prefix: Optional[str] = None, versioned: bool = False):
    """
    Decorator for caching method results.

    Args:
        timeout: Cache timeout in seconds
        key_prefix: Custom key prefix, uses method name if None
        versioned: Whether to use cache versioning
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            prefix = key_prefix or f"{func.__module__}.{func.__qualname__}"
            cache_key = cache_key_generator.generate_cache_key(prefix, *args[1:], **kwargs)  # Skip 'self'

            # Get cache version if versioned
            version = None
            if versioned:
                namespace = prefix.split('.')[0]  # Use module as namespace
                version = cache_version_manager.get_current_version(namespace)

            return cache_manager.get_cached_or_set(
                key=cache_key,
                callable_func=lambda: func(*args, **kwargs),
                timeout=timeout,
                version=version
            )
        return wrapper
    return decorator


# Utility functions
def get_cached_or_set(key: str, callable_func: Callable, timeout: Optional[int] = None) -> Any:
    """Convenience function for cache_manager.get_cached_or_set."""
    return cache_manager.get_cached_or_set(key, callable_func, timeout)


def invalidate_cache_pattern(pattern: str) -> int:
    """Convenience function for cache_manager.invalidate_cache_pattern."""
    return cache_manager.invalidate_cache_pattern(pattern)


def generate_cache_key(prefix: str, *args, **kwargs) -> str:
    """Convenience function for cache_key_generator.generate_cache_key."""
    return cache_key_generator.generate_cache_key(prefix, *args, **kwargs)


# Cache warming utilities
class CacheWarmer:
    """Utilities for cache warming operations."""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.warming_tasks = {}

    def register_warming_task(self, name: str, func: Callable, priority: int = 1):
        """
        Register a cache warming task.

        Args:
            name: Task name
            func: Function to call for warming
            priority: Priority (higher numbers = higher priority)
        """
        self.warming_tasks[name] = {
            'func': func,
            'priority': priority,
        }

    def warm_cache(self, task_names: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Warm specified cache tasks or all registered tasks.

        Args:
            task_names: Specific tasks to warm, or None for all

        Returns:
            Dictionary with task results
        """
        results = {}
        tasks_to_run = task_names or list(self.warming_tasks.keys())

        # Sort by priority (highest first)
        sorted_tasks = sorted(
            [(name, self.warming_tasks[name]) for name in tasks_to_run],
            key=lambda x: x[1]['priority'],
            reverse=True
        )

        for task_name, task_info in sorted_tasks:
            try:
                logger.info(f"Warming cache for task: {task_name}")
                start_time = time.time()
                task_info['func']()
                duration = time.time() - start_time
                logger.info(f"Cache warming completed for {task_name} in {duration:.2f}s")
                results[task_name] = True
            except Exception as e:
                logger.error(f"Cache warming failed for {task_name}: {e}")
                results[task_name] = False

        return results


# Global cache warmer instance
cache_warmer = CacheWarmer(cache_manager)
