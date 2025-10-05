"""
Performance tests and benchmarks for the caching system.

Provides comprehensive testing of cache performance, hit rates, and system throughput.
"""

import time
import statistics
from typing import Dict, List, Any
from django.test import TestCase, override_settings
from django.core.cache import cache
from django.test.utils import override_settings

from core.cache_utils import cache_manager, generate_cache_key, get_cached_or_set
from permissions.permission_checker import cache_user_permissions
from locations.location_tree_cache import cache_location_tree
from permissions.role_cache import cache_role_definitions


class CachePerformanceTest(TestCase):
    """Performance tests for caching functionality."""

    def setUp(self):
        """Set up test data and cache."""
        # Clear cache before each test
        cache.clear()

    def test_cache_key_generation_performance(self):
        """Test performance of cache key generation."""
        iterations = 1000

        # Test data
        test_args = ['user', 123, 'location', 'neighborhood']
        test_kwargs = {'active': True, 'level': 5, 'parent_id': 'abc-123'}

        start_time = time.time()
        for _ in range(iterations):
            key = generate_cache_key('test_prefix', *test_args, **test_kwargs)
        end_time = time.time()

        avg_time = (end_time - start_time) / iterations * 1000  # Convert to milliseconds

        print(f"Cache key generation: {avg_time:.4f}ms per operation")
        self.assertLess(avg_time, 1.0, "Cache key generation should be < 1ms")

    def test_cache_operations_performance(self):
        """Test performance of basic cache operations."""
        iterations = 1000
        test_data = {'key': 'value', 'number': 42, 'list': [1, 2, 3]}

        # Test cache.set performance
        start_time = time.time()
        for i in range(iterations):
            cache_key = f'test_key_{i}'
            cache.set(cache_key, test_data, 300)
        set_time = time.time() - start_time

        # Test cache.get performance
        start_time = time.time()
        for i in range(iterations):
            cache_key = f'test_key_{i}'
            cache.get(cache_key)
        get_time = time.time() - start_time

        set_avg = set_time / iterations * 1000
        get_avg = get_time / iterations * 1000

        print(f"Cache set: {set_avg:.4f}ms per operation")
        print(f"Cache get: {get_avg:.4f}ms per operation")

        self.assertLess(set_avg, 5.0, "Cache set should be < 5ms")
        self.assertLess(get_avg, 2.0, "Cache get should be < 2ms")

    def test_get_cached_or_set_performance(self):
        """Test performance of get_cached_or_set function."""
        def expensive_operation():
            time.sleep(0.01)  # Simulate 10ms operation
            return {'result': 'computed', 'timestamp': time.time()}

        iterations = 100

        # First run - cache misses
        start_time = time.time()
        for i in range(iterations):
            cache_key = f'expensive_test_{i}'
            result = get_cached_or_set(cache_key, expensive_operation, timeout=300)
        first_run_time = time.time() - start_time

        # Second run - cache hits
        start_time = time.time()
        for i in range(iterations):
            cache_key = f'expensive_test_{i}'
            result = get_cached_or_set(cache_key, expensive_operation, timeout=300)
        second_run_time = time.time() - start_time

        first_avg = first_run_time / iterations * 1000
        second_avg = second_run_time / iterations * 1000
        speedup = first_run_time / second_run_time

        print(f"First run (cache miss): {first_avg:.2f}ms per operation")
        print(f"Second run (cache hit): {second_avg:.2f}ms per operation")
        print(f"Cache speedup: {speedup:.1f}x")

        self.assertGreater(speedup, 10, "Cache should provide significant speedup")
        self.assertLess(second_avg, 5.0, "Cached operations should be < 5ms")

    def test_user_permissions_cache_performance(self):
        """Test performance of user permissions caching."""
        from django.contrib.auth import get_user_model
        User = get_user_model()

        # Create test user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        iterations = 50

        # Time cache computation
        start_time = time.time()
        for _ in range(iterations):
            permissions = cache_user_permissions(user)
        end_time = time.time()

        avg_time = (end_time - start_time) / iterations * 1000

        print(f"User permissions caching: {avg_time:.2f}ms per operation")
        self.assertLess(avg_time, 100, "User permissions caching should be < 100ms")

        # Verify cache hit performance
        start_time = time.time()
        for _ in range(iterations):
            permissions = cache_user_permissions(user)
        end_time = time.time()

        cached_avg_time = (end_time - start_time) / iterations * 1000
        print(f"User permissions cache hit: {cached_avg_time:.2f}ms per operation")

        self.assertLess(cached_avg_time, 10, "Cached permissions should be < 10ms")

    def test_location_tree_cache_performance(self):
        """Test performance of location tree caching."""
        iterations = 10

        # Time cache computation
        start_time = time.time()
        for _ in range(iterations):
            tree = cache_location_tree()
        end_time = time.time()

        avg_time = (end_time - start_time) / iterations * 1000

        print(f"Location tree caching: {avg_time:.2f}ms per operation")
        self.assertLess(avg_time, 500, "Location tree caching should be < 500ms")

    def test_role_definitions_cache_performance(self):
        """Test performance of role definitions caching."""
        iterations = 10

        # Time cache computation
        start_time = time.time()
        for _ in range(iterations):
            roles = cache_role_definitions()
        end_time = time.time()

        avg_time = (end_time - start_time) / iterations * 1000

        print(f"Role definitions caching: {avg_time:.2f}ms per operation")
        self.assertLess(avg_time, 200, "Role definitions caching should be < 200ms")

    def test_cache_hit_miss_ratio(self):
        """Test cache hit/miss ratio under load."""
        operations = 1000
        hit_count = 0
        miss_count = 0

        # Perform mixed cache operations
        for i in range(operations):
            cache_key = f'test_ratio_{i % 100}'  # Repeat keys to create hits

            if i % 3 == 0:  # Every 3rd operation, ensure miss
                cache.delete(cache_key)

            result = cache.get(cache_key)
            if result is None:
                miss_count += 1
                cache.set(cache_key, f'value_{i}', 300)
            else:
                hit_count += 1

        hit_ratio = (hit_count / (hit_count + miss_count)) * 100

        print(f"Cache hit ratio test: {hit_ratio:.1f}% ({hit_count} hits, {miss_count} misses)")

        # Should have decent hit ratio due to key reuse
        self.assertGreater(hit_ratio, 50, "Cache hit ratio should be > 50% with key reuse")


class CacheBenchmarkTest(TestCase):
    """Benchmark tests for cache performance under various conditions."""

    @override_settings(CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    })
    def test_memory_cache_performance(self):
        """Test cache performance with in-memory backend."""
        self._run_cache_benchmark("Memory Cache")

    @override_settings(CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        }
    })
    def test_dummy_cache_performance(self):
        """Test cache performance with dummy backend (no caching)."""
        self._run_cache_benchmark("Dummy Cache (No Caching)")

    def _run_cache_benchmark(self, backend_name: str):
        """Run standard cache benchmark."""
        print(f"\n=== {backend_name} Benchmark ===")

        # Test data sizes
        test_sizes = [100, 1000, 10000]

        for size in test_sizes:
            # Generate test data
            test_data = {'data': 'x' * size, 'metadata': {'size': size}}

            # Benchmark cache set
            start_time = time.time()
            cache.set(f'benchmark_{size}', test_data, 300)
            set_time = (time.time() - start_time) * 1000

            # Benchmark cache get
            start_time = time.time()
            result = cache.get(f'benchmark_{size}')
            get_time = (time.time() - start_time) * 1000

            print(f"Size {size} bytes: Set {set_time:.2f}ms, Get {get_time:.2f}ms")

            if backend_name != "Dummy Cache (No Caching)":
                self.assertLess(set_time, 50, f"Cache set should be < 50ms for {size} bytes")
                self.assertLess(get_time, 10, f"Cache get should be < 10ms for {size} bytes")

    def test_concurrent_cache_access(self):
        """Test cache performance under concurrent access."""
        import threading

        results = {}
        errors = []

        def worker(thread_id: int, num_operations: int):
            """Worker function for concurrent cache access."""
            thread_results = []
            try:
                for i in range(num_operations):
                    cache_key = f'concurrent_{thread_id}_{i}'
                    # Mix of set and get operations
                    if i % 2 == 0:
                        cache.set(cache_key, f'thread_{thread_id}_data_{i}', 300)
                        thread_results.append('set')
                    else:
                        result = cache.get(cache_key)
                        thread_results.append('get_hit' if result else 'get_miss')
            except Exception as e:
                errors.append(f'Thread {thread_id}: {e}')

            results[thread_id] = thread_results

        # Run concurrent threads
        num_threads = 5
        operations_per_thread = 100

        threads = []
        start_time = time.time()

        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i, operations_per_thread))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        total_time = time.time() - start_time
        total_operations = num_threads * operations_per_thread
        ops_per_second = total_operations / total_time

        print(f"Concurrent cache test: {ops_per_second:.1f} ops/sec "
              f"({total_operations} ops in {total_time:.2f}s)")

        self.assertEqual(len(errors), 0, f"Concurrent cache errors: {errors}")
        self.assertGreater(ops_per_second, 100, "Should handle at least 100 ops/sec concurrently")

    def test_cache_memory_usage(self):
        """Test cache memory usage scaling."""
        # Test with increasing data sizes
        sizes = [1000, 10000, 100000]

        for size in sizes:
            # Clear cache first
            cache.clear()

            # Add data of this size
            num_entries = 100
            for i in range(num_entries):
                cache_key = f'memory_test_{size}_{i}'
                cache.set(cache_key, 'x' * size, 300)

            # Try to get basic stats (may not be available for all backends)
            print(f"Loaded {num_entries} entries of {size} bytes each")


class SystemPerformanceTest(TestCase):
    """Tests for overall system performance with caching enabled."""

    def test_cold_start_performance(self):
        """Test system performance on cold start (empty cache)."""
        # Clear all caches
        cache.clear()

        # Time various operations that would populate cache
        operations = [
            ('user_permissions', lambda: cache_user_permissions(None)),
            ('location_tree', lambda: cache_location_tree()),
            ('role_definitions', lambda: cache_role_definitions()),
        ]

        results = {}

        for name, operation in operations:
            try:
                start_time = time.time()
                result = operation()
                duration = (time.time() - start_time) * 1000
                results[name] = duration
                print(f"{name}: {duration:.2f}ms")
            except Exception as e:
                results[name] = f'error: {e}'
                print(f"{name}: ERROR - {e}")

        # Check that operations complete within reasonable time
        for name, duration in results.items():
            if isinstance(duration, (int, float)):
                if name == 'location_tree':
                    self.assertLess(duration, 2000, f"{name} should complete in < 2s on cold start")
                else:
                    self.assertLess(duration, 1000, f"{name} should complete in < 1s on cold start")

    def test_warm_start_performance(self):
        """Test system performance with warm cache."""
        # Ensure cache is populated
        cache_user_permissions(None)
        cache_location_tree()
        cache_role_definitions()

        # Time the same operations again
        operations = [
            ('user_permissions_cached', lambda: cache_user_permissions(None)),
            ('location_tree_cached', lambda: cache_location_tree()),
            ('role_definitions_cached', lambda: cache_role_definitions()),
        ]

        results = {}

        for name, operation in operations:
            try:
                start_time = time.time()
                result = operation()
                duration = (time.time() - start_time) * 1000
                results[name] = duration
                print(f"{name}: {duration:.2f}ms")
            except Exception as e:
                results[name] = f'error: {e}'
                print(f"{name}: ERROR - {e}")

        # Cached operations should be much faster
        for name, duration in results.items():
            if isinstance(duration, (int, float)):
                self.assertLess(duration, 50, f"Cached {name} should complete in < 50ms")
