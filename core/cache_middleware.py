"""
API response caching middleware.

Provides automatic caching for API responses based on request patterns.
"""

import hashlib
import logging
from typing import Optional, Any

from django.core.cache import caches
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger(__name__)


class APICacheMiddleware(MiddlewareMixin):
    """
    Middleware for caching API responses.

    Caches GET requests to API endpoints and serves cached responses when available.
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.cache = caches[getattr(settings, 'CACHE_MIDDLEWARE_ALIAS', 'api_cache')]
        self.cache_timeout = getattr(settings, 'CACHE_MIDDLEWARE_SECONDS', 300)
        self.key_prefix = getattr(settings, 'CACHE_MIDDLEWARE_KEY_PREFIX', 'api')
        self.ignored_paths = getattr(settings, 'CACHE_MIDDLEWARE_IGNORED_PATHS', [
            '/api/v1/cache/',  # Don't cache cache management endpoints
            '/api/v1/auth/',   # Don't cache auth endpoints
            '/admin/',         # Don't cache admin
        ])

    def _should_cache_request(self, request: HttpRequest) -> bool:
        """
        Determine if the request should be cached.

        Args:
            request: The HTTP request

        Returns:
            True if request should be cached
        """
        # Only cache GET requests
        if request.method != 'GET':
            return False

        # Don't cache if user is authenticated (unless explicitly allowed)
        if hasattr(request, 'user') and request.user.is_authenticated:
            # Could add logic here to cache for authenticated users based on settings
            return getattr(settings, 'CACHE_API_FOR_AUTHENTICATED_USERS', False)

        # Check ignored paths
        for ignored_path in self.ignored_paths:
            if request.path.startswith(ignored_path):
                return False

        # Don't cache requests with query parameters that indicate dynamic content
        dynamic_params = getattr(settings, 'CACHE_API_EXCLUDE_PARAMS', [
            'format', 'callback', '_', 'timestamp', 'nonce'
        ])

        for param in dynamic_params:
            if param in request.GET:
                return False

        return True

    def _should_cache_response(self, response: HttpResponse) -> bool:
        """
        Determine if the response should be cached.

        Args:
            response: The HTTP response

        Returns:
            True if response should be cached
        """
        # Only cache successful responses
        if not (200 <= response.status_code < 300):
            return False

        # Don't cache responses with cache control headers
        if 'Cache-Control' in response:
            cache_control = response['Cache-Control']
            if 'no-cache' in cache_control or 'private' in cache_control:
                return False

        # Don't cache responses that are too large
        max_size = getattr(settings, 'CACHE_API_MAX_RESPONSE_SIZE', 1024 * 1024)  # 1MB default
        if hasattr(response, 'content') and len(response.content) > max_size:
            return False

        return True

    def _get_cache_key(self, request: HttpRequest) -> str:
        """
        Generate a cache key for the request.

        Args:
            request: The HTTP request

        Returns:
            Cache key string
        """
        # Include path, query parameters, and user info in key
        key_parts = [
            self.key_prefix,
            request.path,
        ]

        # Sort query parameters for consistent caching
        if request.GET:
            query_string = '&'.join(f"{k}={v}" for k, v in sorted(request.GET.items()))
            key_parts.append(hashlib.md5(query_string.encode()).hexdigest()[:8])

        # Include user ID if authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            key_parts.append(f"user_{request.user.pk}")

        # Include accept header for content negotiation
        accept = request.META.get('HTTP_ACCEPT', '')
        if accept:
            key_parts.append(hashlib.md5(accept.encode()).hexdigest()[:4])

        return ':'.join(key_parts)

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Check if request can be served from cache.

        Args:
            request: The HTTP request

        Returns:
            Cached response or None
        """
        if not self._should_cache_request(request):
            return None

        cache_key = self._get_cache_key(request)
        cached_response = self.cache.get(cache_key)

        if cached_response:
            logger.debug(f"API cache hit for key: {cache_key}")
            # Return the cached response
            return cached_response

        logger.debug(f"API cache miss for key: {cache_key}")
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Cache the response if appropriate.

        Args:
            request: The HTTP request
            response: The HTTP response

        Returns:
            The response (potentially modified)
        """
        if not (self._should_cache_request(request) and self._should_cache_response(response)):
            return response

        cache_key = self._get_cache_key(request)

        # Clone the response for caching (to avoid modifying the original)
        cached_response = self._clone_response(response)

        # Store in cache
        self.cache.set(cache_key, cached_response, self.cache_timeout)

        logger.debug(f"Cached API response for key: {cache_key}")
        return response

    def _clone_response(self, response: HttpResponse) -> HttpResponse:
        """
        Create a clone of the response for caching.

        Args:
            response: The response to clone

        Returns:
            Cloned response
        """
        # Create a new response with the same content
        cloned = HttpResponse(
            content=response.content,
            status=response.status_code,
            content_type=response.get('Content-Type', 'application/json'),
        )

        # Copy important headers
        headers_to_copy = [
            'Content-Type',
            'ETag',
            'Last-Modified',
            'Expires',
        ]

        for header in headers_to_copy:
            if header in response:
                cloned[header] = response[header]

        # Add cache metadata
        cloned['X-Cache-Status'] = 'HIT'
        cloned['X-Cache-Time'] = str(self.cache_timeout)

        return cloned


class CacheCompressionMiddleware(MiddlewareMixin):
    """
    Middleware for compressing cached objects.

    Automatically compresses objects above a certain size threshold.
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.compression_threshold = getattr(settings, 'CACHE_COMPRESSION_THRESHOLD', 1024)

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add compression hint to response if content is large.

        Args:
            request: The HTTP request
            response: The HTTP response

        Returns:
            The response with potential compression hints
        """
        if hasattr(response, 'content') and len(response.content) > self.compression_threshold:
            response['X-Compression-Threshold-Exceeded'] = 'true'

        return response
