import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

from django.conf import settings
from django.contrib.gis.geos import Point
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from .models import AuditLog
from .utils import calculate_risk_score, detect_anomalies

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """
    Middleware for automatic API request auditing and security monitoring.

    Logs all API requests with comprehensive information including:
    - User information
    - Request details (method, path, body)
    - Response details (status, processing time)
    - IP address and geolocation
    - Risk scoring and anomaly detection
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # URLs to exclude from auditing (static files, media, etc.)
        self.exclude_urls = getattr(settings, 'AUDIT_EXCLUDE_URLS', [
            '/static/',
            '/media/',
            '/favicon.ico',
            '/admin/jsi18n/',
            '/admin/css/',
            '/admin/img/',
        ])
        # API prefixes to include in auditing
        self.api_prefixes = getattr(settings, 'AUDIT_API_PREFIXES', [
            '/api/',
        ])

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Check if this request should be audited
        if not self._should_audit_request(request):
            return self.get_response(request)

        # Record start time
        start_time = time.time()

        # Extract request information before processing
        request_info = self._extract_request_info(request)

        # Process the request
        response = self.get_response(request)

        # Record end time
        end_time = time.time()
        processing_time = (end_time - start_time) * 1000  # Convert to milliseconds

        # Extract response information
        response_info = self._extract_response_info(response)

        # Create audit log entry
        self._create_audit_log(request_info, response_info, processing_time)

        return response

    def _should_audit_request(self, request: HttpRequest) -> bool:
        """Determine if the request should be audited."""
        path = request.path

        # Exclude certain URLs
        for exclude_url in self.exclude_urls:
            if path.startswith(exclude_url):
                return False

        # Include only API requests or specific patterns
        for api_prefix in self.api_prefixes:
            if path.startswith(api_prefix):
                return True

        # For non-API requests, only audit authenticated users or suspicious patterns
        return (
            hasattr(request, 'user') and
            request.user.is_authenticated and
            self._is_suspicious_request(request)
        )

    def _is_suspicious_request(self, request: HttpRequest) -> bool:
        """Check if request shows suspicious patterns."""
        # This is a basic check - more sophisticated logic would be in utils
        suspicious_indicators = [
            request.META.get('HTTP_X_FORWARDED_FOR'),  # Proxy usage
            len(request.META.get('HTTP_USER_AGENT', '')) > 500,  # Very long UA
            request.method in ['PUT', 'PATCH', 'DELETE'],  # Write operations
        ]
        return any(suspicious_indicators)

    def _extract_request_info(self, request: HttpRequest) -> Dict[str, Any]:
        """Extract relevant information from the request."""
        # Get user information
        user = getattr(request, 'user', None)
        user_id = user.id if user and user.is_authenticated else None
        username = user.get_username() if user and user.is_authenticated else None

        # Get IP address (handle proxies)
        ip_address = self._get_client_ip(request)

        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Extract request body (safely)
        request_body = self._extract_request_body(request)

        # Get location information (if available)
        location = None
        if hasattr(request, 'location'):
            location = request.location

        return {
            'user': user,
            'user_id': user_id,
            'username': username,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'method': request.method,
            'path': request.path,
            'query_string': request.GET.urlencode(),
            'body': request_body,
            'location': location,
        }

    def _extract_response_info(self, response: HttpResponse) -> Dict[str, Any]:
        """Extract relevant information from the response."""
        return {
            'status_code': response.status_code,
            'content_type': response.get('Content-Type', ''),
            'content_length': len(response.content) if hasattr(response, 'content') else 0,
        }

    def _get_client_ip(self, request: HttpRequest) -> Optional[str]:
        """Get the client's real IP address, handling proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP if there are multiple
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _extract_request_body(self, request: HttpRequest) -> Dict[str, Any]:
        """Safely extract request body, limiting size and handling JSON."""
        try:
            if request.method in ['POST', 'PUT', 'PATCH']:
                # Limit body size to prevent memory issues
                max_body_size = getattr(settings, 'AUDIT_MAX_BODY_SIZE', 1024 * 10)  # 10KB default

                if hasattr(request, 'body') and len(request.body) <= max_body_size:
                    content_type = request.META.get('CONTENT_TYPE', '')

                    if 'application/json' in content_type:
                        try:
                            return json.loads(request.body.decode('utf-8'))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            return {'raw_body': request.body.decode('utf-8', errors='replace')[:500]}
                    elif 'application/x-www-form-urlencoded' in content_type:
                        return dict(request.POST)
                    else:
                        # For other content types, store a truncated version
                        return {'raw_body': request.body.decode('utf-8', errors='replace')[:500]}
        except Exception as e:
            logger.warning(f"Failed to extract request body: {e}")

        return {}

    def _create_audit_log(self, request_info: Dict[str, Any], response_info: Dict[str, Any], processing_time: float):
        """Create an audit log entry asynchronously."""
        try:
            # Determine action type based on HTTP method and path
            action = self._determine_action(request_info, response_info)

            # Calculate risk score
            risk_score = calculate_risk_score(
                user=request_info['user'],
                action=action,
                ip_address=request_info['ip_address'],
                location=request_info.get('location')
            )

            # Detect anomalies
            is_suspicious, anomaly_details = detect_anomalies(
                user=request_info['user'],
                current_request=request_info
            )

            # Get geolocation if needed
            geo_location = None
            if risk_score > 50 or is_suspicious:
                geo_location = self._get_geolocation(request_info['ip_address'])

            # Prepare audit log data
            audit_data = {
                'action': action,
                'user': request_info['user'],
                'username': request_info['username'],
                'ip_address': request_info['ip_address'],
                'user_agent': request_info['user_agent'],
                'request_method': request_info['method'],
                'request_path': f"{request_info['path']}?{request_info['query_string']}" if request_info['query_string'] else request_info['path'],
                'request_body': request_info['body'],
                'response_status': response_info['status_code'],
                'processing_time': processing_time,
                'location': request_info['location'],
                'geo_location': geo_location,
                'risk_score': min(risk_score, 100),  # Cap at 100
                'is_suspicious': is_suspicious,
                'metadata': {
                    'anomaly_details': anomaly_details,
                    'content_type': response_info.get('content_type'),
                    'content_length': response_info.get('content_length'),
                    'user_agent_length': len(request_info['user_agent']),
                }
            }

            # Create audit log asynchronously
            self._create_audit_log_async(audit_data)

        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")

    def _determine_action(self, request_info: Dict[str, Any], response_info: Dict[str, Any]) -> str:
        """Determine the action type based on request and response."""
        method = request_info['method']
        path = request_info['path']

        # Map HTTP methods to actions
        method_actions = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete',
        }

        # Special cases for authentication
        if '/login' in path or '/auth/login' in path:
            return 'login'
        elif '/logout' in path or '/auth/logout' in path:
            return 'logout'

        return method_actions.get(method, 'unknown')

    def _get_geolocation(self, ip_address: str) -> Optional[Point]:
        """Get geolocation for an IP address."""
        # This would integrate with a geolocation service
        # For now, return None - implement when geolocation service is available
        return None

    def _create_audit_log_async(self, audit_data: Dict[str, Any]):
        """Create audit log entry asynchronously to avoid blocking response."""
        def _create():
            try:
                AuditLog.objects.create(**audit_data)
            except Exception as e:
                logger.error(f"Failed to create audit log asynchronously: {e}")

        # Use transaction.on_commit to ensure it runs after the request completes
        transaction.on_commit(_create)
