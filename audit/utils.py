from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from django.conf import settings
from django.contrib.gis.geos import Point
from django.core.cache import cache
from django.db import models, transaction
from django.db.models import Count, Q
from django.utils import timezone

from .alerting import send_security_alert_notification

logger = logging.getLogger(__name__)


def log_user_action(
    user,
    action: str,
    resource_type: str = "",
    resource_id: str = "",
    resource_name: str = "",
    old_data: Optional[Dict[str, Any]] = None,
    new_data: Optional[Dict[str, Any]] = None,
    ip_address: str = "",
    user_agent: str = "",
    location=None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Log a user action with comprehensive details.

    Args:
        user: User performing the action
        action: Action type (login, logout, create, read, update, delete)
        resource_type: Type of resource being acted upon
        resource_id: ID of the resource
        resource_name: Human-readable name of the resource
        old_data: Data before the change
        new_data: Data after the change
        ip_address: Client IP address
        user_agent: User agent string
        location: Associated location object
        metadata: Additional metadata

    Returns:
        AuditLog instance
    """
    old_data = old_data or {}
    new_data = new_data or {}
    metadata = metadata or {}

    # Calculate changes summary
    changes_summary = _calculate_changes_summary(old_data, new_data)

    # Calculate risk score
    risk_score = calculate_risk_score(user, action, ip_address, location)

    # Detect anomalies
    is_suspicious, anomaly_details = detect_anomalies(user, {
        'action': action,
        'resource_type': resource_type,
        'ip_address': ip_address,
        'user_agent': user_agent,
    })

    # Get geolocation if suspicious
    geo_location = None
    if risk_score > 50 or is_suspicious:
        geo_location = _get_geolocation_from_ip(ip_address)

    audit_data = {
        'action': action,
        'user': user,
        'username': user.get_username() if user else None,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'resource_name': resource_name,
        'old_values': old_data,
        'new_values': new_data,
        'changes_summary': changes_summary,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'location': location,
        'geo_location': geo_location,
        'risk_score': min(risk_score, 100),
        'is_suspicious': is_suspicious,
        'metadata': {**metadata, 'anomaly_details': anomaly_details},
    }

    def _create():
        try:
            audit_log = AuditLog.objects.create(**audit_data)

            # Generate security alerts if needed
            if is_suspicious or risk_score > 70:
                generate_security_alerts(audit_log)

        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            raise

    transaction.on_commit(_create)
    return AuditLog(**audit_data)


def calculate_risk_score(user, action: str, ip_address: str = "", location=None) -> int:
    """
    Calculate a risk score for a user action (0-100).

    Factors considered:
    - Action type (write operations are riskier)
    - User history and patterns
    - IP address reputation
    - Geographic anomalies
    - Time-based patterns
    - Failed login attempts

    Args:
        user: User performing the action
        action: Action type
        ip_address: Client IP address
        location: Associated location

    Returns:
        Risk score (0-100)
    """
    score = 0
    reasons = []

    # Base score by action type
    action_scores = {
        'login': 10,
        'logout': 5,
        'read': 5,
        'create': 20,
        'update': 30,
        'delete': 50,
    }
    score += action_scores.get(action, 25)
    reasons.append(f"Action type: {action}")

    if user and user.is_authenticated:
        # Check user's recent activity patterns
        recent_logs = AuditLog.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(hours=24)
        )

        # Unusual time patterns
        current_hour = timezone.now().hour
        user_activity_hours = list(recent_logs.values_list('created_at__hour', flat=True))

        if user_activity_hours and current_hour not in user_activity_hours:
            score += 15
            reasons.append("Unusual access time")

        # High frequency of actions
        recent_count = recent_logs.count()
        if recent_count > 100:  # More than 100 actions in 24 hours
            score += 20
            reasons.append("High activity frequency")
        elif recent_count > 50:
            score += 10
            reasons.append("Moderate activity frequency")

        # Check for failed login attempts
        failed_logins = recent_logs.filter(
            action='login',
            response_status__in=[400, 401, 403]
        ).count()

        if failed_logins > 5:
            score += 30
            reasons.append("Multiple failed logins")
        elif failed_logins > 2:
            score += 15
            reasons.append("Recent failed logins")

    # IP-based scoring
    if ip_address:
        # Check if IP is from unusual location
        if _is_suspicious_ip(ip_address):
            score += 25
            reasons.append("Suspicious IP address")

        # Check for IP spoofing or proxy usage
        if _is_proxy_ip(ip_address):
            score += 20
            reasons.append("Proxy/VPN usage detected")

    # Geographic anomalies
    if location and user:
        user_locations = set(AuditLog.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).values_list('location', flat=True))

        if location.id not in user_locations and len(user_locations) > 0:
            score += 15
            reasons.append("Geographic anomaly")

    # Time-based patterns (outside normal business hours)
    current_hour = timezone.now().hour
    if current_hour < 6 or current_hour > 22:  # Outside 6 AM - 10 PM
        score += 10
        reasons.append("Outside business hours")

    # Weekend activity (potentially higher risk)
    current_day = timezone.now().weekday()
    if current_day >= 5:  # Saturday = 5, Sunday = 6
        score += 5
        reasons.append("Weekend activity")

    # Store reasons in cache for potential use
    cache_key = f"risk_score_reasons_{user.id if user else 'anon'}_{timezone.now().strftime('%Y%m%d%H')}"
    cache.set(cache_key, reasons, 3600)  # Cache for 1 hour

    return min(score, 100)


def detect_anomalies(user, current_request: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Detect anomalous behavior patterns.

    Args:
        user: User to check
        current_request: Current request information

    Returns:
        Tuple of (is_suspicious, anomaly_details)
    """
    anomalies = {}
    is_suspicious = False

    if not user or not user.is_authenticated:
        return False, {}

    # Check for brute force patterns
    recent_failed_logins = AuditLog.objects.filter(
        user=user,
        action='login',
        response_status__in=[400, 401, 403],
        created_at__gte=timezone.now() - timedelta(minutes=30)
    ).count()

    if recent_failed_logins >= 5:
        anomalies['brute_force'] = f"{recent_failed_logins} failed logins in 30 minutes"
        is_suspicious = True

    # Check for unusual access patterns
    recent_logs = AuditLog.objects.filter(
        user=user,
        created_at__gte=timezone.now() - timedelta(hours=1)
    )

    # Rapid succession of different actions
    if recent_logs.count() > 20:
        anomalies['high_frequency'] = f"{recent_logs.count()} actions in 1 hour"
        is_suspicious = True

    # Check for geographic anomalies
    current_ip = current_request.get('ip_address')
    if current_ip:
        recent_ips = set(recent_logs.values_list('ip_address', flat=True))
        if current_ip not in recent_ips and len(recent_ips) > 2:
            anomalies['ip_anomaly'] = f"New IP: {current_ip} not in recent IPs"
            is_suspicious = True

    # Check for user agent anomalies
    current_ua = current_request.get('user_agent', '')
    recent_uas = set(recent_logs.values_list('user_agent', flat=True))
    if current_ua and current_ua not in recent_uas and len(recent_uas) > 1:
        anomalies['ua_anomaly'] = "Unusual user agent"
        is_suspicious = True

    # Check for unusual resource access patterns
    action = current_request.get('action')
    resource_type = current_request.get('resource_type')

    if action in ['delete', 'update'] and resource_type:
        # Check if user has been accessing this resource type unusually frequently
        resource_access_count = recent_logs.filter(
            action__in=['delete', 'update'],
            resource_type=resource_type
        ).count()

        if resource_access_count > 10:
            anomalies['resource_abuse'] = f"Excessive {action} operations on {resource_type}"
            is_suspicious = True

    return is_suspicious, anomalies


def generate_security_alerts(audit_log: AuditLog) -> None:
    """
    Generate security alerts based on audit log analysis.

    Args:
        audit_log: The audit log that triggered the alert
    """
    alerts_to_create = []

    # Brute force detection
    if audit_log.action == 'login' and audit_log.response_status in [400, 401, 403]:
        recent_failures = AuditLog.objects.filter(
            user=audit_log.user,
            action='login',
            response_status__in=[400, 401, 403],
            created_at__gte=timezone.now() - timedelta(minutes=15)
        ).count()

        if recent_failures >= 3:
            alerts_to_create.append({
                'alert_type': SecurityAlert.AlertTypes.BRUTE_FORCE,
                'severity': SecurityAlert.Severity.HIGH if recent_failures >= 5 else SecurityAlert.Severity.MEDIUM,
                'title': f"Brute Force Attack Detected - {recent_failures} failed login attempts",
                'description': f"User {audit_log.username} has {recent_failures} failed login attempts in the last 15 minutes",
                'details': {
                    'failed_attempts': recent_failures,
                    'ip_address': audit_log.ip_address,
                    'user_agent': audit_log.user_agent,
                }
            })

    # Geographic anomalies
    if audit_log.risk_score > 60 and audit_log.location:
        user_recent_locations = AuditLog.objects.filter(
            user=audit_log.user,
            created_at__gte=timezone.now() - timedelta(days=7)
        ).values_list('location', flat=True).distinct()

        if audit_log.location.id not in user_recent_locations:
            alerts_to_create.append({
                'alert_type': SecurityAlert.AlertTypes.GEOGRAPHIC_ANOMALY,
                'severity': SecurityAlert.Severity.MEDIUM,
                'title': f"Geographic Anomaly - Access from unusual location",
                'description': f"User {audit_log.username} accessed from location not used in the last 7 days",
                'details': {
                    'current_location': audit_log.location.name if audit_log.location else None,
                    'ip_address': audit_log.ip_address,
                }
            })

    # Suspicious high-risk actions
    if audit_log.risk_score > 80:
        alerts_to_create.append({
            'alert_type': SecurityAlert.AlertTypes.UNUSUAL_ACCESS_PATTERN,
            'severity': SecurityAlert.Severity.HIGH if audit_log.risk_score > 90 else SecurityAlert.Severity.MEDIUM,
            'title': f"High Risk Activity Detected - Risk Score: {audit_log.risk_score}",
            'description': f"Suspicious activity with risk score of {audit_log.risk_score}",
            'details': {
                'action': audit_log.action,
                'resource_type': audit_log.resource_type,
                'risk_score': audit_log.risk_score,
                'ip_address': audit_log.ip_address,
            }
        })

    # Unauthorized access attempts
    if audit_log.response_status in [403, 404] and audit_log.action in ['read', 'update', 'delete']:
        recent_unauthorized = AuditLog.objects.filter(
            user=audit_log.user,
            response_status__in=[403, 404],
            created_at__gte=timezone.now() - timedelta(hours=1)
        ).count()

        if recent_unauthorized >= 3:
            alerts_to_create.append({
                'alert_type': SecurityAlert.AlertTypes.UNAUTHORIZED_ACCESS,
                'severity': SecurityAlert.Severity.MEDIUM,
                'title': f"Unauthorized Access Pattern - {recent_unauthorized} denied requests",
                'description': f"User {audit_log.username} has {recent_unauthorized} unauthorized access attempts in the last hour",
                'details': {
                    'unauthorized_attempts': recent_unauthorized,
                    'ip_address': audit_log.ip_address,
                }
            })

    # Create alerts asynchronously
    for alert_data in alerts_to_create:
        def _create_alert(data):
            try:
                alert, created = SecurityAlert.objects.get_or_create(
                    user=audit_log.user,
                    audit_log=audit_log,
                    alert_type=data['alert_type'],
                    title=data['title'],
                    defaults={
                        'severity': data['severity'],
                        'description': data['description'],
                        'details': data['details'],
                        'ip_address': audit_log.ip_address,
                        'geo_location': audit_log.geo_location,
                    }
                )

                # Send notifications for newly created alerts
                if created:
                    send_security_alert_notification(alert)

            except Exception as e:
                logger.error(f"Failed to create security alert: {e}")

        transaction.on_commit(lambda data=alert_data: _create_alert(data))


def _calculate_changes_summary(old_data: Dict[str, Any], new_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate a summary of changes between old and new data."""
    changes = {}
    added = {}
    removed = {}
    modified = {}

    old_keys = set(old_data.keys())
    new_keys = set(new_data.keys())

    # Added fields
    for key in new_keys - old_keys:
        added[key] = new_data[key]

    # Removed fields
    for key in old_keys - new_keys:
        removed[key] = old_data[key]

    # Modified fields
    for key in old_keys & new_keys:
        if old_data[key] != new_data[key]:
            modified[key] = {
                'old': old_data[key],
                'new': new_data[key]
            }

    if added:
        changes['added'] = added
    if removed:
        changes['removed'] = removed
    if modified:
        changes['modified'] = modified

    return changes


def _is_suspicious_ip(ip_address: str) -> bool:
    """Check if an IP address is known to be suspicious."""
    # This would integrate with threat intelligence services
    # For now, implement basic checks
    suspicious_ranges = [
        '10.0.0.0/8',  # Private networks
        '172.16.0.0/12',  # Private networks
        '192.168.0.0/16',  # Private networks
    ]

    # Basic implementation - in production, use a proper IP range checking library
    return any(ip_address.startswith(range.split('/')[0].rsplit('.', 1)[0]) for range in suspicious_ranges)


def _is_proxy_ip(ip_address: str) -> bool:
    """Check if IP is likely a proxy or VPN."""
    # This would integrate with proxy detection services
    # For now, return False - implement when proxy detection service is available
    return False


def _get_geolocation_from_ip(ip_address: str) -> Optional[Point]:
    """Get geolocation coordinates from IP address."""
    # This would integrate with a geolocation service like MaxMind GeoIP
    # For now, return None - implement when geolocation service is available
    return None


def record_permission_audit(
    *,
    action: str,
    actor=None,
    subject=None,
    role=None,
    location=None,
    payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    message: str = "",
) -> PermissionAuditLog:
    payload = payload or {}
    metadata = metadata or {}

    def _create():
        PermissionAuditLog.objects.create(
            action=action,
            actor=actor,
            subject=subject,
            role=role,
            location=location,
            payload=payload,
            metadata=metadata,
            message=message,
        )

    transaction.on_commit(_create)
    return PermissionAuditLog(
        action=action,
        actor=actor,
        subject=subject,
        role=role,
        location=location,
        payload=payload,
        metadata=metadata,
        message=message,
    )
