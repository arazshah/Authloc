"""
Audit monitoring features for security and compliance.

This module provides specialized monitoring functions for:
- Failed login tracking
- Unusual access patterns detection
- Geographic anomaly monitoring
- Permission escalation detection
- Data export monitoring
"""

import logging
from datetime import timedelta
from typing import Dict, List, Optional, Set, Tuple

from django.core.cache import cache
from django.db.models import Count, Q
from django.utils import timezone

from .models import AuditLog, SecurityAlert
from .utils import generate_security_alerts

logger = logging.getLogger(__name__)


class AuditMonitor:
    """Main class for audit monitoring functionality."""

    def __init__(self):
        self.cache_timeout = 3600  # 1 hour cache

    def check_failed_logins(self, user=None, ip_address: str = None) -> Dict[str, any]:
        """
        Monitor failed login attempts.

        Args:
            user: Specific user to check (optional)
            ip_address: Specific IP to check (optional)

        Returns:
            Dict with failed login statistics and alerts
        """
        now = timezone.now()
        timeframes = {
            '15_minutes': now - timedelta(minutes=15),
            '1_hour': now - timedelta(hours=1),
            '24_hours': now - timedelta(hours=24),
        }

        results = {}

        for timeframe_name, start_time in timeframes.items():
            query = AuditLog.objects.filter(
                action='login',
                response_status__in=[400, 401, 403],
                created_at__gte=start_time
            )

            if user:
                query = query.filter(user=user)
            if ip_address:
                query = query.filter(ip_address=ip_address)

            failed_count = query.count()
            results[timeframe_name] = {
                'count': failed_count,
                'threshold_breached': self._check_failed_login_threshold(failed_count, timeframe_name),
                'recent_attempts': list(query.order_by('-created_at')[:10].values(
                    'username', 'ip_address', 'user_agent', 'created_at'
                ))
            }

        # Generate alerts for critical thresholds
        self._generate_failed_login_alerts(results, user, ip_address)

        return results

    def detect_unusual_access_patterns(self, user=None, hours: int = 24) -> Dict[str, any]:
        """
        Detect unusual access patterns for a user or system-wide.

        Args:
            user: Specific user to analyze (optional)
            hours: Hours to look back

        Returns:
            Dict with pattern analysis results
        """
        start_time = timezone.now() - timedelta(hours=hours)

        if user:
            logs = AuditLog.objects.filter(user=user, created_at__gte=start_time)
        else:
            logs = AuditLog.objects.filter(created_at__gte=start_time)

        patterns = {
            'total_actions': logs.count(),
            'actions_by_type': dict(logs.values('action').annotate(count=Count('action')).values_list('action', 'count')),
            'actions_by_hour': self._analyze_hourly_patterns(logs),
            'ip_addresses': dict(logs.values('ip_address').annotate(count=Count('ip_address')).values_list('ip_address', 'count')),
            'user_agents': dict(logs.values('user_agent').annotate(count=Count('user_agent')).values_list('user_agent', 'count')),
            'locations': dict(logs.values('location__name').annotate(count=Count('location')).values_list('location__name', 'count')),
        }

        # Detect anomalies
        anomalies = self._detect_pattern_anomalies(patterns, user)

        return {
            'patterns': patterns,
            'anomalies': anomalies,
            'risk_score': self._calculate_pattern_risk_score(patterns, anomalies),
        }

    def monitor_geographic_anomalies(self, user=None, days: int = 7) -> List[Dict[str, any]]:
        """
        Monitor for geographic access anomalies.

        Args:
            user: Specific user to check (optional)
            days: Days to look back

        Returns:
            List of geographic anomalies detected
        """
        start_time = timezone.now() - timedelta(days=days)

        query = AuditLog.objects.filter(created_at__gte=start_time)

        if user:
            query = query.filter(user=user)

        # Group by user and location
        user_locations = {}
        for log in query.select_related('user', 'location'):
            if log.user and log.location:
                user_id = log.user.id
                location_id = log.location.id

                if user_id not in user_locations:
                    user_locations[user_id] = {
                        'username': log.username,
                        'locations': set(),
                        'first_seen': {},
                        'last_seen': {},
                    }

                user_locations[user_id]['locations'].add(location_id)

                if location_id not in user_locations[user_id]['first_seen']:
                    user_locations[user_id]['first_seen'][location_id] = log.created_at
                user_locations[user_id]['last_seen'][location_id] = log.created_at

        # Detect anomalies
        anomalies = []
        for user_id, data in user_locations.items():
            if len(data['locations']) > 1:  # User has accessed from multiple locations
                # Check for rapid location changes
                location_changes = self._detect_rapid_location_changes(data)
                if location_changes:
                    anomalies.extend(location_changes)

        return anomalies

    def detect_permission_escalation(self, user=None, hours: int = 24) -> List[Dict[str, any]]:
        """
        Detect potential permission escalation attempts.

        Args:
            user: Specific user to check (optional)
            hours: Hours to look back

        Returns:
            List of potential escalation attempts
        """
        start_time = timezone.now() - timedelta(hours=hours)

        # Look for patterns that might indicate permission escalation
        escalation_patterns = []

        # Check for rapid permission changes
        permission_logs = AuditLog.objects.filter(
            resource_type__in=['permission', 'role', 'group'],
            action__in=['create', 'update', 'delete'],
            created_at__gte=start_time
        )

        if user:
            permission_logs = permission_logs.filter(user=user)

        # Group by user and time windows
        user_permission_activity = {}
        for log in permission_logs:
            user_id = log.user.id if log.user else 'anonymous'
            hour_window = log.created_at.replace(minute=0, second=0, microsecond=0)

            if user_id not in user_permission_activity:
                user_permission_activity[user_id] = {}

            if hour_window not in user_permission_activity[user_id]:
                user_permission_activity[user_id][hour_window] = []

            user_permission_activity[user_id][hour_window].append(log)

        # Detect suspicious patterns
        for user_id, hourly_activity in user_permission_activity.items():
            for hour, logs in hourly_activity.items():
                if len(logs) > 5:  # More than 5 permission changes in an hour
                    escalation_patterns.append({
                        'user_id': user_id,
                        'username': logs[0].username if logs else 'unknown',
                        'time_window': hour,
                        'changes_count': len(logs),
                        'changes': [{
                            'action': log.action,
                            'resource_type': log.resource_type,
                            'resource_name': log.resource_name,
                            'timestamp': log.created_at,
                        } for log in logs],
                        'severity': 'high' if len(logs) > 10 else 'medium',
                    })

        return escalation_patterns

    def monitor_data_exports(self, user=None, hours: int = 24) -> Dict[str, any]:
        """
        Monitor data export activities.

        Args:
            user: Specific user to check (optional)
            hours: Hours to look back

        Returns:
            Dict with export monitoring results
        """
        start_time = timezone.now() - timedelta(hours=hours)

        # Look for export-related actions
        export_actions = ['read', 'create']  # Assuming exports involve reading or creating export files
        export_logs = AuditLog.objects.filter(
            action__in=export_actions,
            resource_type__in=['export', 'report', 'file', 'download'],
            created_at__gte=start_time
        )

        if user:
            export_logs = export_logs.filter(user=user)

        export_stats = {
            'total_exports': export_logs.count(),
            'exports_by_user': dict(export_logs.values('username').annotate(count=Count('username')).values_list('username', 'count')),
            'exports_by_type': dict(export_logs.values('resource_type').annotate(count=Count('resource_type')).values_list('resource_type', 'count')),
            'large_exports': [],  # Would need to check file sizes or record counts
        }

        # Check for suspicious export patterns
        suspicious_exports = self._detect_suspicious_exports(export_logs)

        return {
            'statistics': export_stats,
            'suspicious_activity': suspicious_exports,
        }

    def _check_failed_login_threshold(self, count: int, timeframe: str) -> bool:
        """Check if failed login count exceeds thresholds."""
        thresholds = {
            '15_minutes': 5,
            '1_hour': 10,
            '24_hours': 50,
        }
        return count >= thresholds.get(timeframe, 0)

    def _generate_failed_login_alerts(self, results: Dict, user=None, ip_address: str = None):
        """Generate security alerts for failed login thresholds."""
        for timeframe, data in results.items():
            if data['threshold_breached']:
                alert_type = SecurityAlert.AlertTypes.BRUTE_FORCE
                severity = SecurityAlert.Severity.HIGH if data['count'] > 10 else SecurityAlert.Severity.MEDIUM

                title = f"Multiple Failed Login Attempts - {timeframe.replace('_', ' ').title()}"
                description = f"Detected {data['count']} failed login attempts in the last {timeframe.replace('_', ' ')}"

                if user:
                    description += f" for user {user.username}"
                if ip_address:
                    description += f" from IP {ip_address}"

                # Create alert (this would be enhanced to avoid duplicates)
                SecurityAlert.objects.get_or_create(
                    alert_type=alert_type,
                    user=user,
                    ip_address=ip_address,
                    title=title,
                    defaults={
                        'severity': severity,
                        'description': description,
                        'details': {
                            'failed_attempts': data['count'],
                            'timeframe': timeframe,
                            'ip_address': ip_address,
                        }
                    }
                )

    def _analyze_hourly_patterns(self, logs) -> Dict[int, int]:
        """Analyze action patterns by hour of day."""
        hourly_counts = {}
        for log in logs:
            hour = log.created_at.hour
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        return hourly_counts

    def _detect_pattern_anomalies(self, patterns: Dict, user=None) -> List[Dict]:
        """Detect anomalies in access patterns."""
        anomalies = []

        # Check for unusual hourly patterns
        hourly_actions = patterns.get('actions_by_hour', {})
        if hourly_actions:
            total_actions = sum(hourly_actions.values())
            avg_actions_per_hour = total_actions / 24

            for hour, count in hourly_actions.items():
                if count > avg_actions_per_hour * 3:  # 3x average
                    anomalies.append({
                        'type': 'hourly_spike',
                        'description': f"Unusual activity spike at hour {hour}: {count} actions",
                        'severity': 'medium',
                    })

        # Check for unusual IP diversity
        ip_counts = patterns.get('ip_addresses', {})
        if len(ip_counts) > 5:  # Using more than 5 different IPs
            anomalies.append({
                'type': 'ip_diversity',
                'description': f"Access from {len(ip_counts)} different IP addresses",
                'severity': 'high',
            })

        return anomalies

    def _calculate_pattern_risk_score(self, patterns: Dict, anomalies: List[Dict]) -> int:
        """Calculate overall risk score for patterns."""
        score = 0

        # Base score from anomalies
        for anomaly in anomalies:
            if anomaly['severity'] == 'high':
                score += 30
            elif anomaly['severity'] == 'medium':
                score += 15

        # Score from total actions
        total_actions = patterns.get('total_actions', 0)
        if total_actions > 1000:
            score += 40
        elif total_actions > 500:
            score += 20
        elif total_actions > 100:
            score += 10

        return min(score, 100)

    def _detect_rapid_location_changes(self, user_location_data: Dict) -> List[Dict]:
        """Detect rapid changes between locations."""
        anomalies = []
        locations = user_location_data['locations']
        first_seen = user_location_data['first_seen']
        last_seen = user_location_data['last_seen']

        # Simple check: if user has accessed from multiple locations within short time
        if len(locations) > 1:
            # Check time spans
            earliest = min(first_seen.values())
            latest = max(last_seen.values())
            time_span = latest - earliest

            # If multiple locations accessed within 1 hour
            if time_span.total_seconds() < 3600 and len(locations) > 1:
                anomalies.append({
                    'type': 'rapid_location_change',
                    'username': user_location_data['username'],
                    'locations_count': len(locations),
                    'time_span_minutes': time_span.total_seconds() / 60,
                    'severity': 'high',
                })

        return anomalies

    def _detect_suspicious_exports(self, export_logs) -> List[Dict]:
        """Detect suspicious data export patterns."""
        suspicious = []

        # Group exports by user
        user_exports = {}
        for log in export_logs:
            username = log.username or 'anonymous'
            if username not in user_exports:
                user_exports[username] = []
            user_exports[username].append(log)

        # Check for bulk exports or unusual patterns
        for username, logs in user_exports.items():
            if len(logs) > 20:  # More than 20 exports
                suspicious.append({
                    'username': username,
                    'export_count': len(logs),
                    'severity': 'medium',
                    'description': f"High volume of exports: {len(logs)} in monitoring period",
                })

            # Check for exports of sensitive data types
            sensitive_types = ['user', 'permission', 'audit', 'security']
            sensitive_exports = [log for log in logs if log.resource_type in sensitive_types]

            if len(sensitive_exports) > 5:
                suspicious.append({
                    'username': username,
                    'sensitive_export_count': len(sensitive_exports),
                    'severity': 'high',
                    'description': f"Multiple exports of sensitive data: {len(sensitive_exports)}",
                })

        return suspicious


# Global monitor instance
audit_monitor = AuditMonitor()
