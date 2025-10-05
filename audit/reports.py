"""
Audit report generation system.

Provides comprehensive reporting capabilities for audit logs and security events.
"""

import csv
import io
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from django.db.models import Count, Q
from django.utils import timezone

from .models import AuditLog, SecurityAlert


class AuditReportGenerator:
    """Generator for various audit and security reports."""

    def __init__(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None):
        self.start_date = start_date or (timezone.now() - timedelta(days=30))
        self.end_date = end_date or timezone.now()

    def generate_security_summary_report(self) -> Dict:
        """
        Generate a comprehensive security summary report.

        Includes statistics on audit logs, security alerts, risk patterns, etc.
        """
        # Get audit logs in date range
        audit_logs = AuditLog.objects.filter(
            created_at__gte=self.start_date,
            created_at__lte=self.end_date
        )

        # Get security alerts in date range
        security_alerts = SecurityAlert.objects.filter(
            created_at__gte=self.start_date,
            created_at__lte=self.end_date
        )

        # Calculate basic statistics
        total_logs = audit_logs.count()
        total_alerts = security_alerts.count()

        # Actions breakdown
        actions_breakdown = dict(
            audit_logs.values('action')
            .annotate(count=Count('action'))
            .values_list('action', 'count')
        )

        # Alerts by severity
        alerts_by_severity = dict(
            security_alerts.values('severity')
            .annotate(count=Count('severity'))
            .values_list('severity', 'count')
        )

        # Alerts by type
        alerts_by_type = dict(
            security_alerts.values('alert_type')
            .annotate(count=Count('alert_type'))
            .values_list('alert_type', 'count')
        )

        # Risk score distribution
        risk_distribution = self._calculate_risk_distribution(audit_logs)

        # Top risky users
        top_risky_users = self._get_top_risky_users(audit_logs)

        # Failed login statistics
        failed_login_stats = self._calculate_failed_login_stats(audit_logs)

        # Geographic anomalies
        geographic_anomalies = self._detect_geographic_anomalies(audit_logs)

        return {
            'report_type': 'security_summary',
            'date_range': {
                'start': self.start_date.isoformat(),
                'end': self.end_date.isoformat(),
            },
            'summary': {
                'total_audit_logs': total_logs,
                'total_security_alerts': total_alerts,
                'suspicious_activities': audit_logs.filter(is_suspicious=True).count(),
                'high_risk_activities': audit_logs.filter(risk_score__gte=70).count(),
                'failed_logins': failed_login_stats['total_failed'],
                'unique_users': audit_logs.values('user').distinct().count(),
                'unique_ips': audit_logs.values('ip_address').distinct().count(),
            },
            'actions_breakdown': actions_breakdown,
            'alerts_by_severity': alerts_by_severity,
            'alerts_by_type': alerts_by_type,
            'risk_distribution': risk_distribution,
            'top_risky_users': top_risky_users,
            'failed_login_stats': failed_login_stats,
            'geographic_anomalies': geographic_anomalies,
            'generated_at': timezone.now().isoformat(),
        }

    def generate_user_activity_report(self, user_id: Optional[str] = None) -> Dict:
        """
        Generate a detailed user activity report.

        Args:
            user_id: Specific user ID to report on, or None for all users
        """
        query = AuditLog.objects.filter(
            created_at__gte=self.start_date,
            created_at__lte=self.end_date
        )

        if user_id:
            query = query.filter(user_id=user_id)

        # Group by user
        user_stats = {}
        for log in query.select_related('user'):
            uid = str(log.user_id) if log.user else 'anonymous'
            if uid not in user_stats:
                user_stats[uid] = {
                    'username': log.username or 'anonymous',
                    'total_actions': 0,
                    'actions_by_type': {},
                    'risk_scores': [],
                    'ip_addresses': set(),
                    'last_activity': log.created_at,
                    'suspicious_count': 0,
                }

            user_stats[uid]['total_actions'] += 1
            user_stats[uid]['actions_by_type'][log.action] = \
                user_stats[uid]['actions_by_type'].get(log.action, 0) + 1
            user_stats[uid]['risk_scores'].append(log.risk_score)

            if log.ip_address:
                user_stats[uid]['ip_addresses'].add(log.ip_address)

            if log.is_suspicious:
                user_stats[uid]['suspicious_count'] += 1

            if log.created_at > user_stats[uid]['last_activity']:
                user_stats[uid]['last_activity'] = log.created_at

        # Calculate averages and summaries
        for uid, stats in user_stats.items():
            risk_scores = stats['risk_scores']
            stats['avg_risk_score'] = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            stats['max_risk_score'] = max(risk_scores) if risk_scores else 0
            stats['ip_addresses'] = list(stats['ip_addresses'])

        return {
            'report_type': 'user_activity',
            'date_range': {
                'start': self.start_date.isoformat(),
                'end': self.end_date.isoformat(),
            },
            'user_stats': user_stats,
            'generated_at': timezone.now().isoformat(),
        }

    def generate_compliance_report(self) -> Dict:
        """
        Generate a compliance-focused report.

        Includes data access patterns, permission changes, and security events
        relevant for compliance auditing.
        """
        audit_logs = AuditLog.objects.filter(
            created_at__gte=self.start_date,
            created_at__lte=self.end_date
        )

        # Data access patterns
        data_access = audit_logs.filter(
            action__in=['read', 'create', 'update', 'delete'],
            resource_type__in=['user', 'permission', 'role', 'data']
        )

        # Permission changes
        permission_changes = audit_logs.filter(
            resource_type__in=['permission', 'role', 'group']
        )

        # Security events
        security_events = audit_logs.filter(
            Q(is_suspicious=True) | Q(risk_score__gte=50)
        )

        # Failed authentications
        failed_auth = audit_logs.filter(
            action='login',
            response_status__in=[400, 401, 403]
        )

        return {
            'report_type': 'compliance',
            'date_range': {
                'start': self.start_date.isoformat(),
                'end': self.end_date.isoformat(),
            },
            'data_access_events': {
                'total': data_access.count(),
                'by_action': dict(data_access.values('action').annotate(count=Count('action')).values_list('action', 'count')),
                'by_resource': dict(data_access.values('resource_type').annotate(count=Count('resource_type')).values_list('resource_type', 'count')),
            },
            'permission_changes': {
                'total': permission_changes.count(),
                'by_action': dict(permission_changes.values('action').annotate(count=Count('action')).values_list('action', 'count')),
            },
            'security_events': {
                'total': security_events.count(),
                'suspicious': security_events.filter(is_suspicious=True).count(),
                'high_risk': security_events.filter(risk_score__gte=70).count(),
            },
            'authentication_failures': {
                'total': failed_auth.count(),
                'by_user': dict(failed_auth.values('username').annotate(count=Count('username')).values_list('username', 'count')),
            },
            'generated_at': timezone.now().isoformat(),
        }

    def export_to_csv(self, report_data: Dict, report_type: str) -> str:
        """
        Export report data to CSV format.

        Args:
            report_data: Report data dictionary
            report_type: Type of report for formatting

        Returns:
            CSV content as string
        """
        output = io.StringIO()
        writer = csv.writer(output)

        if report_type == 'security_summary':
            # Write security summary CSV
            writer.writerow(['Metric', 'Value'])
            summary = report_data.get('summary', {})
            for key, value in summary.items():
                writer.writerow([key.replace('_', ' ').title(), value])

        elif report_type == 'user_activity':
            # Write user activity CSV
            writer.writerow(['User ID', 'Username', 'Total Actions', 'Avg Risk Score', 'Max Risk Score', 'Suspicious Count', 'Last Activity'])
            user_stats = report_data.get('user_stats', {})
            for uid, stats in user_stats.items():
                writer.writerow([
                    uid,
                    stats['username'],
                    stats['total_actions'],
                    round(stats['avg_risk_score'], 2),
                    stats['max_risk_score'],
                    stats['suspicious_count'],
                    stats['last_activity'].isoformat(),
                ])

        return output.getvalue()

    def export_to_json(self, report_data: Dict) -> str:
        """
        Export report data to JSON format.

        Args:
            report_data: Report data dictionary

        Returns:
            JSON string
        """
        return json.dumps(report_data, indent=2, default=str)

    def _calculate_risk_distribution(self, audit_logs) -> Dict[str, int]:
        """Calculate risk score distribution."""
        distribution = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}

        for log in audit_logs:
            if log.risk_score <= 20:
                distribution['0-20'] += 1
            elif log.risk_score <= 40:
                distribution['21-40'] += 1
            elif log.risk_score <= 60:
                distribution['41-60'] += 1
            elif log.risk_score <= 80:
                distribution['61-80'] += 1
            else:
                distribution['81-100'] += 1

        return distribution

    def _get_top_risky_users(self, audit_logs, limit: int = 10) -> List[Dict]:
        """Get users with highest risk scores."""
        risky_users = {}

        for log in audit_logs.filter(risk_score__gte=50).select_related('user'):
            uid = str(log.user_id) if log.user else 'anonymous'
            username = log.username or 'anonymous'

            if uid not in risky_users:
                risky_users[uid] = {
                    'user_id': uid,
                    'username': username,
                    'high_risk_count': 0,
                    'avg_risk_score': 0,
                    'total_actions': 0,
                    'risk_scores': [],
                }

            risky_users[uid]['high_risk_count'] += 1
            risky_users[uid]['total_actions'] += 1
            risky_users[uid]['risk_scores'].append(log.risk_score)

        # Calculate averages and sort
        for uid, data in risky_users.items():
            data['avg_risk_score'] = sum(data['risk_scores']) / len(data['risk_scores'])
            del data['risk_scores']  # Remove raw scores

        # Sort by high risk count, then by average risk score
        sorted_users = sorted(
            risky_users.values(),
            key=lambda x: (x['high_risk_count'], x['avg_risk_score']),
            reverse=True
        )

        return sorted_users[:limit]

    def _calculate_failed_login_stats(self, audit_logs) -> Dict:
        """Calculate failed login statistics."""
        failed_logins = audit_logs.filter(
            action='login',
            response_status__in=[400, 401, 403]
        )

        return {
            'total_failed': failed_logins.count(),
            'by_ip': dict(failed_logins.values('ip_address').annotate(count=Count('ip_address')).values_list('ip_address', 'count')),
            'by_user': dict(failed_logins.values('username').annotate(count=Count('username')).values_list('username', 'count')),
        }

    def _detect_geographic_anomalies(self, audit_logs) -> List[Dict]:
        """Detect geographic access anomalies."""
        # This is a simplified version - in production, you'd use actual geolocation data
        anomalies = []

        # Group by user and location
        user_locations = {}
        for log in audit_logs.select_related('user', 'location').exclude(location__isnull=True):
            uid = str(log.user_id) if log.user else 'anonymous'
            location_id = log.location.id

            if uid not in user_locations:
                user_locations[uid] = {
                    'username': log.username or 'anonymous',
                    'locations': set(),
                    'location_times': {},
                }

            user_locations[uid]['locations'].add(location_id)
            if location_id not in user_locations[uid]['location_times']:
                user_locations[uid]['location_times'][location_id] = []
            user_locations[uid]['location_times'][location_id].append(log.created_at)

        # Check for rapid location changes
        for uid, data in user_locations.items():
            if len(data['locations']) > 1:
                # Check if locations were accessed within short time spans
                all_times = []
                for times in data['location_times'].values():
                    all_times.extend(times)

                if len(all_times) >= 2:
                    time_span = max(all_times) - min(all_times)
                    if time_span.total_seconds() < 3600 and len(data['locations']) > 1:  # Within 1 hour
                        anomalies.append({
                            'user_id': uid,
                            'username': data['username'],
                            'location_count': len(data['locations']),
                            'time_span_hours': time_span.total_seconds() / 3600,
                            'severity': 'high',
                        })

        return anomalies
