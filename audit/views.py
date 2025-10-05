import uuid
from datetime import timedelta
from typing import Dict, Any

from django.db.models import Count, Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import AuditLog, SecurityAlert
from .monitoring import audit_monitor
from .permissions import IsSecurityAuditor
from .serializers import (
    AuditLogListSerializer, AuditLogSerializer, SecurityAlertListSerializer,
    SecurityAlertResolveSerializer, SecurityAlertSerializer, SecuritySummarySerializer,
    UserActivitySerializer
)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing audit logs.

    Provides comprehensive audit trail with advanced filtering capabilities.
    """
    queryset = AuditLog.objects.all().select_related('user', 'location')
    permission_classes = [IsAuthenticated, IsSecurityAuditor]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]

    filterset_fields = {
        'action': ['exact', 'in'],
        'user': ['exact'],
        'username': ['exact', 'icontains'],
        'resource_type': ['exact', 'in'],
        'resource_id': ['exact'],
        'ip_address': ['exact', 'icontains'],
        'response_status': ['exact', 'gte', 'lte'],
        'risk_score': ['exact', 'gte', 'lte'],
        'is_suspicious': ['exact'],
        'location': ['exact'],
        'created_at': ['gte', 'lte', 'date'],
    }

    search_fields = [
        'username', 'resource_name', 'ip_address', 'user_agent',
        'request_path', 'action'
    ]

    ordering_fields = [
        'created_at', 'risk_score', 'response_status', 'action'
    ]

    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AuditLogListSerializer
        return AuditLogSerializer

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get summary statistics for audit logs."""
        queryset = self.filter_queryset(self.get_queryset())

        summary = {
            'total_logs': queryset.count(),
            'actions_count': dict(queryset.values('action').annotate(count=Count('action')).values_list('action', 'count')),
            'suspicious_count': queryset.filter(is_suspicious=True).count(),
            'high_risk_count': queryset.filter(risk_score__gte=70).count(),
            'recent_logs': queryset[:5].count(),  # Last 5 logs
        }

        return Response(summary)

    @action(detail=False, methods=['get'])
    def export(self, request):
        """Export audit logs (filtered) to CSV/JSON."""
        # Implementation for data export
        # This would use django-import-export or similar
        return Response({'message': 'Export functionality to be implemented'})


class SecurityAlertViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing security alerts.

    Provides access to security alerts with filtering and resolution capabilities.
    """
    queryset = SecurityAlert.objects.all().select_related(
        'user', 'audit_log', 'resolved_by'
    )
    permission_classes = [IsAuthenticated, IsSecurityAuditor]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]

    filterset_fields = {
        'alert_type': ['exact', 'in'],
        'severity': ['exact', 'in'],
        'user': ['exact'],
        'ip_address': ['exact', 'icontains'],
        'is_resolved': ['exact'],
        'created_at': ['gte', 'lte', 'date'],
    }

    search_fields = [
        'title', 'description', 'ip_address'
    ]

    ordering_fields = [
        'created_at', 'severity', 'alert_type'
    ]

    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return SecurityAlertListSerializer
        elif self.action == 'resolve':
            return SecurityAlertResolveSerializer
        return SecurityAlertSerializer

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve a security alert."""
        alert = self.get_object()
        serializer = SecurityAlertResolveSerializer(
            alert, data=request.data, context={'request': request}
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        """Get all unresolved security alerts."""
        queryset = self.get_queryset().filter(is_resolved=False)
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def by_severity(self, request):
        """Get alerts grouped by severity."""
        alerts_by_severity = self.get_queryset().values('severity').annotate(
            count=Count('severity')
        ).order_by('severity')

        return Response(dict(alerts_by_severity.values_list('severity', 'count')))

    @action(detail=False, methods=['post'])
    def bulk_resolve(self, request):
        """Bulk resolve multiple alerts."""
        alert_ids = request.data.get('alert_ids', [])
        resolution_notes = request.data.get('resolution_notes', '')

        if not alert_ids:
            return Response(
                {'error': 'alert_ids field is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        alerts = SecurityAlert.objects.filter(
            id__in=alert_ids,
            is_resolved=False
        )

        updated_count = alerts.update(
            is_resolved=True,
            resolved_by=request.user,
            resolved_at=timezone.now(),
            resolution_notes=resolution_notes
        )

        return Response({
            'message': f'Successfully resolved {updated_count} alerts'
        })


class UserActivityViewSet(viewsets.ViewSet):
    """
    API endpoint for viewing user activity.

    Provides detailed activity analysis for specific users.
    """
    permission_classes = [IsAuthenticated, IsSecurityAuditor]

    @action(detail=True, methods=['get'])
    def activity(self, request, pk=None):
        """Get detailed activity for a specific user."""
        try:
            user_id = uuid.UUID(pk)
        except ValueError:
            return Response(
                {'error': 'Invalid user ID format'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get user's audit logs
        logs = AuditLog.objects.filter(user_id=user_id).select_related('user')

        if not logs.exists():
            return Response(
                {'error': 'User not found or no activity'},
                status=status.HTTP_404_NOT_FOUND
            )

        user = logs.first().user

        # Calculate activity metrics
        total_actions = logs.count()
        actions_by_type = dict(logs.values('action').annotate(
            count=Count('action')
        ).values_list('action', 'count'))

        # Recent activity (last 10)
        recent_activity = list(logs.order_by('-created_at')[:10].values(
            'action', 'resource_type', 'resource_name', 'ip_address',
            'created_at', 'risk_score', 'is_suspicious'
        ))

        # Risk score trend (last 7 days)
        seven_days_ago = timezone.now() - timedelta(days=7)
        risk_trend = list(logs.filter(created_at__gte=seven_days_ago).order_by('created_at').values_list(
            'created_at__date', 'risk_score'
        ))

        suspicious_activities = logs.filter(is_suspicious=True).count()
        last_activity = logs.order_by('-created_at').first().created_at

        data = {
            'user_id': str(user_id),
            'username': user.get_username(),
            'total_actions': total_actions,
            'actions_by_type': actions_by_type,
            'recent_activity': recent_activity,
            'risk_score_trend': risk_trend,
            'suspicious_activities': suspicious_activities,
            'last_activity': last_activity,
        }

        serializer = UserActivitySerializer(data=data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data)

    @action(detail=True, methods=['get'])
    def failed_logins(self, request, pk=None):
        """Get failed login attempts for a user."""
        try:
            user_id = uuid.UUID(pk)
        except ValueError:
            return Response(
                {'error': 'Invalid user ID format'},
                status=status.HTTP_400_BAD_REQUEST
            )

        failed_logins = audit_monitor.check_failed_logins(user_id=user_id)

        return Response(failed_logins)


class AuditReportsViewSet(viewsets.ViewSet):
    """
    API endpoint for audit reports and analytics.

    Provides security summaries and analytical reports.
    """
    permission_classes = [IsAuthenticated, IsSecurityAuditor]

    @action(detail=False, methods=['get'])
    def security_summary(self, request):
        """Get comprehensive security summary report."""
        # Parse time range from query params
        days = int(request.query_params.get('days', 7))
        start_date = timezone.now() - timedelta(days=days)

        # Get audit logs in time range
        audit_logs = AuditLog.objects.filter(created_at__gte=start_date)
        security_alerts = SecurityAlert.objects.filter(created_at__gte=start_date)

        # Calculate metrics
        total_logs = audit_logs.count()
        total_alerts = security_alerts.count()

        alerts_by_severity = dict(security_alerts.values('severity').annotate(
            count=Count('severity')
        ).values_list('severity', 'count'))

        alerts_by_type = dict(security_alerts.values('alert_type').annotate(
            count=Count('alert_type')
        ).values_list('alert_type', 'count'))

        suspicious_activities = audit_logs.filter(is_suspicious=True).count()
        failed_logins = audit_logs.filter(
            action='login',
            response_status__in=[400, 401, 403]
        ).count()

        # Top risk users (users with most high-risk actions)
        top_risk_users = list(audit_logs.filter(risk_score__gte=50).values('username').annotate(
            high_risk_count=Count('username')
        ).order_by('-high_risk_count')[:10].values('username', 'high_risk_count'))

        # Geographic anomalies (users accessing from multiple locations rapidly)
        geo_anomalies = audit_monitor.monitor_geographic_anomalies(days=days)

        # High risk actions
        high_risk_actions = audit_logs.filter(risk_score__gte=70).count()

        data = {
            'time_range': f'{days} days',
            'total_audit_logs': total_logs,
            'total_security_alerts': total_alerts,
            'alerts_by_severity': alerts_by_severity,
            'alerts_by_type': alerts_by_type,
            'suspicious_activities': suspicious_activities,
            'failed_logins': failed_logins,
            'top_risk_users': top_risk_users,
            'geographic_anomalies': len(geo_anomalies),
            'high_risk_actions': high_risk_actions,
        }

        serializer = SecuritySummarySerializer(data=data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data)

    @action(detail=False, methods=['get'])
    def access_patterns(self, request):
        """Get access pattern analysis."""
        days = int(request.query_params.get('days', 7))
        patterns = audit_monitor.detect_unusual_access_patterns(hours=days*24)

        return Response(patterns)

    @action(detail=False, methods=['get'])
    def permission_escalation(self, request):
        """Get permission escalation detection report."""
        hours = int(request.query_params.get('hours', 24))
        escalation_attempts = audit_monitor.detect_permission_escalation(hours=hours)

        return Response({
            'escalation_attempts': escalation_attempts,
            'total_attempts': len(escalation_attempts),
        })

    @action(detail=False, methods=['get'])
    def data_exports(self, request):
        """Get data export monitoring report."""
        hours = int(request.query_params.get('hours', 24))
        export_monitoring = audit_monitor.monitor_data_exports(hours=hours)

        return Response(export_monitoring)
