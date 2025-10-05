from rest_framework import serializers

from .models import AuditLog, SecurityAlert


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""

    user_email = serializers.CharField(source='user.email', read_only=True)
    location_name = serializers.CharField(source='location.name', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'action', 'user', 'user_email', 'username', 'resource_type',
            'resource_id', 'resource_name', 'old_values', 'new_values',
            'changes_summary', 'ip_address', 'user_agent', 'request_method',
            'request_path', 'request_body', 'response_status', 'processing_time',
            'location', 'location_name', 'geo_location', 'risk_score',
            'is_suspicious', 'metadata', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AuditLogListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing audit logs."""

    user_email = serializers.CharField(source='user.email', read_only=True)
    location_name = serializers.CharField(source='location.name', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'action', 'username', 'user_email', 'resource_type',
            'resource_name', 'ip_address', 'response_status', 'risk_score',
            'is_suspicious', 'created_at', 'location_name'
        ]


class SecurityAlertSerializer(serializers.ModelSerializer):
    """Serializer for SecurityAlert model."""

    user_email = serializers.CharField(source='user.email', read_only=True)
    resolved_by_email = serializers.CharField(source='resolved_by.email', read_only=True)

    class Meta:
        model = SecurityAlert
        fields = [
            'id', 'alert_type', 'severity', 'title', 'description', 'details',
            'user', 'user_email', 'audit_log', 'ip_address', 'geo_location',
            'is_resolved', 'resolved_by', 'resolved_by_email', 'resolved_at',
            'resolution_notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SecurityAlertListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing security alerts."""

    user_email = serializers.CharField(source='user.email', read_only=True)
    audit_log_action = serializers.CharField(source='audit_log.action', read_only=True)

    class Meta:
        model = SecurityAlert
        fields = [
            'id', 'alert_type', 'severity', 'title', 'user_email',
            'ip_address', 'is_resolved', 'created_at', 'audit_log_action'
        ]


class SecurityAlertResolveSerializer(serializers.Serializer):
    """Serializer for resolving security alerts."""

    resolution_notes = serializers.CharField(required=False, allow_blank=True)

    def update(self, instance, validated_data):
        instance.is_resolved = True
        instance.resolved_by = self.context['request'].user
        instance.resolved_at = timezone.now()
        instance.resolution_notes = validated_data.get('resolution_notes', '')
        instance.save()
        return instance


class UserActivitySerializer(serializers.Serializer):
    """Serializer for user activity data."""

    user_id = serializers.UUIDField()
    username = serializers.CharField()
    total_actions = serializers.IntegerField()
    actions_by_type = serializers.DictField()
    recent_activity = serializers.ListField()
    risk_score_trend = serializers.ListField()
    suspicious_activities = serializers.IntegerField()
    last_activity = serializers.DateTimeField()


class SecuritySummarySerializer(serializers.Serializer):
    """Serializer for security summary reports."""

    time_range = serializers.CharField()
    total_audit_logs = serializers.IntegerField()
    total_security_alerts = serializers.IntegerField()
    alerts_by_severity = serializers.DictField()
    alerts_by_type = serializers.DictField()
    suspicious_activities = serializers.IntegerField()
    failed_logins = serializers.IntegerField()
    top_risk_users = serializers.ListField()
    geographic_anomalies = serializers.IntegerField()
    high_risk_actions = serializers.IntegerField()
