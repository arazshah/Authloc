from django.conf import settings
from django.contrib.gis.db import models as gis_models
from django.contrib.postgres.fields import JSONField
from django.db import models

from core.models import TimeStampedModel, UUIDModel


class AuditLog(UUIDModel, TimeStampedModel):
    class Actions(models.TextChoices):
        LOGIN = "login", "Login"
        LOGOUT = "logout", "Logout"
        CREATE = "create", "Create"
        READ = "read", "Read"
        UPDATE = "update", "Update"
        DELETE = "delete", "Delete"

    action = models.CharField(max_length=32, choices=Actions.choices)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    username = models.CharField(max_length=150, blank=True, help_text="Denormalized username for performance")
    resource_type = models.CharField(max_length=100, blank=True, help_text="Model name or resource type")
    resource_id = models.CharField(max_length=100, blank=True, help_text="ID of the affected resource")
    resource_name = models.CharField(max_length=255, blank=True, help_text="Human-readable resource name")
    old_values = JSONField(default=dict, blank=True, help_text="Previous values before change")
    new_values = JSONField(default=dict, blank=True, help_text="New values after change")
    changes_summary = JSONField(default=dict, blank=True, help_text="Summary of what changed")
    ip_address = models.GenericIPAddressField(blank=True, null=True, help_text="Client IP address")
    user_agent = models.TextField(blank=True, help_text="User agent string")
    request_method = models.CharField(max_length=10, blank=True, help_text="HTTP method")
    request_path = models.TextField(blank=True, help_text="Request URL path")
    request_body = JSONField(default=dict, blank=True, help_text="Request body data")
    response_status = models.PositiveIntegerField(blank=True, null=True, help_text="HTTP response status code")
    processing_time = models.DecimalField(
        max_digits=10, decimal_places=3, blank=True, null=True,
        help_text="Request processing time in seconds"
    )
    location = models.ForeignKey(
        "locations.Location",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    geo_location = gis_models.PointField(blank=True, null=True, help_text="Geographic coordinates")
    risk_score = models.PositiveIntegerField(default=0, help_text="Risk score (0-100)")
    is_suspicious = models.BooleanField(default=False, help_text="Whether this activity is suspicious")
    metadata = JSONField(default=dict, blank=True, help_text="Additional metadata")

    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["resource_type", "created_at"]),
            models.Index(fields=["ip_address", "created_at"]),
            models.Index(fields=["risk_score", "created_at"]),
            models.Index(fields=["is_suspicious", "created_at"]),
            models.Index(fields=["location", "created_at"]),
        ]

    def __str__(self):  # pragma: no cover - display helper
        return f"{self.action} {self.resource_type} by {self.username or 'Anonymous'}"


class SecurityAlert(UUIDModel, TimeStampedModel):
    class AlertTypes(models.TextChoices):
        SUSPICIOUS_LOGIN = "suspicious_login", "Suspicious Login"
        BRUTE_FORCE = "brute_force", "Brute Force Attack"
        UNAUTHORIZED_ACCESS = "unauthorized_access", "Unauthorized Access"
        PERMISSION_ESCALATION = "permission_escalation", "Permission Escalation"
        DATA_EXPORT = "data_export", "Data Export"
        GEOGRAPHIC_ANOMALY = "geographic_anomaly", "Geographic Anomaly"
        UNUSUAL_ACCESS_PATTERN = "unusual_access_pattern", "Unusual Access Pattern"

    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    alert_type = models.CharField(max_length=50, choices=AlertTypes.choices)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    details = JSONField(default=dict, blank=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_alerts",
    )
    audit_log = models.ForeignKey(
        AuditLog,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_alerts",
    )
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    geo_location = gis_models.PointField(blank=True, null=True)

    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="resolved_alerts",
    )
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolution_notes = models.TextField(blank=True)

    class Meta:
        verbose_name = "Security Alert"
        verbose_name_plural = "Security Alerts"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["alert_type", "created_at"]),
            models.Index(fields=["severity", "created_at"]),
            models.Index(fields=["is_resolved", "created_at"]),
            models.Index(fields=["user", "created_at"]),
        ]

    def __str__(self):  # pragma: no cover - display helper
        return f"{self.severity} {self.alert_type}: {self.title}"


class PermissionAuditLog(UUIDModel, TimeStampedModel):
    class Actions(models.TextChoices):
        GRANT = "grant", "Grant"
        REVOKE = "revoke", "Revoke"
        CHECK = "check", "Check"
        BULK_GRANT = "bulk_grant", "Bulk Grant"
        BULK_REVOKE = "bulk_revoke", "Bulk Revoke"

    action = models.CharField(max_length=32, choices=Actions.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="performed_permission_audits",
    )
    subject = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="targeted_permission_audits",
    )
    role = models.ForeignKey(
        "permissions.Role",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="permission_audits",
    )
    location = models.ForeignKey(
        "locations.Location",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="permission_audits",
    )
    payload = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    message = models.TextField(blank=True)

    class Meta:
        verbose_name = "Permission Audit Log"
        verbose_name_plural = "Permission Audit Logs"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["subject", "created_at"]),
            models.Index(fields=["role", "created_at"]),
            models.Index(fields=["location", "created_at"]),
        ]

    def __str__(self):  # pragma: no cover - display helper
        return f"{self.action} {self.subject or '-'} @ {self.location or 'global'}"


__all__ = ["AuditLog", "SecurityAlert", "PermissionAuditLog"]
