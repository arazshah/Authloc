from django.conf import settings
from django.db import models

from core.models import TimeStampedModel, UUIDModel


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


__all__ = ["PermissionAuditLog"]
