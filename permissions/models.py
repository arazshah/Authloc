from __future__ import annotations

from typing import Any, Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from core.models import TimeStampedModel, UUIDModel, UserTrackedModel
from locations.models import Location
from permissions.constants import SYSTEM_ROLE_PRIORITIES


class RoleQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)

    def system_roles(self):
        return self.filter(is_system_role=True)

    def non_system_roles(self):
        return self.filter(is_system_role=False)


class Role(UUIDModel, TimeStampedModel, UserTrackedModel):
    name = models.CharField(max_length=150, unique=True)
    code = models.SlugField(max_length=150, unique=True)
    description = models.TextField(blank=True)
    permissions = models.JSONField(default=dict, blank=True)
    is_system_role = models.BooleanField(default=False)
    priority = models.PositiveIntegerField(default=100)
    parent_role = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="children",
        help_text=_("Parent role for permission inheritance."),
    )
    is_active = models.BooleanField(default=True)

    objects = RoleQuerySet.as_manager()

    class Meta:
        verbose_name = "Role"
        verbose_name_plural = "Roles"
        ordering = ("priority", "name")

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.name} ({self.code})"

    def clean(self):
        super().clean()
        if self.parent_role_id == self.pk and self.pk is not None:
            raise models.ValidationError({"parent_role": _("A role cannot inherit from itself.")})

    def save(self, *args: Any, **kwargs: Any):
        if self.is_system_role:
            self.priority = SYSTEM_ROLE_PRIORITIES.get(self.code, self.priority)
        super().save(*args, **kwargs)


class UserRoleQuerySet(models.QuerySet):
    def active(self, at: Optional[Any] = None):
        reference = at or timezone.now()
        return self.filter(
            models.Q(valid_from__isnull=True) | models.Q(valid_from__lte=reference),
            models.Q(valid_until__isnull=True) | models.Q(valid_until__gte=reference),
            is_active=True,
        )

    def for_user(self, user):
        return self.filter(user=user)

    def for_location(self, location: Optional[Location]):
        if location is None:
            return self
        return self.filter(location=location)


class UserRole(UUIDModel, TimeStampedModel, UserTrackedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_roles")
    location = models.ForeignKey(
        Location,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="user_roles",
    )
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_user_roles",
    )
    reason = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)

    objects = UserRoleQuerySet.as_manager()

    class Meta:
        verbose_name = "User Role"
        verbose_name_plural = "User Roles"
        unique_together = ("user", "role", "location", "valid_from", "valid_until")
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["role", "is_active"]),
            models.Index(fields=["location"]),
            models.Index(fields=["valid_from", "valid_until"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        target_location = getattr(self.location, "name", None)
        return f"{self.user} -> {self.role} ({target_location or 'Global'})"

    def is_current(self, at: Optional[Any] = None) -> bool:
        reference = at or timezone.now()
        if not self.is_active:
            return False
        if self.valid_from and self.valid_from > reference:
            return False
        if self.valid_until and self.valid_until < reference:
            return False
        return True

    def deactivate(self, reason: Optional[str] = None, updated_by=None):
        self.is_active = False
        update_fields = {"is_active", "updated_at"}
        if reason is not None:
            self.reason = reason
            update_fields.add("reason")
        self.updated_by = updated_by
        update_fields.add("updated_by")
        self.save(update_fields=sorted(update_fields))


class RoleAssignmentRequestQuerySet(models.QuerySet):
    def pending(self):
        return self.filter(status=self.model.Status.PENDING)

    def approved(self):
        return self.filter(status=self.model.Status.APPROVED)

    def rejected(self):
        return self.filter(status=self.model.Status.REJECTED)


class RoleAssignmentRequest(UUIDModel, TimeStampedModel, UserTrackedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="role_assignment_requests",
    )
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="assignment_requests")
    location = models.ForeignKey(
        Location,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="role_assignment_requests",
    )
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="requested_role_assignments",
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_role_assignments",
    )
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING, db_index=True)
    reason = models.TextField(blank=True)
    response_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_user_role = models.OneToOneField(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assignment_request",
    )

    objects = RoleAssignmentRequestQuerySet.as_manager()

    class Meta:
        verbose_name = "Role Assignment Request"
        verbose_name_plural = "Role Assignment Requests"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["role", "status"]),
            models.Index(fields=["location"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        scope = getattr(self.location, "name", None)
        return f"Request {self.pk} for {self.user} -> {self.role} ({scope or 'Global'})"

    def clean(self):
        super().clean()
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ValidationError({"valid_until": _("valid_until must be greater than valid_from.")})

    def approve(self, approver=None, response_message: Optional[str] = None) -> UserRole:
        if self.status != self.Status.PENDING:
            raise ValidationError({"status": _("Only pending requests can be approved.")})

        with transaction.atomic():
            user_role = UserRole.objects.create(
                user=self.user,
                role=self.role,
                location=self.location,
                valid_from=self.valid_from,
                valid_until=self.valid_until,
                assigned_by=approver,
                reason=self.reason,
                metadata=self.metadata,
                is_active=True,
                created_by=self.requested_by,
                updated_by=approver,
            )
            self.status = self.Status.APPROVED
            self.approver = approver
            self.reviewed_at = timezone.now()
            if response_message:
                self.response_message = response_message
            self.created_user_role = user_role
            self.updated_by = approver
            self.save(
                update_fields=[
                    "status",
                    "approver",
                    "reviewed_at",
                    "response_message",
                    "created_user_role",
                    "updated_at",
                    "updated_by",
                ]
            )
        return user_role

    def reject(self, approver=None, response_message: Optional[str] = None):
        if self.status != self.Status.PENDING:
            raise ValidationError({"status": _("Only pending requests can be rejected.")})

        self.status = self.Status.REJECTED
        self.approver = approver
        self.reviewed_at = timezone.now()
        if response_message:
            self.response_message = response_message
        self.updated_by = approver
        self.save(
            update_fields=["status", "approver", "reviewed_at", "response_message", "updated_at", "updated_by"]
        )
