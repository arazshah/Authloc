from django.conf import settings
from django.contrib.gis.db import models

from core.models import TimeStampedModel, UUIDModel, UserTrackedModel


class TrustedLocation(UUIDModel, TimeStampedModel, UserTrackedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="trusted_locations",
    )
    name = models.CharField(max_length=120)
    location = models.PointField(geography=True)
    radius_meters = models.PositiveIntegerField(default=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Trusted Location"
        verbose_name_plural = "Trusted Locations"
        unique_together = ("user", "name")
        ordering = ("user", "name")

    def __str__(self) -> str:  # pragma: no cover - simple display
        return f"{self.name} ({self.user})"


class LocationVerification(UUIDModel, TimeStampedModel):
    class Status(models.TextChoices):
        APPROVED = "approved", "Approved"
        DENIED = "denied", "Denied"
        REVIEW = "review", "Needs Review"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="location_verifications",
    )
    trusted_location = models.ForeignKey(
        TrustedLocation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verifications",
    )
    reported_location = models.PointField(geography=True)
    accuracy_meters = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.REVIEW)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Location Verification"
        verbose_name_plural = "Location Verifications"
        ordering = ("-created_at",)

    def __str__(self) -> str:  # pragma: no cover - simple display
        return f"Verification for {self.user} at {self.created_at:%Y-%m-%d %H:%M:%S}"
