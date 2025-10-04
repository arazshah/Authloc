from django.conf import settings
from django.contrib.gis.db import models
from django.contrib.gis.geos import GEOSException
from django.core.exceptions import ValidationError
from django.db import models as django_models
from django.utils.translation import gettext_lazy as _

from core.models import TimeStampedModel, UUIDModel, UserTrackedModel


class LocationType(UUIDModel, TimeStampedModel, UserTrackedModel):
    class Levels(django_models.IntegerChoices):
        COUNTRY = 0, _("Country")
        PROVINCE = 1, _("Province")
        COUNTY = 2, _("County")
        CITY = 3, _("City")
        DISTRICT = 4, _("District")
        NEIGHBORHOOD = 5, _("Neighborhood")

    name = django_models.CharField(max_length=120, unique=True)
    name_fa = django_models.CharField(max_length=120, blank=True)
    code = django_models.CharField(max_length=50, unique=True)
    level = django_models.PositiveSmallIntegerField(choices=Levels.choices)
    icon = django_models.CharField(max_length=100, blank=True)
    color = django_models.CharField(max_length=32, blank=True)
    is_active = django_models.BooleanField(default=True)

    class Meta:
        verbose_name = "Location Type"
        verbose_name_plural = "Location Types"
        ordering = ("level", "name")

    def __str__(self) -> str:  # pragma: no cover - simple display
        return f"{self.name} ({self.get_level_display()})"


class LocationQuerySet(django_models.QuerySet):
    def roots(self):
        return self.filter(parent__isnull=True)

    def with_level(self, level: int):
        return self.filter(level=level)

    def descendants_of(self, location: "Location", include_self: bool = False):
        qs = self.filter(path__startswith=location.path)
        if not include_self:
            qs = qs.exclude(pk=location.pk)
        return qs

    def ancestors_of(self, location: "Location", include_self: bool = False):
        identifiers = [identifier for identifier in location.path.strip("/").split("/") if identifier]
        qs = self.filter(pk__in=identifiers).order_by("level")
        if not include_self:
            qs = qs.exclude(pk=location.pk)
        return qs

    def siblings_of(self, location: "Location", include_self: bool = False):
        qs = self.filter(parent=location.parent)
        if not include_self:
            qs = qs.exclude(pk=location.pk)
        return qs


class LocationManager(django_models.Manager.from_queryset(LocationQuerySet)):  # type: ignore[misc]
    pass


class Location(UUIDModel, TimeStampedModel, UserTrackedModel):
    name = django_models.CharField(max_length=120)
    name_fa = django_models.CharField(max_length=120, blank=True)
    code = django_models.CharField(max_length=50)
    type = django_models.ForeignKey(LocationType, on_delete=django_models.PROTECT, related_name="locations")
    parent = django_models.ForeignKey(
        "self",
        on_delete=django_models.CASCADE,
        null=True,
        blank=True,
        related_name="children",
    )
    level = django_models.PositiveSmallIntegerField(editable=False, db_index=True)
    path = django_models.CharField(max_length=1024, editable=False, db_index=True, blank=True)
    geometry = models.GeometryField(srid=4326, null=True, blank=True)
    center_point = models.PointField(srid=4326, geography=True, null=True, blank=True)
    area_sqm = django_models.FloatField(null=True, blank=True, editable=False)
    perimeter_m = django_models.FloatField(null=True, blank=True, editable=False)
    population = django_models.BigIntegerField(null=True, blank=True)
    postal_code = django_models.CharField(max_length=20, blank=True)
    description = django_models.TextField(blank=True)
    metadata = django_models.JSONField(default=dict, blank=True)
    is_active = django_models.BooleanField(default=True, db_index=True)

    objects = LocationManager()

    class Meta:
        verbose_name = "Location"
        verbose_name_plural = "Locations"
        unique_together = (("parent", "code"),)
        ordering = ("path",)
        constraints = (
            django_models.UniqueConstraint(
                fields=("code",),
                condition=django_models.Q(parent__isnull=True),
                name="location_unique_root_code",
            ),
        )

    def __str__(self) -> str:  # pragma: no cover - simple display
        return f"{self.name} ({self.code})"

    def clean(self):
        super().clean()
        if self.parent_id == self.id and self.id is not None:
            raise ValidationError({"parent": _("A location cannot be its own parent.")})

        if not self.type_id:
            raise ValidationError({"type": _("Location type is required.")})

        if self.parent:
            if self.parent.level + 1 != self.type.level:
                raise ValidationError(
                    {
                        "type": _(
                            "The location type level must be exactly one greater than the parent location level."
                        )
                    }
                )
        elif self.type.level != 0:
            raise ValidationError({"type": _("Root locations must use a level 0 type.")})

        if self.parent is None and self.code:
            qs = Location.objects.filter(parent__isnull=True, code=self.code)
            if self._state.adding:
                if qs.exists():
                    raise ValidationError({"code": _("Root location codes must be unique.")})
            else:
                qs = qs.exclude(pk=self.pk)
                if qs.exists():
                    raise ValidationError({"code": _("Root location codes must be unique.")})

    def save(self, *args, **kwargs):
        self.full_clean()
        previous_path = None
        previous_level = None
        if not self._state.adding:
            previous = Location.objects.get(pk=self.pk)
            previous_path = previous.path
            previous_level = previous.level

        self.level = self.type.level
        self._update_geometry_metrics()

        super().save(*args, **kwargs)

        desired_path = self._build_path()
        if self.path != desired_path:
            Location.objects.filter(pk=self.pk).update(path=desired_path)
            self.path = desired_path

        if previous_path and previous_path != self.path:
            self._propagate_path_change(previous_path, previous_level)

    def _build_path(self) -> str:
        if self.parent:
            return f"{self.parent.path}{self.pk}/"
        return f"{self.pk}/"

    def _propagate_path_change(self, previous_path: str, previous_level: int | None):
        descendants = Location.objects.filter(path__startswith=previous_path).exclude(pk=self.pk)
        for descendant in descendants.only("pk", "path", "level"):
            suffix = descendant.path[len(previous_path) :]
            new_path = f"{self.path}{suffix}"
            new_level = descendant.level
            if previous_level is not None:
                new_level = descendant.level - previous_level + self.level
            Location.objects.filter(pk=descendant.pk).update(path=new_path, level=new_level)

    def _update_geometry_metrics(self):
        if not self.geometry:
            self.area_sqm = None
            self.perimeter_m = None
            if not self.center_point:
                self.center_point = None
            return

        geometry = self.geometry
        if geometry.srid is None:
            geometry.srid = 4326

        if not self.center_point:
            try:
                centroid = geometry.centroid
                if centroid.srid is None:
                    centroid.srid = 4326
                self.center_point = centroid
            except (GEOSException, TypeError):  # pragma: no cover - protective
                self.center_point = None

        try:
            metric_geom = geometry.clone()
            metric_geom.transform(3857)
            self.area_sqm = metric_geom.area
            self.perimeter_m = metric_geom.length
        except (GEOSException, ValueError):  # pragma: no cover - protective
            self.area_sqm = None
            self.perimeter_m = None

    # Tree helpers -----------------------------------------------------
    def get_ancestors(self, include_self: bool = False):
        return Location.objects.ancestors_of(self, include_self=include_self)

    def get_descendants(self, include_self: bool = False):
        return Location.objects.descendants_of(self, include_self=include_self)

    def get_siblings(self, include_self: bool = False):
        return Location.objects.siblings_of(self, include_self=include_self)

    def is_ancestor_of(self, other: "Location") -> bool:
        if not other or other.pk == self.pk:
            return False
        return other.path.startswith(self.path)

    def is_descendant_of(self, other: "Location") -> bool:
        if not other or other.pk == self.pk:
            return False
        return self.path.startswith(other.path)


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
