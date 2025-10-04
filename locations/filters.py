from __future__ import annotations

import json
from typing import Any, Iterable

import django_filters
from django.contrib.gis.geos import Polygon
from django.core.exceptions import ValidationError

from .models import Location, LocationType


class LocationTypeFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(field_name="name", lookup_expr="icontains")
    code = django_filters.CharFilter(field_name="code", lookup_expr="iexact")
    level = django_filters.NumberFilter(field_name="level")
    is_active = django_filters.BooleanFilter(field_name="is_active")

    class Meta:
        model = LocationType
        fields = ["name", "code", "level", "is_active"]


class LocationFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(field_name="name", lookup_expr="icontains")
    name_fa = django_filters.CharFilter(field_name="name_fa", lookup_expr="icontains")
    code = django_filters.CharFilter(field_name="code", lookup_expr="icontains")
    type = django_filters.ModelChoiceFilter(queryset=LocationType.objects.all())
    type_code = django_filters.CharFilter(field_name="type__code", lookup_expr="iexact")
    parent = django_filters.UUIDFilter(field_name="parent__id")
    parent_code = django_filters.CharFilter(field_name="parent__code", lookup_expr="iexact")
    level = django_filters.NumberFilter(field_name="level")
    is_active = django_filters.BooleanFilter(field_name="is_active")
    min_population = django_filters.NumberFilter(field_name="population", lookup_expr="gte")
    max_population = django_filters.NumberFilter(field_name="population", lookup_expr="lte")
    metadata = django_filters.CharFilter(method="filter_metadata")
    bbox = django_filters.CharFilter(method="filter_bbox")

    class Meta:
        model = Location
        fields: Iterable[str] = [
            "name",
            "name_fa",
            "code",
            "type",
            "type_code",
            "parent",
            "parent_code",
            "level",
            "is_active",
            "min_population",
            "max_population",
            "metadata",
            "bbox",
        ]

    def filter_metadata(self, queryset, name, value):  # noqa: D401 - django-filters signature
        try:
            metadata_dict = json.loads(value) if isinstance(value, str) else value
        except json.JSONDecodeError as exc:
            raise ValidationError("metadata must be a valid JSON object") from exc
        if not isinstance(metadata_dict, dict):
            raise ValidationError("metadata must be a JSON object")
        for key, val in metadata_dict.items():
            queryset = queryset.filter(**{f"metadata__{key}": val})
        return queryset

    def filter_bbox(self, queryset, name, value):  # noqa: D401 - django-filters signature
        try:
            if isinstance(value, str):
                parts = [float(v.strip()) for v in value.split(",")]
            else:
                parts = list(value)
            if len(parts) != 4:
                raise ValueError
        except (TypeError, ValueError):
            raise ValidationError("bbox must contain four comma-separated numbers: min_lon,min_lat,max_lon,max_lat")
        min_lon, min_lat, max_lon, max_lat = parts
        polygon = Polygon(
            (
                (min_lon, min_lat),
                (max_lon, min_lat),
                (max_lon, max_lat),
                (min_lon, max_lat),
                (min_lon, min_lat),
            )
        )
        polygon.srid = 4326
        return queryset.filter(geometry__isnull=False, geometry__intersects=polygon)


__all__ = ["LocationTypeFilter", "LocationFilter"]
