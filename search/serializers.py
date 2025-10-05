from __future__ import annotations

import json
from typing import Any, Iterable, Sequence

from django.contrib.gis.geos import GEOSGeometry
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers


class PaginationSerializer(serializers.Serializer):
    page = serializers.IntegerField(min_value=1, required=False, default=1)
    page_size = serializers.IntegerField(min_value=1, max_value=200, required=False, default=25)


class SearchRequestSerializer(serializers.Serializer):
    query = serializers.CharField(required=False, allow_blank=True, default="")
    filters = serializers.DictField(child=serializers.JSONField(), required=False, default=dict)
    sort = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True, default=list
    )
    include_facets = serializers.BooleanField(required=False, default=True)
    pagination = PaginationSerializer(required=False)

    def get_pagination(self, attrs: dict[str, Any]) -> dict[str, int]:
        pagination_data = attrs.get("pagination") or {}
        page = pagination_data.get("page", 1)
        page_size = pagination_data.get("page_size", 25)
        return {"page": page, "page_size": page_size}


class SpatialMixin(serializers.Serializer):
    polygon = serializers.ListField(
        child=serializers.ListField(child=serializers.FloatField()),
        required=False,
        help_text="List of [lon, lat] points defining a polygon",
    )
    route = serializers.ListField(
        child=serializers.ListField(child=serializers.FloatField()),
        required=False,
        help_text="Polyline represented as list of [lon, lat] points",
    )
    radius = serializers.FloatField(required=False, min_value=0.0)
    center_point = serializers.ListField(
        child=serializers.FloatField(),
        min_length=2,
        max_length=2,
        required=False,
        help_text="Center point for radius-based searches as [lon, lat]",
    )
    bbox = serializers.ListField(
        child=serializers.FloatField(),
        min_length=4,
        max_length=4,
        required=False,
        help_text="Bounding box defined as [min_lon, min_lat, max_lon, max_lat]",
    )

    def _ensure_point_list(self, points: Iterable[Iterable[float]]) -> list[list[float]]:
        try:
            normalized = [[float(coord) for coord in pair] for pair in points]
        except (TypeError, ValueError) as exc:
            raise ValidationError(_("Invalid coordinate list provided")) from exc
        if not normalized:
            raise ValidationError(_("At least one coordinate pair is required"))
        return normalized

    def get_polygon_geometry(self) -> GEOSGeometry | None:
        polygon_points = self.validated_data.get("polygon")
        if not polygon_points:
            return None
        normalized = self._ensure_point_list(polygon_points)
        if normalized[0] != normalized[-1]:
            normalized.append(normalized[0])
        geojson = {
            "type": "Polygon",
            "coordinates": [normalized],
        }
        return GEOSGeometry(json.dumps(geojson), srid=4326)

    def get_route_geometry(self) -> GEOSGeometry | None:
        route_points = self.validated_data.get("route")
        if not route_points:
            return None
        normalized = self._ensure_point_list(route_points)
        if len(normalized) < 2:
            raise ValidationError(_("Route geometry requires at least two points"))
        geojson = {
            "type": "LineString",
            "coordinates": normalized,
        }
        return GEOSGeometry(json.dumps(geojson), srid=4326)

    def get_bbox(self) -> Sequence[float] | None:
        bbox = self.validated_data.get("bbox")
        if not bbox:
            return None
        min_lon, min_lat, max_lon, max_lat = bbox
        if min_lon >= max_lon or min_lat >= max_lat:
            raise ValidationError(_("Bounding box coordinates are invalid"))
        return bbox

    def get_radius_filter(self) -> tuple[float, float, float] | None:
        radius = self.validated_data.get("radius")
        center = self.validated_data.get("center_point")
        if radius is None or center is None:
            return None
        try:
            lon, lat = float(center[0]), float(center[1])
        except (TypeError, ValueError) as exc:
            raise ValidationError(_("Center point coordinates are invalid")) from exc
        return lon, lat, radius


class LocationSearchRequestSerializer(SpatialMixin, SearchRequestSerializer):
    location_types = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    location_levels = serializers.ListField(
        child=serializers.IntegerField(min_value=0), required=False, allow_empty=True
    )
    include_inactive = serializers.BooleanField(required=False, default=False)
    ancestors_of = serializers.UUIDField(required=False)
    descendants_of = serializers.UUIDField(required=False)
    nearest_only = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        attrs = super().validate(attrs)
        center = attrs.get("center_point")
        radius = attrs.get("radius")
        if (center and radius is None) or (radius and not center):
            raise ValidationError("Both center_point and radius are required for radius searches")
        return attrs


class UserSearchRequestSerializer(SearchRequestSerializer):
    departments = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    positions = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    is_active = serializers.BooleanField(required=False)
    role_codes = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )


class AuditLogSearchRequestSerializer(SpatialMixin, SearchRequestSerializer):
    action_types = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    risk_min = serializers.IntegerField(required=False, min_value=0, max_value=100)
    risk_max = serializers.IntegerField(required=False, min_value=0, max_value=100)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        attrs = super().validate(attrs)
        min_risk = attrs.get("risk_min")
        max_risk = attrs.get("risk_max")
        if min_risk is not None and max_risk is not None and min_risk > max_risk:
            raise ValidationError(_("risk_min cannot be greater than risk_max"))
        if attrs.get("date_from") and attrs.get("date_to"):
            if attrs["date_from"] > attrs["date_to"]:
                raise ValidationError(_("date_from cannot be greater than date_to"))
        return attrs


class SearchResultSerializer(serializers.Serializer):
    id = serializers.CharField()
    type = serializers.CharField()
    score = serializers.FloatField(required=False)
    summary = serializers.DictField(child=serializers.JSONField())
    metadata = serializers.DictField(child=serializers.JSONField(), required=False)


class FacetSerializer(serializers.Serializer):
    name = serializers.CharField()
    buckets = serializers.ListField(child=serializers.DictField())


class SearchSuggestionSerializer(serializers.Serializer):
    query = serializers.CharField()
    normalized_query = serializers.CharField()
    popularity = serializers.IntegerField()


class SearchAnalyticsSerializer(serializers.Serializer):
    total_queries = serializers.IntegerField()
    average_latency_ms = serializers.FloatField()
    abandonment_rate = serializers.FloatField()
    click_through_rate = serializers.FloatField()
    top_queries = serializers.ListField(child=SearchSuggestionSerializer())
    performance_buckets = serializers.DictField(child=serializers.IntegerField())


class SearchClickSerializer(serializers.Serializer):
    query_id = serializers.UUIDField()
    object_type = serializers.CharField(max_length=64)
    object_id = serializers.CharField(max_length=128)
    position = serializers.IntegerField(min_value=0)
    metadata = serializers.DictField(child=serializers.JSONField(), required=False, default=dict)


class AdvancedSearchRequestSerializer(serializers.Serializer):
    query = serializers.CharField(required=False, allow_blank=True, default="")
    targets = serializers.ListField(
        child=serializers.ChoiceField(choices=["locations", "users", "audit_logs"]),
        required=False,
        allow_empty=True,
        default=list,
    )
    include_facets = serializers.BooleanField(required=False, default=False)
    filters = serializers.DictField(child=serializers.JSONField(), required=False, default=dict)
    pagination = PaginationSerializer(required=False)

    def get_targets(self) -> list[str]:
        targets = self.validated_data.get("targets") or ["locations", "users", "audit_logs"]
        return targets

    def get_pagination(self) -> dict[str, int]:
        pagination_data = self.validated_data.get("pagination") or {}
        page = pagination_data.get("page", 1)
        page_size = pagination_data.get("page_size", 10)
        return {"page": page, "page_size": page_size}


__all__ = [
    "AdvancedSearchRequestSerializer",
    "AuditLogSearchRequestSerializer",
    "FacetSerializer",
    "LocationSearchRequestSerializer",
    "PaginationSerializer",
    "SearchAnalyticsSerializer",
    "SearchClickSerializer",
    "SearchRequestSerializer",
    "SearchResultSerializer",
    "SearchSuggestionSerializer",
    "UserSearchRequestSerializer",
]
