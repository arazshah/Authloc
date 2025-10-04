from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from django.contrib.gis.geos import GEOSGeometry, Point
from django.db import transaction
from rest_framework import serializers

from .models import Location, LocationType


class GeometryField(serializers.Field):
    default_error_messages = {
        "invalid": "Invalid geometry representation.",
    }

    def to_representation(self, value: GEOSGeometry | None) -> Any:
        if value is None:
            return None
        if value.srid is None:
            value.srid = 4326
        return json.loads(value.geojson)

    def to_internal_value(self, data: Any) -> GEOSGeometry | None:
        if data in (None, ""):
            return None
        try:
            if isinstance(data, (dict, list)):
                geometry = GEOSGeometry(json.dumps(data))
            else:
                geometry = GEOSGeometry(data)
        except Exception:  # pragma: no cover - validated via serializer errors
            self.fail("invalid")
        if geometry.srid is None:
            geometry.srid = 4326
        return geometry


class PointGeometryField(GeometryField):
    default_error_messages = {
        "invalid": "Invalid point geometry representation.",
    }

    def to_internal_value(self, data: Any) -> Point | None:
        geometry = super().to_internal_value(data)
        if geometry is None:
            return None
        if not isinstance(geometry, Point):
            self.fail("invalid")
        return geometry


class LocationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LocationType
        fields = [
            "id",
            "name",
            "name_fa",
            "code",
            "level",
            "icon",
            "color",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class LocationListSerializer(serializers.ModelSerializer):
    type = LocationTypeSerializer(read_only=True)
    type_id = serializers.PrimaryKeyRelatedField(
        queryset=LocationType.objects.all(), write_only=True, source="type"
    )
    parent = serializers.PrimaryKeyRelatedField(read_only=True)
    parent_id = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, write_only=True, source="parent"
    )
    distance = serializers.FloatField(read_only=True)

    class Meta:
        model = Location
        fields = [
            "id",
            "name",
            "name_fa",
            "code",
            "type",
            "type_id",
            "parent",
            "parent_id",
            "level",
            "path",
            "population",
            "postal_code",
            "is_active",
            "distance",
        ]
        read_only_fields = ["id", "level", "path", "type", "parent"]


class LocationDetailSerializer(serializers.ModelSerializer):
    type = LocationTypeSerializer(read_only=True)
    type_id = serializers.PrimaryKeyRelatedField(
        queryset=LocationType.objects.all(), write_only=True, source="type"
    )
    parent_id = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, write_only=True, source="parent"
    )
    geometry = GeometryField(required=False, allow_null=True)
    center_point = PointGeometryField(required=False, allow_null=True)
    parent = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Location
        fields = [
            "id",
            "name",
            "name_fa",
            "code",
            "type",
            "type_id",
            "parent",
            "parent_id",
            "level",
            "path",
            "geometry",
            "center_point",
            "area_sqm",
            "perimeter_m",
            "population",
            "postal_code",
            "description",
            "metadata",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "level",
            "path",
            "type",
            "area_sqm",
            "perimeter_m",
            "parent",
            "created_at",
            "updated_at",
        ]


class LocationTreeSerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()
    type = LocationTypeSerializer(read_only=True)

    class Meta:
        model = Location
        fields = [
            "id",
            "name",
            "name_fa",
            "code",
            "level",
            "path",
            "type",
            "parent",
            "children",
        ]
        read_only_fields = fields

    def get_children(self, obj: Location) -> list[dict[str, Any]]:
        child_map = self.context.get("child_map") if isinstance(self.context, dict) else None
        if child_map is not None:
            children = child_map.get(obj.pk, [])
        else:
            children = obj.children.all()
        serializer = LocationTreeSerializer(children, many=True, context=self.context)
        return serializer.data


class LocationGeoJSONSerializer(serializers.ModelSerializer):
    type = serializers.SerializerMethodField()
    geometry = GeometryField(source="geometry", read_only=True)
    properties = serializers.SerializerMethodField()

    class Meta:
        model = Location
        fields = ["type", "geometry", "properties"]

    def get_type(self, obj: Location) -> str:
        return "Feature"

    def get_properties(self, obj: Location) -> dict[str, Any]:
        return {
            "id": str(obj.pk),
            "name": obj.name,
            "name_fa": obj.name_fa,
            "code": obj.code,
            "type": obj.type.code if obj.type else None,
            "type_level": obj.level,
            "parent": str(obj.parent_id) if obj.parent_id else None,
            "population": obj.population,
            "postal_code": obj.postal_code,
            "metadata": obj.metadata,
        }


class LocationSearchSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True)
    name_fa = serializers.CharField(required=False, allow_blank=True)
    code = serializers.CharField(required=False, allow_blank=True)
    type = serializers.UUIDField(required=False)
    type_code = serializers.CharField(required=False, allow_blank=True)
    parent = serializers.UUIDField(required=False)
    level = serializers.IntegerField(required=False, min_value=0)
    population_min = serializers.IntegerField(required=False, min_value=0)
    population_max = serializers.IntegerField(required=False, min_value=0)
    bbox = serializers.ListField(
        child=serializers.FloatField(), min_length=4, max_length=4, required=False
    )
    metadata = serializers.DictField(required=False)
    include_children = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        min_population = attrs.get("population_min")
        max_population = attrs.get("population_max")
        if min_population is not None and max_population is not None and min_population > max_population:
            raise serializers.ValidationError("population_min cannot be greater than population_max")
        return attrs


class LocationNearbySerializer(serializers.Serializer):
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()
    radius_meters = serializers.IntegerField(min_value=1)
    type_code = serializers.CharField(required=False)
    limit = serializers.IntegerField(min_value=1, max_value=100, required=False, default=10)

    def to_point(self) -> Point:
        validated = self.validated_data
        return Point(validated["longitude"], validated["latitude"], srid=4326)


class LocationBulkImportSerializer(serializers.Serializer):
    FORMAT_CHOICES = ("csv", "geojson")

    file = serializers.FileField()
    format = serializers.ChoiceField(choices=FORMAT_CHOICES, required=False)
    location_type = serializers.PrimaryKeyRelatedField(queryset=LocationType.objects.all(), required=False)
    parent = serializers.PrimaryKeyRelatedField(queryset=Location.objects.all(), required=False, allow_null=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        upload = attrs.get("file")
        fmt = attrs.get("format")
        if not fmt and upload:
            name = upload.name.lower()
            if name.endswith(".csv"):
                attrs["format"] = "csv"
            elif name.endswith(".json") or name.endswith(".geojson"):
                attrs["format"] = "geojson"
        if attrs.get("format") == "geojson" and not attrs.get("location_type"):
            # GeoJSON allows embedding type_code in features; optional
            pass
        if attrs.get("format") == "csv" and not attrs.get("location_type"):
            raise serializers.ValidationError(
                {"location_type": "A location_type is required when importing CSV files."}
            )
        return attrs

    @transaction.atomic
    def save(self, *, created_by=None) -> list[Location]:
        from .utils import import_from_csv, import_from_geojson

        upload = self.validated_data["file"]
        fmt = self.validated_data["format"]
        location_type = self.validated_data.get("location_type")
        parent = self.validated_data.get("parent")

        if fmt == "csv":
            locations = import_from_csv(upload, location_type=location_type, parent=parent, created_by=created_by)
        else:
            content = upload.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8")
            locations = import_from_geojson(content, default_type=location_type, created_by=created_by)
        return locations


def build_feature_collection(locations: Iterable[Location]) -> dict[str, Any]:
    serializer = LocationGeoJSONSerializer(locations, many=True)
    return {
        "type": "FeatureCollection",
        "features": serializer.data,
    }


__all__ = [
    "LocationTypeSerializer",
    "LocationListSerializer",
    "LocationDetailSerializer",
    "LocationTreeSerializer",
    "LocationGeoJSONSerializer",
    "LocationSearchSerializer",
    "LocationNearbySerializer",
    "LocationBulkImportSerializer",
    "build_feature_collection",
]
