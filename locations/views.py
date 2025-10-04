from __future__ import annotations

from collections import defaultdict

from django.db.models import Prefetch
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .filters import LocationFilter, LocationTypeFilter
from .models import Location, LocationType
from .serializers import (
    LocationBulkImportSerializer,
    LocationDetailSerializer,
    LocationGeoJSONSerializer,
    LocationListSerializer,
    LocationNearbySerializer,
    LocationSearchSerializer,
    LocationTreeSerializer,
    LocationTypeSerializer,
    build_feature_collection,
)
from .utils import find_locations_within_radius


class LocationTypeViewSet(viewsets.ModelViewSet):
    queryset = LocationType.objects.all().order_by("level", "name")
    serializer_class = LocationTypeSerializer
    permission_classes = [IsAuthenticated]
    filterset_class = LocationTypeFilter
    search_fields = ["name", "name_fa", "code"]
    ordering_fields = ["name", "level", "created_at"]
    ordering = ["level", "name"]


class LocationViewSet(viewsets.ModelViewSet):
    queryset = (
        Location.objects.select_related("type", "parent")
        .prefetch_related(Prefetch("children", queryset=Location.objects.select_related("type")))
        .order_by("path")
    )
    permission_classes = [IsAuthenticated]
    filterset_class = LocationFilter
    search_fields = ["name", "name_fa", "code", "postal_code"]
    ordering_fields = [
        "name",
        "name_fa",
        "code",
        "level",
        "population",
        "created_at",
        "updated_at",
    ]
    ordering = ["path"]

    def get_serializer_class(self):
        if self.action in {"list", "children", "ancestors", "descendants", "nearby", "search"}:
            return LocationListSerializer
        if self.action == "tree":
            return LocationTreeSerializer
        if self.action == "geojson":
            return LocationGeoJSONSerializer
        return LocationDetailSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        return context

    def perform_create(self, serializer: LocationDetailSerializer) -> Location:
        user = self.request.user if self.request and self.request.user.is_authenticated else None
        return serializer.save(created_by=user, updated_by=user)

    def perform_update(self, serializer: LocationDetailSerializer) -> Location:
        user = self.request.user if self.request and self.request.user.is_authenticated else None
        return serializer.save(updated_by=user)

    @action(detail=False, methods=["get"], url_path="tree")
    def tree(self, request: Request, *args, **kwargs) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        include_inactive = request.query_params.get("include_inactive") == "true"
        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        nodes = list(queryset)
        child_map = defaultdict(list)
        for location in nodes:
            if location.parent_id:
                child_map[location.parent_id].append(location)

        roots = [location for location in nodes if location.parent_id is None]
        serializer = LocationTreeSerializer(
            roots,
            many=True,
            context={**self.get_serializer_context(), "child_map": child_map},
        )
        return Response(serializer.data)

    @action(detail=True, methods=["get"], url_path="children")
    def children(self, request: Request, pk=None) -> Response:  # noqa: D401 - DRF signature
        location = self.get_object()
        queryset = location.children.select_related("type", "parent").all()
        page = self.paginate_queryset(queryset)
        serializer = LocationListSerializer(page or queryset, many=True, context=self.get_serializer_context())
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    @action(detail=True, methods=["get"], url_path="ancestors")
    def ancestors(self, request: Request, pk=None) -> Response:  # noqa: D401 - DRF signature
        location = self.get_object()
        queryset = location.get_ancestors(include_self=False).select_related("type", "parent")
        serializer = LocationListSerializer(queryset, many=True, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["get"], url_path="descendants")
    def descendants(self, request: Request, pk=None) -> Response:  # noqa: D401 - DRF signature
        location = self.get_object()
        queryset = location.get_descendants(include_self=False).select_related("type", "parent")
        page = self.paginate_queryset(queryset)
        serializer = LocationListSerializer(page or queryset, many=True, context=self.get_serializer_context())
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="search")
    def search(self, request: Request, *args, **kwargs) -> Response:
        serializer = LocationSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        queryset = self.get_queryset()

        if "name" in data:
            queryset = queryset.filter(name__icontains=data["name"])
        if "name_fa" in data:
            queryset = queryset.filter(name_fa__icontains=data["name_fa"])
        if "code" in data:
            queryset = queryset.filter(code__icontains=data["code"])
        if "type" in data:
            queryset = queryset.filter(type_id=data["type"])
        if "type_code" in data:
            queryset = queryset.filter(type__code__iexact=data["type_code"])
        if "parent" in data:
            queryset = queryset.filter(parent_id=data["parent"])
        if "level" in data:
            queryset = queryset.filter(level=data["level"])
        if "population_min" in data:
            queryset = queryset.filter(population__gte=data["population_min"])
        if "population_max" in data:
            queryset = queryset.filter(population__lte=data["population_max"])
        if "metadata" in data:
            for key, value in data["metadata"].items():
                queryset = queryset.filter(**{f"metadata__{key}": value})
        if "bbox" in data:
            min_lon, min_lat, max_lon, max_lat = data["bbox"]
            from django.contrib.gis.geos import Polygon

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
            queryset = queryset.filter(geometry__isnull=False, geometry__intersects=polygon)

        if not data.get("include_children"):
            queryset = queryset.filter(is_active=True)

        queryset = queryset.distinct()

        page = self.paginate_queryset(queryset)
        serializer = LocationListSerializer(page or queryset, many=True, context=self.get_serializer_context())
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="nearby")
    def nearby(self, request: Request, *args, **kwargs) -> Response:
        serializer = LocationNearbySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        point = serializer.to_point()
        radius = serializer.validated_data["radius_meters"]
        type_code = serializer.validated_data.get("type_code")
        limit = serializer.validated_data.get("limit", 10)

        queryset = self.get_queryset()
        if type_code:
            queryset = queryset.filter(type__code=type_code)

        locations = find_locations_within_radius(point, radius, queryset=queryset).order_by("distance")[:limit]
        serializer = LocationListSerializer(locations, many=True, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="bulk-import")
    def bulk_import(self, request: Request, *args, **kwargs) -> Response:
        serializer = LocationBulkImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user if request.user.is_authenticated else None
        locations = serializer.save(created_by=user)
        data = LocationDetailSerializer(locations, many=True, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], url_path="geojson")
    def geojson(self, request: Request, *args, **kwargs) -> Response:
        queryset = self.filter_queryset(self.get_queryset()).filter(geometry__isnull=False)
        return Response(build_feature_collection(queryset))
