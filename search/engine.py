from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any, Iterable

from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.db.models import Count, F, Q

from authentication.models import CustomUser
from audit.models import AuditLog
from locations.models import Location
from permissions.permission_checker import PermissionChecker

from .cache import cache_response, get_cached_response
from .constants import FACET_DEFINITIONS, SEARCH_VECTOR_CONFIG
from .serializers import (
    AuditLogSearchRequestSerializer,
    LocationSearchRequestSerializer,
    SearchResultSerializer,
    UserSearchRequestSerializer,
)


@dataclass
class SearchResult:
    id: str
    type: str
    score: float | None
    summary: dict[str, Any]
    metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "type": self.type,
            "summary": self.summary,
        }
        if self.score is not None:
            payload["score"] = self.score
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


class BaseSearchEngine:
    target: str
    model = None
    serializer_class = SearchResultSerializer

    def __init__(self, *, user, request=None):
        self.user = user
        self.request = request
        self.last_metadata: dict[str, Any] = {"from_cache": False, "duration_ms": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def search(self, serializer) -> dict[str, Any]:
        payload = serializer.validated_data
        cache_key_payload = {
            "payload": payload,
            "target": self.target,
            "user": str(getattr(self.user, "pk", "anonymous")),
        }
        cached = get_cached_response(self.target, cache_key_payload)
        if cached:
            self.last_metadata = {"from_cache": True, "duration_ms": 0}
            return copy.deepcopy(cached)

        start = time.perf_counter()
        queryset = self.build_queryset(payload)
        queryset = self.apply_ordering(queryset, payload)
        facets = self.build_facets(queryset, payload) if payload.get("include_facets", True) else {}
        pagination_conf = serializer.get_pagination(payload)
        page_data, total_count = self.paginate(queryset, pagination_conf)
        results = [self.serialize_result(obj) for obj in page_data]
        duration_ms = int((time.perf_counter() - start) * 1000)

        response = {
            "results": [result.as_dict() for result in results],
            "facets": facets,
            "pagination": {
                "total": total_count,
                "page": pagination_conf["page"],
                "page_size": pagination_conf["page_size"],
            },
            "duration_ms": duration_ms,
        }

        self.last_metadata = {"from_cache": False, "duration_ms": duration_ms}
        cache_response(self.target, cache_key_payload, response, facets=bool(facets))
        return copy.deepcopy(response)

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------
    def build_queryset(self, payload: dict[str, Any]) -> Iterable:
        raise NotImplementedError

    def apply_ordering(self, queryset, payload):
        return queryset

    def paginate(self, queryset, pagination) -> tuple[list[Any], int]:
        page = pagination["page"]
        page_size = pagination["page_size"]
        total = queryset.count()
        start = (page - 1) * page_size
        end = start + page_size
        return list(queryset[start:end]), total

    def build_facets(self, queryset, payload: dict[str, Any]) -> dict[str, Any]:
        facets = {}
        facet_fields = FACET_DEFINITIONS.get(self.target, {})
        for facet_name, field in facet_fields.items():
            buckets = (
                queryset.exclude(**{f"{field}__isnull": True})
                .values(field)
                .annotate(count=Count("id"))
                .order_by("-count")[:10]
            )
            facets[facet_name] = [
                {"value": entry[field], "count": entry["count"]} for entry in buckets
            ]
        return facets

    def serialize_result(self, obj) -> SearchResult:
        raise NotImplementedError

    def build_search_vector(self, *fields: tuple[str, str]):
        vector = None
        for field_name, weight in fields:
            current = SearchVector(field_name, weight=weight)
            vector = current if vector is None else vector + current
        return vector

    def apply_permissions(self, queryset, action: str):
        return queryset


class LocationSearchEngine(BaseSearchEngine):
    target = "locations"
    model = Location

    def build_queryset(self, payload: dict[str, Any]):
        queryset = Location.objects.select_related("type", "parent")
        queryset = self.apply_permissions(queryset, "read")

        query = payload.get("query", "").strip()
        if query:
            vector_config = SEARCH_VECTOR_CONFIG[self.target]["fields"]
            vector = self.build_search_vector(*vector_config)
            search_query = SearchQuery(query)
            queryset = queryset.annotate(rank=SearchRank(vector, search_query)).filter(rank__gte=0.1)
        else:
            queryset = queryset.annotate(rank=F("level"))

        serializer = LocationSearchRequestSerializer(data=payload)
        serializer.is_valid(raise_exception=True)

        queryset = self.apply_filters(queryset, serializer)
        queryset = self.apply_spatial_filters(queryset, serializer)
        return queryset

    def apply_filters(self, queryset, serializer: LocationSearchRequestSerializer):
        data = serializer.validated_data
        if types := data.get("location_types"):
            queryset = queryset.filter(type__code__in=types)
        if levels := data.get("location_levels"):
            queryset = queryset.filter(level__in=levels)
        if not data.get("include_inactive"):
            queryset = queryset.filter(is_active=True)
        if parent := data.get("ancestors_of"):
            queryset = queryset.filter(path__contains=f"{parent}/")
        if descendant := data.get("descendants_of"):
            queryset = queryset.filter(path__startswith=f"{descendant}/")
        filters = data.get("filters", {})
        for field, value in filters.items():
            queryset = queryset.filter(**{field: value})
        return queryset

    def apply_spatial_filters(self, queryset, serializer: LocationSearchRequestSerializer):
        polygon = serializer.get_polygon_geometry()
        if polygon:
            queryset = queryset.filter(geometry__isnull=False, geometry__within=polygon)
        bbox = serializer.get_bbox()
        if bbox:
            min_lon, min_lat, max_lon, max_lat = bbox
            queryset = queryset.filter(
                geometry__isnull=False,
                geometry__bboverlaps=(min_lon, min_lat, max_lon, max_lat),
            )
        radius_filter = serializer.get_radius_filter()
        if radius_filter:
            lon, lat, radius = radius_filter
            reference_point = Point(lon, lat, srid=4326)
            queryset = queryset.filter(center_point__distance_lte=(reference_point, D(m=radius)))
        if route := serializer.get_route_geometry():
            queryset = queryset.filter(geometry__intersects=route)
        if serializer.validated_data.get("nearest_only") and serializer.get_radius_filter():
            lon, lat, radius = serializer.get_radius_filter()
            reference_point = Point(lon, lat, srid=4326)
            queryset = queryset.annotate(
                distance=Distance("center_point", reference_point)
            ).order_by("distance")
        return queryset

    def apply_ordering(self, queryset, payload):
        sort = payload.get("sort") or []
        if sort:
            return queryset.order_by(*sort)
        return queryset.order_by(*SEARCH_VECTOR_CONFIG[self.target]["default_sort"])

    def serialize_result(self, obj) -> SearchResult:
        summary = {
            "name": obj.name,
            "type": getattr(obj.type, "code", None),
            "code": obj.code,
            "level": obj.level,
            "parent": str(obj.parent_id) if obj.parent_id else None,
        }
        metadata = {
            "path": obj.path,
            "population": obj.population,
            "is_active": obj.is_active,
        }
        score = getattr(obj, "rank", None)
        return SearchResult(
            id=str(obj.pk),
            type=self.target,
            score=float(score) if score is not None else None,
            summary=summary,
            metadata={k: v for k, v in metadata.items() if v is not None},
        )

    def apply_permissions(self, queryset, action: str):
        if not self.user or not getattr(self.user, "is_authenticated", False):
            return queryset.none()
        checker = PermissionChecker(self.user)
        accessible = checker.get_accessible_locations(action)
        return queryset.filter(pk__in=accessible.values_list("pk", flat=True))


class UserSearchEngine(BaseSearchEngine):
    target = "users"
    model = CustomUser

    def build_queryset(self, payload: dict[str, Any]):
        queryset = CustomUser.objects.all()
        if not getattr(self.user, "is_staff", False):
            queryset = queryset.filter(is_active=True)

        query = payload.get("query", "").strip()
        if query:
            vector_fields = SEARCH_VECTOR_CONFIG[self.target]["fields"]
            vector = self.build_search_vector(*vector_fields)
            search_query = SearchQuery(query)
            queryset = queryset.annotate(rank=SearchRank(vector, search_query)).filter(rank__gte=0.1)
        else:
            queryset = queryset.annotate(rank=F("date_joined"))

        serializer = UserSearchRequestSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        queryset = self.apply_filters(queryset, serializer)
        return queryset

    def apply_filters(self, queryset, serializer: UserSearchRequestSerializer):
        data = serializer.validated_data
        if departments := data.get("departments"):
            queryset = queryset.filter(department__in=departments)
        if positions := data.get("positions"):
            queryset = queryset.filter(position__in=positions)
        if data.get("is_active") is not None:
            queryset = queryset.filter(is_active=data["is_active"])
        if role_codes := data.get("role_codes"):
            queryset = queryset.filter(user_roles__role__code__in=role_codes).distinct()
        return queryset

    def apply_ordering(self, queryset, payload):
        sort = payload.get("sort") or []
        if sort:
            return queryset.order_by(*sort)
        return queryset.order_by(*SEARCH_VECTOR_CONFIG[self.target]["default_sort"])

    def serialize_result(self, obj) -> SearchResult:
        summary = {
            "username": obj.username,
            "email": obj.email,
            "department": obj.department,
            "position": obj.position,
        }
        metadata = {
            "is_active": obj.is_active,
            "last_login": obj.last_login.isoformat() if obj.last_login else None,
        }
        score = getattr(obj, "rank", None)
        return SearchResult(
            id=str(obj.pk),
            type=self.target,
            score=float(score) if score is not None else None,
            summary=summary,
            metadata={k: v for k, v in metadata.items() if v is not None},
        )


class AuditLogSearchEngine(BaseSearchEngine):
    target = "audit_logs"
    model = AuditLog

    def build_queryset(self, payload: dict[str, Any]):
        queryset = AuditLog.objects.select_related("user", "location")
        serializer = AuditLogSearchRequestSerializer(data=payload)
        serializer.is_valid(raise_exception=True)

        queryset = self.apply_permissions(queryset, "read")

        query = payload.get("query", "").strip()
        if query:
            vector_fields = SEARCH_VECTOR_CONFIG[self.target]["fields"]
            vector = self.build_search_vector(*vector_fields)
            search_query = SearchQuery(query)
            queryset = queryset.annotate(rank=SearchRank(vector, search_query)).filter(rank__gte=0.1)
        else:
            queryset = queryset.annotate(rank=F("created_at"))

        queryset = self.apply_filters(queryset, serializer)
        queryset = self.apply_spatial_filters(queryset, serializer)
        return queryset

    def apply_filters(self, queryset, serializer: AuditLogSearchRequestSerializer):
        data = serializer.validated_data
        if actions := data.get("action_types"):
            queryset = queryset.filter(action__in=actions)
        if data.get("risk_min") is not None:
            queryset = queryset.filter(risk_score__gte=data["risk_min"])
        if data.get("risk_max") is not None:
            queryset = queryset.filter(risk_score__lte=data["risk_max"])
        if data.get("date_from"):
            queryset = queryset.filter(created_at__gte=data["date_from"])
        if data.get("date_to"):
            queryset = queryset.filter(created_at__lte=data["date_to"])
        filters = data.get("filters", {})
        for field, value in filters.items():
            queryset = queryset.filter(**{field: value})
        return queryset

    def apply_spatial_filters(self, queryset, serializer: AuditLogSearchRequestSerializer):
        polygon = serializer.get_polygon_geometry()
        if polygon:
            queryset = queryset.filter(geo_location__isnull=False, geo_location__within=polygon)
        radius_filter = serializer.get_radius_filter()
        if radius_filter:
            lon, lat, radius = radius_filter
            queryset = queryset.filter(geo_location__distance_lte=((lat, lon), radius))
        bbox = serializer.get_bbox()
        if bbox:
            min_lon, min_lat, max_lon, max_lat = bbox
            queryset = queryset.filter(
                geo_location__isnull=False,
                geo_location__bboverlaps=(min_lon, min_lat, max_lon, max_lat),
            )
        route = serializer.get_route_geometry()
        if route:
            queryset = queryset.filter(geo_location__intersects=route)
        return queryset

    def apply_ordering(self, queryset, payload):
        sort = payload.get("sort") or []
        if sort:
            return queryset.order_by(*sort)
        return queryset.order_by(*SEARCH_VECTOR_CONFIG[self.target]["default_sort"])

    def apply_permissions(self, queryset, action: str):
        if not self.user or not getattr(self.user, "is_authenticated", False):
            return queryset.none()
        if hasattr(self.user, "is_superuser") and self.user.is_superuser:
            return queryset
        # Use existing audit security permission: only users with security auditor role
        if not getattr(self.user, "is_staff", False):
            return queryset.filter(user=self.user)
        return queryset

    def serialize_result(self, obj) -> SearchResult:
        summary = {
            "action": obj.action,
            "username": obj.username or (obj.user.get_username() if obj.user else None),
            "resource_type": obj.resource_type,
            "resource_name": obj.resource_name,
        }
        metadata = {
            "risk_score": obj.risk_score,
            "is_suspicious": obj.is_suspicious,
            "created_at": obj.created_at.isoformat() if obj.created_at else None,
            "location": str(obj.location_id) if obj.location_id else None,
        }
        score = getattr(obj, "rank", None)
        return SearchResult(
            id=str(obj.pk),
            type=self.target,
            score=float(score) if score is not None else None,
            summary=summary,
            metadata={k: v for k, v in metadata.items() if v is not None},
        )


__all__ = [
    "AuditLogSearchEngine",
    "BaseSearchEngine",
    "LocationSearchEngine",
    "SearchResult",
    "UserSearchEngine",
]
