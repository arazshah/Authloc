from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any, Dict

from django.db.models import Avg, Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)

from .engine import (
    BaseSearchEngine,
    AuditLogSearchEngine,
    LocationSearchEngine,
    UserSearchEngine,
)
from .serializers import (
    AdvancedSearchRequestSerializer,
    AuditLogSearchRequestSerializer,
    AdvancedSearchResponseSerializer,
    LocationSearchRequestSerializer,
    SearchAnalyticsSerializer,
    SearchClickSerializer,
    SearchRequestSerializer,
    SearchResponseSerializer,
    SearchSuggestionSerializer,
    UserSearchRequestSerializer,
)
from .services import (
    get_search_suggestions,
    log_search_execution,
    record_result_click,
)
from .models import SearchQueryLog, SearchResultClick


@extend_schema_view(
    post=extend_schema(
        tags=["Search"],
        summary="Execute a search query",
        description=(
            "Executes a contextual search query against the Authloc index. "
            "Supports pagination, facets, sorting, and advanced filters depending on the target engine."
        ),
        responses={
            200: OpenApiResponse(response=SearchResponseSerializer, description="Search results returned successfully."),
            400: OpenApiResponse(description="The submitted payload failed validation."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="The authenticated user is not permitted to access this resource."),
        },
        examples=[
            OpenApiExample(
                "Location search request",
                request_only=True,
                value={
                    "query": "Central Park",
                    "include_facets": True,
                    "pagination": {"page": 1, "page_size": 10},
                    "location_types": ["CITY"],
                },
            ),
            OpenApiExample(
                "Location search response",
                response_only=True,
                value={
                    "results": [
                        {
                            "id": "8f1d8d74-1c5d-4a32-9a7f-8ec239df164f",
                            "type": "locations",
                            "score": 0.87,
                            "summary": {
                                "name": "Central Park",
                                "type": "CITY",
                                "code": "CENPRK",
                                "level": 3,
                                "parent": "f410b9c1-7ee6-48bd-9b13-4f3426dcbf3e",
                            },
                            "metadata": {
                                "path": "country/state/city",
                                "is_active": True,
                            },
                        }
                    ],
                    "facets": {
                        "location_type": [
                            {"value": "CITY", "count": 12},
                            {"value": "DISTRICT", "count": 4},
                        ]
                    },
                    "pagination": {"total": 16, "page": 1, "page_size": 10},
                    "duration_ms": 142,
                },
            ),
        ],
    )
)
class BaseSearchAPIView(APIView):
    permission_classes = [IsAuthenticated]
    engine_class = None
    serializer_class = SearchRequestSerializer
    target = ""

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        engine = self.engine_class(user=request.user, request=request)
        response_payload = engine.search(serializer)
        log_search_execution(
            user=request.user,
            target=self.target,
            payload=copy.deepcopy(serializer.validated_data),
            response=copy.deepcopy(response_payload),
            metadata=copy.deepcopy(engine.last_metadata),
            request=request,
        )
        return Response(response_payload)


class LocationSearchAPIView(BaseSearchAPIView):
    engine_class = LocationSearchEngine
    serializer_class = LocationSearchRequestSerializer
    target = LocationSearchEngine.target


class UserSearchAPIView(BaseSearchAPIView):
    engine_class = UserSearchEngine
    serializer_class = UserSearchRequestSerializer
    target = UserSearchEngine.target


class AuditLogSearchAPIView(BaseSearchAPIView):
    engine_class = AuditLogSearchEngine
    serializer_class = AuditLogSearchRequestSerializer
    target = AuditLogSearchEngine.target


@extend_schema(
    tags=["Search"],
    summary="Get search suggestions",
    description="Provides type-ahead suggestions based on historical search popularity.",
    parameters=[
        OpenApiParameter("query", OpenApiParameter.STR, OpenApiParameter.PATH, description="Partial query text to retrieve suggestions for."),
    ],
    responses={
        200: OpenApiResponse(response=SearchSuggestionSerializer(many=True), description="Suggestions returned successfully."),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
    },
    examples=[
        OpenApiExample(
            "Suggestion response",
            value=[
                {"query": "central park", "normalized_query": "central park", "popularity": 42},
                {"query": "central station", "normalized_query": "central station", "popularity": 18},
            ],
            response_only=True,
        )
    ],
)
class SearchSuggestionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, query: str, *args, **kwargs) -> Response:
        suggestions = get_search_suggestions(query)
        return Response(suggestions)


@extend_schema(
    tags=["Search"],
    summary="Record a result click",
    description="Records an analytics event when a user clicks on a search result item.",
    request=SearchClickSerializer,
    responses={
        201: OpenApiResponse(description="Click recorded successfully."),
        400: OpenApiResponse(description="The submitted payload failed validation."),
        401: OpenApiResponse(description="Authentication required."),
        404: OpenApiResponse(description="Associated search query could not be found."),
    },
    examples=[
        OpenApiExample(
            "Click payload",
            request_only=True,
            value={
                "query_id": "9ae1f930-1b2c-45af-9f8c-113f1f5f4c21",
                "object_type": "locations",
                "object_id": "8f1d8d74-1c5d-4a32-9a7f-8ec239df164f",
                "position": 1,
                "metadata": {"origin": "search_results"},
            },
        )
    ],
)
class SearchClickAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = SearchClickSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        query_log = get_object_or_404(SearchQueryLog, pk=data["query_id"])
        record_result_click(
            query_log=query_log,
            object_type=data["object_type"],
            object_id=data["object_id"],
            position=data["position"],
            metadata=data.get("metadata") or {},
            user=request.user,
        )
        return Response({"status": "recorded"}, status=status.HTTP_201_CREATED)


class SearchAnalyticsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Search"],
        summary="Retrieve search analytics",
        description="Returns aggregate analytics for search activity, including click-through rate and performance buckets.",
        parameters=[
            OpenApiParameter(
                "target",
                OpenApiParameter.STR,
                OpenApiParameter.QUERY,
                required=False,
                description="Optional search target to filter analytics (e.g. `locations`, `users`).",
            ),
            OpenApiParameter(
                "days",
                OpenApiParameter.INT,
                OpenApiParameter.QUERY,
                required=False,
                description="Number of days to look back. Defaults to 7.",
            ),
        ],
        responses={
            200: OpenApiResponse(response=SearchAnalyticsSerializer, description="Analytics payload returned."),
            401: OpenApiResponse(description="Authentication required."),
        },
        examples=[
            OpenApiExample(
                "Analytics response",
                response_only=True,
                value={
                    "total_queries": 128,
                    "average_latency_ms": 215.4,
                    "abandonment_rate": 0.12,
                    "click_through_rate": 0.63,
                    "top_queries": [
                        {"query": "central park", "normalized_query": "central park", "popularity": 24},
                        {"query": "north zone", "normalized_query": "north zone", "popularity": 18},
                    ],
                    "performance_buckets": {"fast": 80, "moderate": 35, "slow": 13},
                },
            )
        ],
    )
    def get(self, request: Request, *args, **kwargs) -> Response:
        target = request.query_params.get("target")
        try:
            days = int(request.query_params.get("days", 7))
        except ValueError:
            days = 7

        queryset = SearchQueryLog.objects.all()
        if target:
            queryset = queryset.filter(target=target)
        if days > 0:
            since = timezone.now() - timedelta(days=days)
            queryset = queryset.filter(executed_at__gte=since)

        total_queries = queryset.count()
        if total_queries == 0:
            payload = {
                "total_queries": 0,
                "average_latency_ms": 0.0,
                "abandonment_rate": 0.0,
                "click_through_rate": 0.0,
                "top_queries": [],
                "performance_buckets": {},
            }
        else:
            aggregates = queryset.aggregate(avg_latency=Avg("latency_ms"))
            abandonments = queryset.filter(result_count=0).count()
            abandonment_rate = abandonments / total_queries
            clicks = SearchResultClick.objects.filter(query__in=queryset.values("pk")).count()
            click_through_rate = clicks / total_queries if total_queries else 0.0
            top_queries = list(
                queryset.values("query_text", "normalized_query")
                .annotate(total=Count("id"))
                .order_by("-total", "-executed_at")[:10]
            )
            top_payload = [
                {
                    "query": item["query_text"],
                    "normalized_query": item["normalized_query"],
                    "popularity": item["total"],
                }
                for item in top_queries
            ]
            bucket_map = {
                entry["performance_bucket"] or "unknown": entry["count"]
                for entry in queryset.values("performance_bucket").annotate(count=Count("id"))
            }
            payload = {
                "total_queries": total_queries,
                "average_latency_ms": float(aggregates.get("avg_latency") or 0.0),
                "abandonment_rate": float(abandonment_rate),
                "click_through_rate": float(click_through_rate),
                "top_queries": top_payload,
                "performance_buckets": bucket_map,
            }

        serializer = SearchAnalyticsSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class AdvancedSearchAPIView(APIView):
    permission_classes = [IsAuthenticated]

    ENGINE_MAP: Dict[str, tuple[type[BaseSearchEngine], type[SearchRequestSerializer]]] = {
        "locations": (LocationSearchEngine, LocationSearchRequestSerializer),
        "users": (UserSearchEngine, UserSearchRequestSerializer),
        "audit_logs": (AuditLogSearchEngine, AuditLogSearchRequestSerializer),
    }

    @extend_schema(
        tags=["Search"],
        summary="Execute a multi-target search",
        description="Runs a federated search across multiple targets (locations, users, audit logs) and aggregates the results.",
        request=AdvancedSearchRequestSerializer,
        responses={
            200: OpenApiResponse(response=AdvancedSearchResponseSerializer, description="Aggregated search results returned."),
            400: OpenApiResponse(description="Payload failed validation."),
            401: OpenApiResponse(description="Authentication required."),
        },
        examples=[
            OpenApiExample(
                "Advanced search request",
                request_only=True,
                value={
                    "query": "central",
                    "targets": ["locations", "users"],
                    "include_facets": False,
                    "filters": {
                        "users": {"departments": ["Security"]},
                    },
                    "pagination": {"page": 1, "page_size": 5},
                },
            ),
            OpenApiExample(
                "Advanced search response",
                response_only=True,
                value={
                    "results": {
                        "locations": [
                            {
                                "id": "8f1d8d74-1c5d-4a32-9a7f-8ec239df164f",
                                "type": "locations",
                                "summary": {"name": "Central Park", "type": "CITY", "code": "CENPRK"},
                            }
                        ],
                        "users": [
                            {
                                "id": "5c3f7e10-9d3c-4c5f-9b5f-5f5e9d9f1a0b",
                                "type": "users",
                                "summary": {
                                    "username": "jane.doe",
                                    "email": "jane.doe@example.com",
                                    "department": "Security",
                                },
                            }
                        ],
                    },
                    "facets": {
                        "locations": {"location_type": [{"value": "CITY", "count": 8}]},
                        "users": {},
                    },
                    "duration_ms": 380,
                },
            ),
        ],
    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = AdvancedSearchRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        targets = serializer.get_targets()
        pagination = serializer.get_pagination()
        aggregated_results: dict[str, Any] = {}
        aggregated_facets: dict[str, Any] = {}
        total_duration = 0

        for target in targets:
            config = self.ENGINE_MAP.get(target)
            if not config:
                continue
            engine_class, serializer_class = config
            engine_serializer = serializer_class(
                data=self._build_target_payload(target, data, pagination)
            )
            engine_serializer.is_valid(raise_exception=True)
            engine = engine_class(user=request.user, request=request)
            result_payload = engine.search(engine_serializer)
            aggregated_results[target] = result_payload["results"]
            aggregated_facets[target] = result_payload.get("facets", {})
            total_duration += result_payload.get("duration_ms", 0)
            log_search_execution(
                user=request.user,
                target=target,
                payload=copy.deepcopy(engine_serializer.validated_data),
                response=copy.deepcopy(result_payload),
                metadata=copy.deepcopy(engine.last_metadata),
                request=request,
            )

        combined_response = {
            "results": aggregated_results,
            "facets": aggregated_facets,
            "duration_ms": total_duration,
        }

        log_search_execution(
            user=request.user,
            target="advanced",
            payload=copy.deepcopy(data),
            response=copy.deepcopy(combined_response),
            metadata={"duration_ms": total_duration, "from_cache": False},
            request=request,
        )
        return Response(combined_response, status=status.HTTP_200_OK)

    def _build_target_payload(
        self,
        target: str,
        data: dict[str, Any],
        pagination: dict[str, int],
    ) -> dict[str, Any]:
        payload = {
            "query": data.get("query", ""),
            "include_facets": data.get("include_facets", False),
            "pagination": pagination,
        }
        filters = data.get("filters", {})
        target_filters = filters.get(target, {}) if isinstance(filters, dict) else {}
        payload.update(target_filters)
        return payload


__all__ = [
    "AdvancedSearchAPIView",
    "AuditLogSearchAPIView",
    "LocationSearchAPIView",
    "SearchSuggestionAPIView",
    "UserSearchAPIView",
]
