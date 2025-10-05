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

from .engine import (
    BaseSearchEngine,
    AuditLogSearchEngine,
    LocationSearchEngine,
    UserSearchEngine,
)
from .serializers import (
    AdvancedSearchRequestSerializer,
    AuditLogSearchRequestSerializer,
    LocationSearchRequestSerializer,
    SearchAnalyticsSerializer,
    SearchClickSerializer,
    SearchRequestSerializer,
    UserSearchRequestSerializer,
)
from .services import (
    get_search_suggestions,
    log_search_execution,
    record_result_click,
)
from .models import SearchQueryLog, SearchResultClick


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


class SearchSuggestionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, query: str, *args, **kwargs) -> Response:
        suggestions = get_search_suggestions(query)
        return Response(suggestions)


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
