from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .cache import cache_suggestions, get_cached_suggestions
from .models import PopularSearchTerm, SearchQueryLog, SearchResultClick


def normalize_query(query: str | None) -> str:
    if not query:
        return ""
    return " ".join(query.strip().lower().split())


def compute_performance_bucket(duration_ms: int | float | None) -> str:
    if duration_ms is None:
        return "unknown"
    if duration_ms < 200:
        return "fast"
    if duration_ms < 500:
        return "moderate"
    if duration_ms < 1000:
        return "slow"
    return "very_slow"


def _serialize_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, list | tuple):  # type: ignore[redundant-expr]
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize_value(val) for key, val in value.items()}
    return str(value)


def _serialize_filters(payload: dict[str, Any]) -> dict[str, Any]:
    excluded_keys = {"query", "pagination"}
    return {key: _serialize_value(val) for key, val in payload.items() if key not in excluded_keys}


def _build_request_metadata(request: HttpRequest | None, metadata: dict[str, Any]) -> dict[str, Any]:
    if not request:
        return metadata
    headers = request.headers if hasattr(request, "headers") else {}
    request_data = {
        "path": request.get_full_path() if hasattr(request, "get_full_path") else "",
        "method": request.method,
        "remote_addr": request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR"),
        "user_agent": headers.get("User-Agent") if headers else request.META.get("HTTP_USER_AGENT"),
    }
    request_data.update(metadata)
    return request_data


def log_search_execution(
    *,
    user,
    target: str,
    payload: dict[str, Any],
    response: dict[str, Any],
    metadata: dict[str, Any],
    request: HttpRequest | None = None,
) -> SearchQueryLog:
    query_text = payload.get("query", "") or ""
    normalized = normalize_query(query_text)
    filters_payload = _serialize_filters(payload)
    pagination = response.get("pagination", {})
    result_count = int(pagination.get("total", len(response.get("results", []))))
    duration_ms = int(metadata.get("duration_ms", 0) or 0)
    log_kwargs = {
        "query_text": query_text,
        "normalized_query": normalized,
        "target": target,
        "filters": filters_payload,
        "result_count": result_count,
        "duration_ms": duration_ms,
        "latency_ms": duration_ms,
        "performance_bucket": compute_performance_bucket(duration_ms),
        "abandoned": False,
        "request_metadata": _build_request_metadata(
            request,
            {
                "from_cache": metadata.get("from_cache", False),
                "facets": bool(response.get("facets")),
            },
        ),
    }
    if getattr(user, "is_authenticated", False):
        log_kwargs["created_by"] = user
        log_kwargs["updated_by"] = user
    with transaction.atomic():
        log = SearchQueryLog.objects.create(**log_kwargs)
    return log


def record_result_click(
    *,
    query_log: SearchQueryLog,
    object_type: str,
    object_id: str,
    position: int,
    metadata: dict[str, Any] | None = None,
    user=None,
) -> SearchResultClick:
    click_kwargs = {
        "query": query_log,
        "object_type": object_type,
        "object_id": object_id,
        "position": position,
        "metadata": metadata or {},
    }
    if getattr(user, "is_authenticated", False):
        click_kwargs["created_by"] = user
        click_kwargs["updated_by"] = user
    return SearchResultClick.objects.create(**click_kwargs)


def get_search_suggestions(prefix: str, *, limit: int = 10) -> list[dict[str, Any]]:
    normalized = normalize_query(prefix)
    if not normalized:
        return []

    cached = get_cached_suggestions(normalized)
    if cached is not None:
        return cached

    suggestions: list[dict[str, Any]] = []
    popular_qs = (
        PopularSearchTerm.objects.filter(normalized_query__startswith=normalized)
        .order_by("-total_count", "-last_used_at")
        .values("query_text", "normalized_query", "total_count")[: limit]
    )
    suggestions.extend(
        {
            "query": item["query_text"],
            "normalized_query": item["normalized_query"],
            "popularity": item["total_count"],
        }
        for item in popular_qs
    )

    if len(suggestions) < limit:
        remaining = limit - len(suggestions)
        log_qs = (
            SearchQueryLog.objects.filter(normalized_query__startswith=normalized)
            .order_by("-executed_at")
            .values("query_text", "normalized_query")[: remaining * 2]
        )
        existing = {item["query"] for item in suggestions}
        for item in log_qs:
            if item["query_text"] in existing:
                continue
            suggestions.append(
                {
                    "query": item["query_text"],
                    "normalized_query": item["normalized_query"],
                    "popularity": 0,
                }
            )
            if len(suggestions) >= limit:
                break

    cache_suggestions(normalized, suggestions)
    return suggestions[:limit]


__all__ = [
    "compute_performance_bucket",
    "get_search_suggestions",
    "log_search_execution",
    "normalize_query",
    "record_result_click",
]
