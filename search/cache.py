"""Caching helpers for the search application."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.core.cache import caches

from core.cache_utils import cache_manager, cache_key_generator
from search.constants import (
    SEARCH_FACET_CACHE_TIMEOUT,
    SEARCH_QUERY_CACHE_TIMEOUT,
    SEARCH_SUGGESTION_CACHE_TIMEOUT,
)

CACHE_ALIAS = "api_cache"


def _normalize_payload(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return digest


def _cache() -> Any:
    return caches[CACHE_ALIAS]


def get_search_cache_key(namespace: str, payload: dict[str, Any]) -> str:
    fingerprint = _normalize_payload(payload)
    return cache_key_generator.generate_cache_key("search", namespace, fingerprint)


def get_cached_response(namespace: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    cache_key = get_search_cache_key(namespace, payload)
    return _cache().get(cache_key)


def cache_response(namespace: str, payload: dict[str, Any], data: dict[str, Any], *, facets: bool = False) -> None:
    cache_key = get_search_cache_key(namespace, payload)
    timeout = SEARCH_FACET_CACHE_TIMEOUT if facets else SEARCH_QUERY_CACHE_TIMEOUT
    _cache().set(cache_key, data, timeout=timeout)


def get_cached_suggestions(prefix: str) -> list[dict[str, Any]] | None:
    cache_key = cache_key_generator.generate_cache_key("search", "suggestions", prefix.lower())
    return cache_manager.cache.get(cache_key)


def cache_suggestions(prefix: str, suggestions: list[dict[str, Any]]) -> None:
    cache_key = cache_key_generator.generate_cache_key("search", "suggestions", prefix.lower())
    cache_manager.cache.set(cache_key, suggestions, timeout=SEARCH_SUGGESTION_CACHE_TIMEOUT)
