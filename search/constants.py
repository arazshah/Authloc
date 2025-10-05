"""Constants and configuration helpers for the search application."""

from __future__ import annotations

SEARCH_QUERY_CACHE_TIMEOUT = 120  # seconds
SEARCH_SUGGESTION_CACHE_TIMEOUT = 300
SEARCH_FACET_CACHE_TIMEOUT = 600
SEARCH_ANALYTICS_CACHE_TIMEOUT = 60

SEARCH_VECTOR_CONFIG = {
    "locations": {
        "fields": [
            ("name", "A"),
            ("code", "B"),
            ("description", "C"),
        ],
        "default_sort": ["-rank", "name"],
    },
    "users": {
        "fields": [
            ("username", "A"),
            ("email", "A"),
            ("department", "B"),
            ("position", "B"),
        ],
        "default_sort": ["-rank", "username"],
    },
    "audit_logs": {
        "fields": [
            ("username", "A"),
            ("resource_name", "A"),
            ("action", "B"),
            ("request_path", "B"),
            ("ip_address", "C"),
        ],
        "default_sort": ["-created_at"],
    },
}

FACET_DEFINITIONS = {
    "locations": {
        "type": "type__code",
        "level": "level",
        "is_active": "is_active",
    },
    "users": {
        "department": "department",
        "position": "position",
        "is_active": "is_active",
    },
    "audit_logs": {
        "action": "action",
        "resource_type": "resource_type",
        "risk_bucket": "risk_bucket",
        "is_suspicious": "is_suspicious",
    },
}
