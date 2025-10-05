from __future__ import annotations

from datetime import timedelta

from django.contrib import admin
from django.utils import timezone

from .models import PopularSearchTerm, SearchQueryLog, SearchResultClick


@admin.register(SearchQueryLog)
class SearchQueryLogAdmin(admin.ModelAdmin):
    list_display = (
        "query_text",
        "target",
        "result_count",
        "duration_ms",
        "performance_bucket",
        "executed_at",
    )
    list_filter = (
        "target",
        "performance_bucket",
        "executed_at",
    )
    search_fields = (
        "query_text",
        "normalized_query",
        "request_metadata",
    )
    readonly_fields = (
        "query_text",
        "normalized_query",
        "target",
        "filters",
        "result_count",
        "duration_ms",
        "executed_at",
        "request_metadata",
        "performance_bucket",
        "latency_ms",
        "abandoned",
        "created_by",
        "updated_by",
        "created_at",
        "updated_at",
    )
    date_hierarchy = "executed_at"
    ordering = ("-executed_at",)
    actions = [
        "mark_as_abandoned",
        "purge_older_than_30_days",
    ]

    def mark_as_abandoned(self, request, queryset):
        updated = queryset.update(abandoned=True)
        self.message_user(request, f"Marked {updated} queries as abandoned.")

    mark_as_abandoned.short_description = "Mark selected queries as abandoned"  # type: ignore[attr-defined]

    def purge_older_than_30_days(self, request, queryset):
        cutoff = timezone.now() - timedelta(days=30)
        deleted, _ = queryset.filter(executed_at__lt=cutoff).delete()
        self.message_user(request, f"Deleted {deleted} older query logs.")

    purge_older_than_30_days.short_description = "Delete selected queries older than 30 days"  # type: ignore[attr-defined]

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        queryset = self.get_queryset(request)
        summary = {
            "total_queries": queryset.count(),
            "average_latency": queryset.aggregate(avg_latency=admin.models.Avg("latency_ms"))["avg_latency"]
            or 0,
            "abandoned": queryset.filter(abandoned=True).count(),
        }
        extra_context["search_summary"] = summary
        return super().changelist_view(request, extra_context=extra_context)


@admin.register(SearchResultClick)
class SearchResultClickAdmin(admin.ModelAdmin):
    list_display = (
        "object_type",
        "object_id",
        "position",
        "query",
        "created_at",
    )
    list_filter = ("object_type", "created_at")
    search_fields = ("object_type", "object_id")
    readonly_fields = (
        "query",
        "object_type",
        "object_id",
        "position",
        "metadata",
        "created_by",
        "updated_by",
        "created_at",
        "updated_at",
    )
    ordering = ("-created_at",)


@admin.register(PopularSearchTerm)
class PopularSearchTermAdmin(admin.ModelAdmin):
    list_display = (
        "query_text",
        "total_count",
        "average_duration_ms",
        "last_used_at",
    )
    search_fields = ("query_text", "normalized_query")
    ordering = ("-total_count",)
    readonly_fields = (
        "query_text",
        "normalized_query",
        "total_count",
        "average_duration_ms",
        "last_used_at",
        "created_at",
        "updated_at",
    )

    actions = ["reset_counts"]

    def reset_counts(self, request, queryset):
        updated = queryset.update(total_count=0, average_duration_ms=0.0)
        self.message_user(request, f"Reset counts for {updated} search terms.")

    reset_counts.short_description = "Reset popularity counters"  # type: ignore[attr-defined]
