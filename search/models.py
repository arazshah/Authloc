from __future__ import annotations

from typing import Any

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.db import models
from django.utils import timezone

from core.models import TimeStampedModel, UUIDModel, UserTrackedModel


class SearchQueryLogQuerySet(models.QuerySet):
    def for_target(self, target: str):
        return self.filter(target=target)

    def popular_terms(self, limit: int = 10):
        return (
            self.values("normalized_query")
            .annotate(total=models.Count("id"))
            .order_by("-total")[:limit]
        )

    def performance_stats(self):
        return self.aggregate(
            avg_duration=models.Avg("duration_ms"),
            max_duration=models.Max("duration_ms"),
            min_duration=models.Min("duration_ms"),
            total=models.Count("id"),
        )


class SearchQueryLog(UUIDModel, TimeStampedModel, UserTrackedModel):
    class Target(models.TextChoices):
        LOCATIONS = "locations", "Locations"
        USERS = "users", "Users"
        AUDIT_LOGS = "audit_logs", "Audit Logs"
        ADVANCED = "advanced", "Advanced"

    objects = SearchQueryLogQuerySet.as_manager()

    query_text = models.CharField(max_length=500)
    normalized_query = models.CharField(max_length=500, blank=True)
    target = models.CharField(max_length=32, choices=Target.choices)
    vector = SearchVectorField(null=True)
    filters = models.JSONField(default=dict, blank=True)
    result_count = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(default=0)
    executed_at = models.DateTimeField(default=timezone.now)
    request_metadata = models.JSONField(default=dict, blank=True)
    abandoned = models.BooleanField(default=False)
    latency_ms = models.PositiveIntegerField(default=0)
    performance_bucket = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ("-executed_at",)
        indexes = [
            GinIndex(fields=["vector"], name="searchquerylog_vector_gin"),
            models.Index(fields=["target", "executed_at"], name="searchquerylog_target_time"),
            models.Index(fields=["query_text"], name="searchquerylog_query_text_idx"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.target}: {self.query_text[:50]}"


class SearchResultClick(UUIDModel, TimeStampedModel, UserTrackedModel):
    query = models.ForeignKey(SearchQueryLog, related_name="clicks", on_delete=models.CASCADE)
    object_type = models.CharField(max_length=64)
    object_id = models.CharField(max_length=64)
    position = models.PositiveIntegerField(default=0)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["object_type", "created_at"], name="searchclick_object_type_time"),
            models.Index(fields=["query", "position"], name="searchclick_query_position"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.object_type}#{self.object_id} (q={self.query_id})"


class PopularSearchTerm(UUIDModel, TimeStampedModel):
    query_text = models.CharField(max_length=500, unique=True)
    normalized_query = models.CharField(max_length=500, blank=True)
    total_count = models.PositiveIntegerField(default=0)
    last_used_at = models.DateTimeField(auto_now=True)
    average_duration_ms = models.FloatField(default=0.0)
    last_result_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("-total_count", "-last_used_at")
        indexes = [
            models.Index(fields=["total_count", "last_used_at"], name="popularsearchterm_count_time"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.query_text

    @classmethod
    def update_from_log(cls, log: SearchQueryLog) -> "PopularSearchTerm":
        defaults: dict[str, Any] = {
            "normalized_query": log.normalized_query,
            "last_used_at": log.executed_at,
            "last_result_count": log.result_count,
            "total_count": 1,
            "average_duration_ms": log.duration_ms,
        }
        obj, created = cls.objects.get_or_create(query_text=log.query_text, defaults=defaults)
        if created:
            return obj

        updates: dict[str, Any] = {
            "total_count": models.F("total_count") + 1,
            "last_result_count": log.result_count,
            "last_used_at": log.executed_at,
        }
        updates["average_duration_ms"] = models.Case(
            models.When(
                total_count__gt=0,
                then=(models.F("average_duration_ms") * models.F("total_count") + log.duration_ms)
                / (models.F("total_count") + 1),
            ),
            default=log.duration_ms,
            output_field=models.FloatField(),
        )
        cls.objects.filter(pk=obj.pk).update(**updates)
        return cls.objects.get(pk=obj.pk)


__all__ = [
    "SearchQueryLog",
    "SearchResultClick",
    "PopularSearchTerm",
]
