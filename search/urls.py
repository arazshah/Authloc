from __future__ import annotations

from django.urls import path

from .views import (
    AdvancedSearchAPIView,
    AuditLogSearchAPIView,
    LocationSearchAPIView,
    SearchAnalyticsAPIView,
    SearchClickAPIView,
    SearchSuggestionAPIView,
    UserSearchAPIView,
)

app_name = "search"

urlpatterns = [
    path("locations/", LocationSearchAPIView.as_view(), name="locations"),
    path("users/", UserSearchAPIView.as_view(), name="users"),
    path("audit-logs/", AuditLogSearchAPIView.as_view(), name="audit-logs"),
    path("suggestions/<str:query>/", SearchSuggestionAPIView.as_view(), name="suggestions"),
    path("advanced/", AdvancedSearchAPIView.as_view(), name="advanced"),
    path("clicks/", SearchClickAPIView.as_view(), name="clicks"),
    path("analytics/", SearchAnalyticsAPIView.as_view(), name="analytics"),
]
