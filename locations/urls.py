from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import LocationTypeViewSet, LocationViewSet

router = DefaultRouter()
router.register(r"location-types", LocationTypeViewSet, basename="location-type")
router.register(r"locations", LocationViewSet, basename="location")

app_name = "locations"

urlpatterns = [
    path("", include(router.urls)),
]
