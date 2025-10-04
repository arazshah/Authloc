from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import RoleAssignmentRequestViewSet, RoleViewSet, UserRoleViewSet

router = DefaultRouter()
router.register(r"roles", RoleViewSet, basename="role")
router.register(r"user-roles", UserRoleViewSet, basename="user-role")
router.register(r"role-requests", RoleAssignmentRequestViewSet, basename="role-request")

app_name = "permissions"

urlpatterns = [
    path("", include(router.urls)),
]
