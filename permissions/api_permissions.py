from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import SAFE_METHODS, BasePermission

from locations.models import Location

from .permission_checker import PermissionChecker


METHOD_ACTION_MAP: Dict[str, str] = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


class _LocationResolver:
    """Helper for resolving location identifiers from view/request context."""

    def __init__(self, request, view):
        self.request = request
        self.view = view

    def resolve(self) -> Any:
        if hasattr(self.view, "get_permission_location"):
            location = self.view.get_permission_location(self.request)
            if location is not None:
                return location

        parser_context = getattr(self.request, "parser_context", {}) or {}
        view_context = parser_context.get("view") if parser_context else None
        if view_context and hasattr(view_context, "get_permission_location"):
            location = view_context.get_permission_location(self.request)
            if location is not None:
                return location

        location = self._from_kwargs(self.view)
        if location is not None:
            return location

        if parser_context:
            location = self._from_kwargs(parser_context.get("view"))
            if location is not None:
                return location

        explicit = self._from_request_data()
        if explicit is not None:
            return explicit

        return None

    def _from_kwargs(self, view) -> Any:
        if not view:
            return None
        kwargs = getattr(view, "kwargs", {}) or {}
        candidates = [
            getattr(view, "permission_location_kwarg", None),
            "location_id",
            "location_pk",
            "location",
        ]
        for candidate in candidates:
            if candidate and candidate in kwargs:
                return kwargs[candidate]
        return None

    def _from_request_data(self) -> Any:
        data = getattr(self.request, "data", None)
        if isinstance(data, dict):
            for key in ("location", "location_id"):
                if key in data and data[key]:
                    return data[key]
        query_params = getattr(self.request, "query_params", None)
        if query_params:
            for key in ("location", "location_id"):
                value = query_params.get(key)
                if value:
                    return value
        return None


def _resolve_action(request, view) -> Optional[str]:
    if hasattr(view, "get_permission_action"):
        action = view.get_permission_action(request)
        if action:
            return action

    explicit = getattr(view, "permission_action", None)
    if explicit:
        return explicit

    view_action = getattr(view, "action", None)
    if view_action:
        return view_action

    method = getattr(request, "method", None)
    if method:
        return METHOD_ACTION_MAP.get(method.upper())
    return None


def _checker_for_request(request) -> Optional[PermissionChecker]:
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return None
    return PermissionChecker(user)


class HasLocationAccess(BasePermission):
    """Ensure user has location-level permission for the target action."""

    message = _("You do not have access to perform this action for the selected location.")

    def has_permission(self, request, view) -> bool:
        checker = _checker_for_request(request)
        if checker is None:
            return False

        action = _resolve_action(request, view)
        if action is None:
            action = METHOD_ACTION_MAP.get(request.method, "read")

        location_identifier = _LocationResolver(request, view).resolve()
        return checker.can_access_location(location_identifier, action)

    def has_object_permission(self, request, view, obj) -> bool:
        return self.has_permission(request, view)


class HasFieldAccess(HasLocationAccess):
    """Verify both location and field-level permissions for the request."""

    message = _("You do not have field-level access to perform this action.")

    def has_permission(self, request, view) -> bool:
        if not super().has_permission(request, view):
            return False

        action = _resolve_action(request, view) or METHOD_ACTION_MAP.get(request.method, "read")
        checker = _checker_for_request(request)
        if checker is None:
            return False

        model_name = getattr(view, "permission_model_name", None)
        if not model_name:
            return True

        location_identifier = _LocationResolver(request, view).resolve()
        field_matrix = checker.get_accessible_fields(location_identifier, model_name)

        if request.method in SAFE_METHODS:
            return True

        mode = "write"
        rules = field_matrix.get(mode, {})
        allowed: Optional[Iterable[str]] = rules.get("allow")
        restricted: Iterable[str] = rules.get("deny", set()) or []

        payload = getattr(request, "data", {}) or {}
        if not isinstance(payload, dict):
            return True

        keys = set(payload.keys())
        if allowed is not None and not keys.issubset(set(allowed)):
            return False
        if keys.intersection(set(restricted)):
            return False
        return True


class IsLocationAdmin(HasLocationAccess):
    """Grant access only if user has admin privileges for the location."""

    message = _("Administrative access required for this location.")

    def has_permission(self, request, view) -> bool:
        checker = _checker_for_request(request)
        if checker is None:
            return False

        location_identifier = _LocationResolver(request, view).resolve()
        return checker.can_access_location(location_identifier, "admin")


__all__ = [
    "HasLocationAccess",
    "HasFieldAccess",
    "IsLocationAdmin",
]
