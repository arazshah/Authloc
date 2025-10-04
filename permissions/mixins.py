from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from rest_framework.request import Request

from .permission_checker import PermissionChecker


class FieldPermissionMixin:
    """Automatically filters serializer fields based on field-level permissions."""

    permission_model_name: Optional[str] = None

    def get_permission_model_name(self) -> Optional[str]:
        return self.permission_model_name

    def get_permission_location(self, request: Request) -> Any:
        view = getattr(self, "view", None) or getattr(self, "context", {}).get("view")
        if view and hasattr(view, "get_permission_location"):
            return view.get_permission_location(request)
        if view and hasattr(view, "kwargs"):
            return view.kwargs.get("location_id") or view.kwargs.get("location")
        return None

    def get_permission_checker(self, request: Request) -> Optional[PermissionChecker]:
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return None
        return PermissionChecker(user)

    def filter_fields_by_permissions(
        self,
        fields: Dict[str, Any],
        *,
        request: Request,
        action: str,
    ) -> Dict[str, Any]:
        model_name = self.get_permission_model_name()
        if not model_name:
            return fields

        checker = self.get_permission_checker(request)
        if checker is None:
            return {name: field for name, field in fields.items() if not getattr(field, "required", False)}

        location = self.get_permission_location(request)
        matrix = checker.get_accessible_fields(location, model_name)
        mode = "write" if action != "read" else "read"
        rules = matrix.get(mode, {})
        allowed: Optional[Iterable[str]] = rules.get("allow")
        restricted: Iterable[str] = rules.get("deny", set()) or []

        filtered = {}
        for name, field in fields.items():
            if allowed is not None and name not in allowed:
                continue
            if name in restricted:
                continue
            filtered[name] = field
        return filtered

    # ------------------------------------------------------------------
    # DRF Serializer hooks
    # ------------------------------------------------------------------
    def get_fields(self):  # type: ignore[override]
        fields = super().get_fields()  # type: ignore[misc]
        request = self.context.get("request") if hasattr(self, "context") else None
        if request is None:
            return fields

        view = self.context.get("view") if hasattr(self, "context") else None
        action = getattr(view, "action", "read") if view else "read"
        if getattr(request, "method", "GET").upper() not in {"GET", "HEAD", "OPTIONS"}:
            action = "write"
        filtered = self.filter_fields_by_permissions(fields, request=request, action=action)
        return filtered

    def to_representation(self, instance):  # type: ignore[override]
        data = super().to_representation(instance)
        request = self.context.get("request") if hasattr(self, "context") else None
        if request is None:
            return data
        view = self.context.get("view") if hasattr(self, "context") else None
        action = getattr(view, "action", "read") if view else "read"
        location = self.get_permission_location(request)
        checker = self.get_permission_checker(request)
        if checker is None:
            return data
        model_name = self.get_permission_model_name()
        if not model_name:
            return data
        return checker.filter_fields(data, location, model_name, action=action)
