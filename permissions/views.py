"""Viewsets for the `permissions` app RBAC endpoints."""
from __future__ import annotations

from typing import Any, Dict, List

from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from audit.utils import record_permission_audit
from locations.serializers import LocationListSerializer

from .api_permissions import HasFieldAccess, HasLocationAccess, IsLocationAdmin
from .models import FieldPermission, LocationAccess, Role, RoleAssignmentRequest, UserRole
from .permission_checker import PermissionChecker
from .serializers import (
    BulkRoleAssignmentRequestSerializer,
    EffectivePermissionQuerySerializer,
    EffectivePermissionResponseSerializer,
    FieldPermissionSerializer,
    LocationAccessBulkGrantSerializer,
    LocationAccessBulkRevokeSerializer,
    LocationAccessCheckSerializer,
    LocationAccessGrantSerializer,
    LocationAccessRevokeSerializer,
    LocationAccessSerializer,
    MyRolesQuerySerializer,
    RoleAssignmentApprovalSerializer,
    RoleAssignmentPayloadSerializer,
    RoleAssignmentRequestSerializer,
    RoleSerializer,
    UserRoleSerializer,
)
from .services import (
    assign_role_to_user,
    bulk_assign_roles,
    bulk_grant_location_access,
    bulk_revoke_location_access,
    check_location_access,
    create_role_assignment_request,
    grant_location_access,
    revoke_location_access,
)
from .utils import get_effective_permissions, get_user_roles


class RoleViewSet(viewsets.ModelViewSet):
    """CRUD operations for `Role` instances with assignment helpers."""

    queryset = Role.objects.select_related("parent_role")
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        return context

    def perform_create(self, serializer: RoleSerializer) -> None:
        user = self.request.user if self.request.user.is_authenticated else None
        serializer.save(created_by=user, updated_by=user)

    def perform_update(self, serializer: RoleSerializer) -> None:
        user = self.request.user if self.request.user.is_authenticated else None
        serializer.save(updated_by=user)

    def perform_destroy(self, instance: Role) -> None:
        if instance.is_system_role:
            raise ValidationError("System roles cannot be deleted.")
        super().perform_destroy(instance)

    @action(detail=True, methods=["post"], url_path="assign-to-user")
    def assign_to_user(self, request: Request, pk: str | None = None) -> Response:
        role = self.get_object()
        serializer = RoleAssignmentPayloadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        assigned_by = request.user if request.user.is_authenticated else None
        user_role = assign_role_to_user(
            role=role,
            user=payload["user"],
            location=payload.get("location"),
            valid_from=payload.get("valid_from"),
            valid_until=payload.get("valid_until"),
            assigned_by=assigned_by,
            reason=payload.get("reason", ""),
            metadata=payload.get("metadata"),
        )
        data = UserRoleSerializer(user_role, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="bulk-assign")
    def bulk_assign(self, request: Request) -> Response:
        serializer = BulkRoleAssignmentRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.validated_data["role"]
        assignments = serializer.validated_data["assignments"]
        assigned_by = request.user if request.user.is_authenticated else None
        created_roles = bulk_assign_roles(role=role, assignments=assignments, assigned_by=assigned_by)
        data = UserRoleSerializer(created_roles, many=True, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_200_OK)


class UserRoleViewSet(viewsets.ModelViewSet):
    """CRUD operations for `UserRole` objects and helper endpoints."""

    queryset = UserRole.objects.select_related("user", "role", "location", "assigned_by")
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        return context

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        assigned_by = request.user if request.user.is_authenticated else None
        user_role = assign_role_to_user(
            role=payload["role"],
            user=payload["user"],
            location=payload.get("location"),
            valid_from=payload.get("valid_from"),
            valid_until=payload.get("valid_until"),
            assigned_by=assigned_by,
            reason=payload.get("reason", ""),
            metadata=payload.get("metadata"),
        )
        output = self.get_serializer(user_role)
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=False, methods=["get"], url_path="my-roles")
    def my_roles(self, request: Request) -> Response:
        serializer = MyRolesQuerySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data.get("location")
        roles = get_user_roles(request.user, location=location)
        data = self.get_serializer(roles, many=True).data
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_path="effective-permissions")
    def effective_permissions(self, request: Request) -> Response:
        serializer = EffectivePermissionQuerySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data.get("location")
        permissions = get_effective_permissions(request.user, location=location)
        response_serializer = EffectivePermissionResponseSerializer(
            {"permissions": permissions, "generated_at": timezone.now()}
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class LocationAccessViewSet(viewsets.ModelViewSet):
    """Manage location access entries with inheritance-aware grants."""

    queryset = LocationAccess.objects.select_related("user", "role", "location", "granted_by")
    serializer_class = LocationAccessSerializer
    permission_classes = [IsAuthenticated, HasLocationAccess]

    permission_action_map: Dict[str, List[type]] = {
        "create": [IsAuthenticated, IsLocationAdmin],
        "update": [IsAuthenticated, IsLocationAdmin],
        "partial_update": [IsAuthenticated, IsLocationAdmin],
        "destroy": [IsAuthenticated, IsLocationAdmin],
        "grant": [IsAuthenticated, IsLocationAdmin],
        "bulk_grant": [IsAuthenticated, IsLocationAdmin],
        "revoke": [IsAuthenticated, IsLocationAdmin],
        "bulk_revoke": [IsAuthenticated, IsLocationAdmin],
        "my_locations": [IsAuthenticated, HasLocationAccess],
        "check": [IsAuthenticated, HasLocationAccess],
    }

    def get_permissions(self):  # pragma: no cover - DRF hook
        classes = self.permission_action_map.get(self.action, self.permission_classes)
        return [permission() for permission in classes]

    def get_permission_action(self, request: Request) -> str:
        if self.action in {"create", "update", "partial_update", "destroy", "grant", "bulk_grant", "revoke", "bulk_revoke"}:
            return "admin"
        return "read"

    def get_permission_location(self, request: Request):  # pragma: no cover - DRF hook
        if self.action in {"retrieve", "update", "partial_update", "destroy"}:
            instance = getattr(self, "_cached_instance", None)
            if instance is None:
                instance = self.get_object()
                self._cached_instance = instance
            return instance.location_id

        data = request.data if isinstance(request.data, dict) else {}
        if data.get("location"):
            return data["location"]

        if self.action in {"check", "my_locations"}:
            location_param = request.query_params.get("location")
            if location_param:
                return location_param
        return None

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        context.setdefault("view", self)
        return context

    def _build_payload(
        self,
        serializer: LocationAccessSerializer,
        *,
        instance: LocationAccess | None = None,
    ) -> dict[str, Any]:
        data = dict(serializer.validated_data)
        if instance is not None:
            data.setdefault("user", instance.user)
            data.setdefault("role", instance.role)
            if "location" not in data:
                data["location"] = instance.location
            data.setdefault("reason", instance.reason)
            data.setdefault("can_read", instance.can_read)
            data.setdefault("can_create", instance.can_create)
            data.setdefault("can_update", instance.can_update)
            data.setdefault("can_delete", instance.can_delete)
            data.setdefault("can_admin", instance.can_admin)
            data.setdefault("accessible_fields", instance.accessible_fields or [])
            data.setdefault("restricted_fields", instance.restricted_fields or [])
            data.setdefault("inherit_to_children", instance.inherit_to_children)
            data.setdefault("valid_from", instance.valid_from)
            data.setdefault("valid_until", instance.valid_until)
        data["granted_by"] = self.request.user if self.request.user.is_authenticated else None
        return data

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = self._build_payload(serializer)
        access = grant_location_access(**payload)
        output = self.get_serializer(access)
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request: Request, *args, **kwargs) -> Response:
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        payload = self._build_payload(serializer, instance=instance)
        access = grant_location_access(**payload)
        output = self.get_serializer(access)
        return Response(output.data, status=status.HTTP_200_OK)

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request: Request, *args, **kwargs) -> Response:
        instance = self.get_object()
        reason = ""
        if isinstance(request.data, dict):
            reason = request.data.get("reason", "")
        reason = reason or request.query_params.get("reason", "")
        count = revoke_location_access(
            user=instance.user,
            role=instance.role,
            location=instance.location,
            revoked_by=request.user if request.user.is_authenticated else None,
            reason=reason,
        )
        return Response({"revoked": count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="grant")
    def grant(self, request: Request) -> Response:
        serializer = LocationAccessGrantSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        payload = {
            **serializer.validated_data,
            "granted_by": request.user if request.user.is_authenticated else None,
        }
        access = grant_location_access(**payload)
        output = self.get_serializer(access)
        return Response(output.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="bulk-grant")
    def bulk_grant(self, request: Request) -> Response:
        serializer = LocationAccessBulkGrantSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        granted = bulk_grant_location_access(
            grants=serializer.validated_data["grants"],
            granted_by=request.user if request.user.is_authenticated else None,
        )
        output = self.get_serializer(granted, many=True)
        return Response(output.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="revoke")
    def revoke(self, request: Request) -> Response:
        serializer = LocationAccessRevokeSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        count = revoke_location_access(
            user=payload["user"],
            role=payload["role"],
            location=payload.get("location"),
            revoked_by=request.user if request.user.is_authenticated else None,
            reason=payload.get("reason", ""),
        )
        return Response({"revoked": count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="bulk-revoke")
    def bulk_revoke(self, request: Request) -> Response:
        serializer = LocationAccessBulkRevokeSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        count = bulk_revoke_location_access(
            revocations=serializer.validated_data["revocations"],
            revoked_by=request.user if request.user.is_authenticated else None,
        )
        return Response({"revoked": count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_path="my-locations")
    def my_locations(self, request: Request) -> Response:
        action_name = request.query_params.get("action", "read")
        checker = PermissionChecker(request.user)
        locations = checker.get_accessible_locations(action_name)
        serializer = LocationListSerializer(locations, many=True, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="check")
    def check(self, request: Request) -> Response:
        serializer = LocationAccessCheckSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        allowed = check_location_access(
            user=request.user,
            location=serializer.validated_data.get("location"),
            action=serializer.validated_data.get("action", "read"),
        )
        return Response({"allowed": allowed}, status=status.HTTP_200_OK)


class FieldPermissionViewSet(viewsets.ModelViewSet):
    """Manage role-based field permissions."""

    queryset = FieldPermission.objects.select_related("role")
    serializer_class = FieldPermissionSerializer
    permission_classes = [IsAuthenticated, IsLocationAdmin]

    permission_action_map: Dict[str, List[type]] = {
        "list": [IsAuthenticated, HasLocationAccess],
        "retrieve": [IsAuthenticated, HasLocationAccess],
        "create": [IsAuthenticated, IsLocationAdmin],
        "update": [IsAuthenticated, IsLocationAdmin],
        "partial_update": [IsAuthenticated, IsLocationAdmin],
        "destroy": [IsAuthenticated, IsLocationAdmin],
    }

    def get_permissions(self):  # pragma: no cover - DRF hook
        classes = self.permission_action_map.get(self.action, self.permission_classes)
        return [permission() for permission in classes]

    def get_permission_action(self, request: Request) -> str:
        if self.action in {"create", "update", "partial_update", "destroy"}:
            return "admin"
        return "read"

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        context.setdefault("view", self)
        return context

    def perform_create(self, serializer: FieldPermissionSerializer) -> None:
        user = self.request.user if self.request.user.is_authenticated else None
        instance = serializer.save(created_by=user, updated_by=user)
        record_permission_audit(
            action="grant",
            actor=user,
            subject=None,
            role=instance.role,
            location=None,
            payload={
                "model_name": instance.model_name,
                "field_name": instance.field_name,
                "can_read": instance.can_read,
                "can_write": instance.can_write,
            },
        )

    def perform_update(self, serializer: FieldPermissionSerializer) -> None:
        user = self.request.user if self.request.user.is_authenticated else None
        instance = serializer.save(updated_by=user)
        record_permission_audit(
            action="grant",
            actor=user,
            subject=None,
            role=instance.role,
            location=None,
            payload={
                "model_name": instance.model_name,
                "field_name": instance.field_name,
                "can_read": instance.can_read,
                "can_write": instance.can_write,
            },
        )

    def perform_destroy(self, instance: FieldPermission) -> None:
        user = self.request.user if self.request.user.is_authenticated else None
        record_permission_audit(
            action="revoke",
            actor=user,
            subject=None,
            role=instance.role,
            location=None,
            payload={
                "model_name": instance.model_name,
                "field_name": instance.field_name,
            },
        )
        instance.delete()


class RoleAssignmentRequestViewSet(viewsets.ModelViewSet):
    """Workflow endpoints for role assignment approval process."""

    queryset = RoleAssignmentRequest.objects.select_related(
        "user",
        "role",
        "location",
        "requested_by",
        "approver",
        "created_user_role",
    )
    serializer_class = RoleAssignmentRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        context.setdefault("request", self.request)
        return context

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        requested_by = request.user if request.user.is_authenticated else None
        assignment_request = create_role_assignment_request(
            user=payload["user"],
            role=payload["role"],
            requested_by=requested_by,
            location=payload.get("location"),
            valid_from=payload.get("valid_from"),
            valid_until=payload.get("valid_until"),
            reason=payload.get("reason", ""),
            metadata=payload.get("metadata"),
        )
        output = self.get_serializer(assignment_request)
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request: Request, pk: str | None = None) -> Response:
        approver = request.user
        if not approver.is_staff and not approver.is_superuser:
            raise PermissionDenied("You do not have permission to review assignment requests.")

        assignment_request = self.get_object()
        serializer = RoleAssignmentApprovalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        approve = serializer.validated_data["approve"]
        message = serializer.validated_data.get("response_message")

        if approve:
            user_role = assignment_request.approve(approver=approver, response_message=message)
            data = {
                "request": self.get_serializer(assignment_request).data,
                "user_role": UserRoleSerializer(user_role, context=self.get_serializer_context()).data,
            }
            return Response(data, status=status.HTTP_200_OK)

        assignment_request.reject(approver=approver, response_message=message)
        data = self.get_serializer(assignment_request).data
        return Response(data, status=status.HTTP_200_OK)
