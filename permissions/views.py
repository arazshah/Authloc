"""Viewsets for the `permissions` app RBAC endpoints."""
from __future__ import annotations

from typing import Any

from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .models import Role, RoleAssignmentRequest, UserRole
from .serializers import (
    BulkRoleAssignmentRequestSerializer,
    EffectivePermissionQuerySerializer,
    EffectivePermissionResponseSerializer,
    MyRolesQuerySerializer,
    RoleAssignmentApprovalSerializer,
    RoleAssignmentRequestSerializer,
    RoleAssignmentPayloadSerializer,
    RoleSerializer,
    UserRoleSerializer,
)
from .services import assign_role_to_user, bulk_assign_roles, create_role_assignment_request
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
