"""Serializers for the `permissions` app."""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from locations.models import Location

from .constants import PermissionActions, PermissionResources
from .mixins import FieldPermissionMixin
from .models import FieldPermission, LocationAccess, Role, RoleAssignmentRequest, UserRole

User = get_user_model()


def _validate_permission_mapping(permissions: Dict[str, Iterable[str]]) -> Dict[str, list[str]]:
    cleaned: Dict[str, list[str]] = {}
    for resource, actions in permissions.items():
        if resource not in PermissionResources.ALL:
            raise serializers.ValidationError({"permissions": f"Unknown resource '{resource}'."})
        action_list = []
        for action in actions:
            if action not in PermissionActions.ALL:
                raise serializers.ValidationError({"permissions": f"Invalid action '{action}' for '{resource}'."})
            action_list.append(action)
        cleaned[resource] = sorted(set(action_list))
    return cleaned


class RoleSerializer(serializers.ModelSerializer):
    parent_role = serializers.PrimaryKeyRelatedField(read_only=True)
    parent_role_id = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(), write_only=True, allow_null=True, source="parent_role"
    )
    permissions = serializers.DictField(
        required=False,
        child=serializers.ListField(child=serializers.CharField()),
        default=dict,
    )

    class Meta:
        model = Role
        fields = [
            "id",
            "name",
            "code",
            "description",
            "permissions",
            "is_system_role",
            "priority",
            "parent_role",
            "parent_role_id",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "priority"]

    def validate_permissions(self, value: Dict[str, Iterable[str]]):
        return _validate_permission_mapping(value or {})

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if self.instance and attrs.get("code") and self.instance.is_system_role:
            raise serializers.ValidationError({"code": "System role codes cannot be modified."})
        return super().validate(attrs)


class LocationAccessSerializer(FieldPermissionMixin, serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    granted_by = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )

    class Meta:
        model = LocationAccess
        fields = [
            "id",
            "user",
            "role",
            "location",
            "can_read",
            "can_create",
            "can_update",
            "can_delete",
            "can_admin",
            "accessible_fields",
            "restricted_fields",
            "inherit_to_children",
            "valid_from",
            "valid_until",
            "granted_by",
            "reason",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    permission_model_name = "permissions.LocationAccess"

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        valid_from = attrs.get("valid_from")
        valid_until = attrs.get("valid_until")
        if valid_from is None and self.instance is not None:
            valid_from = self.instance.valid_from
        if valid_until is None and self.instance is not None:
            valid_until = self.instance.valid_until
        if valid_from and valid_until and valid_from > valid_until:
            raise serializers.ValidationError({"valid_until": "valid_until must be after valid_from."})

        accessible = attrs.get("accessible_fields")
        if accessible is None and self.instance is not None:
            accessible = self.instance.accessible_fields or []
        restricted = attrs.get("restricted_fields")
        if restricted is None and self.instance is not None:
            restricted = self.instance.restricted_fields or []
        accessible_set = set(accessible or [])
        restricted_set = set(restricted or [])
        if accessible_set and restricted_set and accessible_set & restricted_set:
            raise serializers.ValidationError(
                {"restricted_fields": "restricted_fields cannot overlap with accessible_fields."}
            )

        return super().validate(attrs)


class LocationAccessGrantSerializer(serializers.Serializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    can_read = serializers.BooleanField(required=False, default=True)
    can_create = serializers.BooleanField(required=False, default=False)
    can_update = serializers.BooleanField(required=False, default=False)
    can_delete = serializers.BooleanField(required=False, default=False)
    can_admin = serializers.BooleanField(required=False, default=False)
    accessible_fields = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True, default=list
    )
    restricted_fields = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True, default=list
    )
    inherit_to_children = serializers.BooleanField(required=False, default=True)
    valid_from = serializers.DateTimeField(required=False, allow_null=True)
    valid_until = serializers.DateTimeField(required=False, allow_null=True)
    reason = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        valid_from = attrs.get("valid_from")
        valid_until = attrs.get("valid_until")
        if valid_from and valid_until and valid_from > valid_until:
            raise serializers.ValidationError({"valid_until": "valid_until must be after valid_from."})
        accessible = set(attrs.get("accessible_fields", []) or [])
        restricted = set(attrs.get("restricted_fields", []) or [])
        if accessible and restricted and accessible & restricted:
            raise serializers.ValidationError(
                {"restricted_fields": "restricted_fields cannot overlap with accessible_fields."}
            )
        return attrs


class LocationAccessBulkGrantSerializer(serializers.Serializer):
    grants = LocationAccessGrantSerializer(many=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not attrs.get("grants"):
            raise serializers.ValidationError({"grants": "At least one grant payload is required."})
        return attrs


class LocationAccessRevokeSerializer(serializers.Serializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    reason = serializers.CharField(required=False, allow_blank=True)


class LocationAccessBulkRevokeSerializer(serializers.Serializer):
    revocations = LocationAccessRevokeSerializer(many=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not attrs.get("revocations"):
            raise serializers.ValidationError(
                {"revocations": "At least one revocation payload is required."}
            )
        return attrs


class LocationAccessCheckSerializer(serializers.Serializer):
    action = serializers.CharField(required=False, default="read")
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )


class FieldPermissionSerializer(serializers.ModelSerializer):
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())

    class Meta:
        model = FieldPermission
        fields = [
            "id",
            "role",
            "model_name",
            "field_name",
            "can_read",
            "can_write",
            "conditions",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        model_name = attrs.get("model_name")
        field_name = attrs.get("field_name")
        if model_name:
            attrs["model_name"] = model_name.strip()
        elif self.instance is not None:
            attrs.setdefault("model_name", self.instance.model_name)
        if field_name:
            attrs["field_name"] = field_name.strip()
        elif self.instance is not None:
            attrs.setdefault("field_name", self.instance.field_name)
        return super().validate(attrs)


class UserRoleSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    assigned_by = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    created_user_role_request = serializers.PrimaryKeyRelatedField(
        source="assignment_request", read_only=True
    )

    class Meta:
        model = UserRole
        fields = [
            "id",
            "user",
            "role",
            "location",
            "valid_from",
            "valid_until",
            "assigned_by",
            "reason",
            "metadata",
            "is_active",
            "created_user_role_request",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_user_role_request", "created_at", "updated_at"]

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        valid_from = attrs.get("valid_from")
        valid_until = attrs.get("valid_until")
        if valid_from and valid_until and valid_from > valid_until:
            raise serializers.ValidationError({"valid_until": "valid_until must be after valid_from."})
        return super().validate(attrs)


class RoleAssignmentRequestSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    requested_by = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    approver = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    created_user_role = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = RoleAssignmentRequest
        fields = [
            "id",
            "user",
            "role",
            "location",
            "valid_from",
            "valid_until",
            "requested_by",
            "approver",
            "status",
            "reason",
            "response_message",
            "metadata",
            "reviewed_at",
            "created_user_role",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "approver",
            "response_message",
            "reviewed_at",
            "created_user_role",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        valid_from = attrs.get("valid_from")
        valid_until = attrs.get("valid_until")
        if valid_from and valid_until and valid_from > valid_until:
            raise serializers.ValidationError({"valid_until": "valid_until must be after valid_from."})
        return super().validate(attrs)


class RoleAssignmentActionSerializer(serializers.Serializer):
    response_message = serializers.CharField(required=False, allow_blank=True)


class RoleAssignmentApprovalSerializer(serializers.Serializer):
    approve = serializers.BooleanField()
    response_message = serializers.CharField(required=False, allow_blank=True)


class RoleAssignmentPayloadSerializer(serializers.Serializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )
    valid_from = serializers.DateTimeField(required=False, allow_null=True)
    valid_until = serializers.DateTimeField(required=False, allow_null=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    metadata = serializers.DictField(required=False)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        valid_from = attrs.get("valid_from")
        valid_until = attrs.get("valid_until")
        if valid_from and valid_until and valid_from > valid_until:
            raise serializers.ValidationError({"valid_until": "valid_until must be after valid_from."})
        return attrs


class BulkRoleAssignmentSerializer(serializers.Serializer):
    assignments = RoleAssignmentPayloadSerializer(many=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not attrs.get("assignments"):
            raise serializers.ValidationError({"assignments": "At least one assignment is required."})
        return attrs


class BulkRoleAssignmentRequestSerializer(BulkRoleAssignmentSerializer):
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())


class MyRolesQuerySerializer(serializers.Serializer):
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )


class EffectivePermissionQuerySerializer(serializers.Serializer):
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )

    def to_internal_value(self, data: Any) -> Dict[str, Any]:
        if data in (None, ""):
            return {"location": None}
        return super().to_internal_value(data)


class EffectivePermissionResponseSerializer(serializers.Serializer):
    permissions = serializers.DictField(child=serializers.ListField(child=serializers.CharField()))
    generated_at = serializers.DateTimeField(read_only=True)


class PermissionCheckSerializer(serializers.Serializer):
    resource = serializers.ChoiceField(choices=PermissionResources.ALL)
    action = serializers.ChoiceField(choices=PermissionActions.ALL)
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(), allow_null=True, required=False
    )


__all__ = [
    "RoleSerializer",
    "UserRoleSerializer",
    "RoleAssignmentRequestSerializer",
    "RoleAssignmentActionSerializer",
    "RoleAssignmentApprovalSerializer",
    "RoleAssignmentPayloadSerializer",
    "BulkRoleAssignmentSerializer",
    "BulkRoleAssignmentRequestSerializer",
    "LocationAccessSerializer",
    "LocationAccessGrantSerializer",
    "LocationAccessBulkGrantSerializer",
    "LocationAccessRevokeSerializer",
    "LocationAccessBulkRevokeSerializer",
    "LocationAccessCheckSerializer",
    "FieldPermissionSerializer",
    "MyRolesQuerySerializer",
    "EffectivePermissionQuerySerializer",
    "EffectivePermissionResponseSerializer",
    "PermissionCheckSerializer",
]
