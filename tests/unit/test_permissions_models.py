"""Unit tests for `permissions` models."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from permissions.constants import (
    PermissionActions,
    PermissionResources,
    SYSTEM_ROLE_CODES,
    flatten_permission_actions,
)
from permissions.models import RoleAssignmentRequest, LocationAccess
from tests.factories.authentication import StaffUserFactory
from tests.factories.locations import LocationFactory
from tests.factories.permissions import (
    FieldPermissionFactory,
    LocationAccessFactory,
    RoleAssignmentRequestFactory,
    RoleFactory,
    UserRoleFactory,
)

pytestmark = pytest.mark.authorization


class TestRoleModel:
    def test_clean_prevents_self_parent(self):
        role = RoleFactory()
        role.parent_role = role
        with pytest.raises(ValidationError):
            role.clean()

    def test_system_role_priority_is_enforced(self):
        role = RoleFactory(code=SYSTEM_ROLE_CODES["SUPER_ADMIN"], is_system_role=True)
        role.save()
        assert role.priority == 10


class TestUserRoleModel:
    def test_is_current_respects_validity_window(self):
        now = timezone.now()
        user_role = UserRoleFactory(valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=1))
        assert user_role.is_current()

        user_role.valid_until = now - timedelta(hours=1)
        user_role.save(update_fields=["valid_until"])
        assert not user_role.is_current()


class TestRoleAssignmentRequest:
    def test_approve_creates_user_role_and_updates_state(self):
        approver = StaffUserFactory()
        request = RoleAssignmentRequestFactory()

        user_role = request.approve(approver=approver, response_message="Approved")

        request.refresh_from_db()
        assert request.status == RoleAssignmentRequest.Status.APPROVED
        assert request.approver == approver
        assert request.created_user_role == user_role
        assert user_role.role == request.role
        assert user_role.user == request.user

    def test_reject_updates_status(self):
        approver = StaffUserFactory()
        request = RoleAssignmentRequestFactory()

        request.reject(approver=approver, response_message="Denied")
        request.refresh_from_db()

        assert request.status == RoleAssignmentRequest.Status.REJECTED
        assert request.approver == approver
        assert request.response_message == "Denied"


class TestLocationAccessModel:
    def test_clean_rejects_overlap_between_accessible_and_restricted(self):
        access = LocationAccessFactory.build(accessible_fields=["name"], restricted_fields=["name"])
        with pytest.raises(ValidationError):
            access.clean()

    def test_is_current_respects_window(self):
        access = LocationAccessFactory(valid_until=timezone.now() + timedelta(days=1))
        assert access.is_current()
        access.valid_until = timezone.now() - timedelta(hours=1)
        access.save(update_fields=["valid_until"])
        assert not access.is_current()


class TestFieldPermissionModel:
    def test_save_strips_whitespace(self):
        permission = FieldPermissionFactory(model_name=" locations.Location ", field_name=" name ")
        permission.refresh_from_db()
        assert permission.model_name == "locations.Location"
        assert permission.field_name == "name"


class TestPermissionUtilities:
    def test_flatten_permission_actions(self):
        permissions = {
            PermissionResources.LOCATIONS: [PermissionActions.READ, PermissionActions.UPDATE],
            PermissionResources.USERS: [PermissionActions.ADMIN],
        }
        flattened = flatten_permission_actions(permissions)
        assert flattened == {PermissionActions.READ, PermissionActions.UPDATE, PermissionActions.ADMIN}
