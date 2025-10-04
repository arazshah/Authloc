from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase

from permissions.constants import (
    ALL_PERMISSIONS_TEMPLATE,
    PermissionActions,
    PermissionResources,
    SYSTEM_ROLE_CODES,
)
from permissions.models import Role, UserRole
from permissions.utils import get_effective_permissions, has_permission, merge_permissions

User = get_user_model()


def create_user(index: int = 0, **extra):
    defaults = {
        "username": f"user{index}",
        "email": f"user{index}@example.com",
        "password": "password123",
        "national_code": f"{index:010d}",
        "phone_number": f"09{index:09d}",
    }
    defaults.update(extra)
    return User.objects.create_user(**defaults)


class PermissionUtilsTests(TestCase):
    def test_merge_permissions_deduplicates_actions(self):
        merged = merge_permissions(
            {"locations": ["read", "update"]},
            {"locations": ["read", "delete"], "users": ["read"]},
        )
        self.assertEqual(sorted(merged["locations"]), ["delete", "read", "update"])
        self.assertEqual(merged["users"], ["read"])

    def test_get_effective_permissions_includes_parent_role(self):
        user = create_user(1)
        parent_role = Role.objects.create(
            name="Parent",
            code="parent-role",
            permissions={PermissionResources.LOCATIONS: [PermissionActions.READ]},
        )
        child_role = Role.objects.create(
            name="Child",
            code="child-role",
            permissions={PermissionResources.USERS: [PermissionActions.UPDATE]},
            parent_role=parent_role,
        )
        UserRole.objects.create(user=user, role=child_role)

        permissions = get_effective_permissions(user)
        self.assertIn(PermissionResources.LOCATIONS, permissions)
        self.assertIn(PermissionResources.USERS, permissions)
        self.assertIn(PermissionActions.READ, permissions[PermissionResources.LOCATIONS])
        self.assertIn(PermissionActions.UPDATE, permissions[PermissionResources.USERS])
        self.assertTrue(has_permission(user, PermissionResources.USERS, PermissionActions.UPDATE))
        self.assertFalse(has_permission(user, PermissionResources.REPORTS, PermissionActions.DELETE))

    def test_super_admin_has_full_access(self):
        user = create_user(2)
        super_role = Role.objects.create(
            name="Super Admin",
            code=SYSTEM_ROLE_CODES["SUPER_ADMIN"],
            permissions={},
            is_system_role=True,
        )
        UserRole.objects.create(user=user, role=super_role)

        permissions = get_effective_permissions(user)
        self.assertGreaterEqual(len(permissions), len(ALL_PERMISSIONS_TEMPLATE))
        self.assertIn(PermissionResources.AUDIT, permissions)
        self.assertIn(
            PermissionActions.DELETE,
            permissions[PermissionResources.USERS],
        )
        self.assertTrue(has_permission(user, PermissionResources.REPORTS, PermissionActions.EXPORT))
