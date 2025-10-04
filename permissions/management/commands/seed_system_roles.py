from __future__ import annotations

from typing import Dict, Optional

from django.core.management.base import BaseCommand
from django.db import transaction

from permissions.constants import (
    ALL_PERMISSIONS_TEMPLATE,
    SYSTEM_ROLE_CODES,
    SYSTEM_ROLE_PERMISSION_PRESETS,
    SYSTEM_ROLE_PRIORITIES,
)
from permissions.models import Role


ROLE_HIERARCHY: Dict[str, Optional[str]] = {
    SYSTEM_ROLE_CODES["SUPER_ADMIN"]: None,
    SYSTEM_ROLE_CODES["MAYOR"]: SYSTEM_ROLE_CODES["SUPER_ADMIN"],
    SYSTEM_ROLE_CODES["DISTRICT_MANAGER"]: SYSTEM_ROLE_CODES["MAYOR"],
    SYSTEM_ROLE_CODES["EMPLOYEE"]: SYSTEM_ROLE_CODES["DISTRICT_MANAGER"],
    SYSTEM_ROLE_CODES["CONTRACTOR"]: SYSTEM_ROLE_CODES["EMPLOYEE"],
    SYSTEM_ROLE_CODES["CITIZEN"]: None,
}


class Command(BaseCommand):
    help = "Seed or update system roles with predefined permissions and hierarchy."

    def handle(self, *args, **options):
        with transaction.atomic():
            roles = self._create_or_update_roles()
            self._link_hierarchy(roles)
        self.stdout.write(self.style.SUCCESS("System roles have been seeded successfully."))

    def _create_or_update_roles(self) -> Dict[str, Role]:
        roles: Dict[str, Role] = {}
        for code, name in SYSTEM_ROLE_CODES.items():
            permissions = SYSTEM_ROLE_PERMISSION_PRESETS.get(code, {})
            if code == SYSTEM_ROLE_CODES["SUPER_ADMIN"]:
                permissions = {key: list(value) for key, value in ALL_PERMISSIONS_TEMPLATE.items()}

            role, _ = Role.objects.update_or_create(
                code=code,
                defaults={
                    "name": name.replace("_", " ").title(),
                    "description": f"System role '{name}' auto-seeded by management command.",
                    "permissions": permissions,
                    "is_system_role": True,
                    "priority": SYSTEM_ROLE_PRIORITIES.get(code, 100),
                    "is_active": True,
                },
            )
            roles[code] = role
        return roles

    def _link_hierarchy(self, roles: Dict[str, Role]) -> None:
        for code, parent_code in ROLE_HIERARCHY.items():
            role = roles[code]
            parent = roles.get(parent_code) if parent_code else None
            if role.parent_role_id != getattr(parent, "id", None):
                role.parent_role = parent
                role.save(update_fields=["parent_role", "updated_at"])
