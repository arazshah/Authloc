"""Constants for the `permissions` app."""
from __future__ import annotations

from typing import Dict, List, Set


class PermissionActions:
    """Enumerates supported permission actions."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    ADMIN = "admin"
    EXPORT = "export"
    IMPORT = "import"

    ALL: List[str] = [CREATE, READ, UPDATE, DELETE, ADMIN, EXPORT, IMPORT]
    DEFAULT_READ_ONLY: List[str] = [READ]
    PRIVILEGED: List[str] = [ADMIN]


class PermissionResources:
    """Enumerates resources covered by RBAC."""

    LOCATIONS = "locations"
    USERS = "users"
    REPORTS = "reports"
    AUDIT = "audit"

    ALL: List[str] = [LOCATIONS, USERS, REPORTS, AUDIT]


ALL_PERMISSIONS_TEMPLATE: Dict[str, List[str]] = {
    resource: list(PermissionActions.ALL) for resource in PermissionResources.ALL
}


SYSTEM_ROLE_CODES: Dict[str, str] = {
    "SUPER_ADMIN": "SUPER_ADMIN",
    "MAYOR": "MAYOR",
    "DISTRICT_MANAGER": "DISTRICT_MANAGER",
    "EMPLOYEE": "EMPLOYEE",
    "CONTRACTOR": "CONTRACTOR",
    "CITIZEN": "CITIZEN",
}


SYSTEM_ROLE_PRIORITIES: Dict[str, int] = {
    SYSTEM_ROLE_CODES["SUPER_ADMIN"]: 10,
    SYSTEM_ROLE_CODES["MAYOR"]: 20,
    SYSTEM_ROLE_CODES["DISTRICT_MANAGER"]: 30,
    SYSTEM_ROLE_CODES["EMPLOYEE"]: 40,
    SYSTEM_ROLE_CODES["CONTRACTOR"]: 50,
    SYSTEM_ROLE_CODES["CITIZEN"]: 60,
}


SYSTEM_ROLE_PERMISSION_PRESETS: Dict[str, Dict[str, List[str]]] = {
    SYSTEM_ROLE_CODES["SUPER_ADMIN"]: ALL_PERMISSIONS_TEMPLATE,
    SYSTEM_ROLE_CODES["MAYOR"]: {
        PermissionResources.LOCATIONS: PermissionActions.ALL,
        PermissionResources.USERS: [PermissionActions.READ, PermissionActions.UPDATE, PermissionActions.ADMIN],
        PermissionResources.REPORTS: PermissionActions.ALL,
        PermissionResources.AUDIT: PermissionActions.ALL,
    },
    SYSTEM_ROLE_CODES["DISTRICT_MANAGER"]: {
        PermissionResources.LOCATIONS: [PermissionActions.READ, PermissionActions.UPDATE],
        PermissionResources.USERS: [PermissionActions.READ, PermissionActions.UPDATE],
        PermissionResources.REPORTS: [PermissionActions.READ, PermissionActions.EXPORT],
        PermissionResources.AUDIT: [PermissionActions.READ],
    },
    SYSTEM_ROLE_CODES["EMPLOYEE"]: {
        PermissionResources.LOCATIONS: [PermissionActions.READ],
        PermissionResources.USERS: [PermissionActions.READ],
        PermissionResources.REPORTS: [PermissionActions.READ],
        PermissionResources.AUDIT: [],
    },
    SYSTEM_ROLE_CODES["CONTRACTOR"]: {
        PermissionResources.LOCATIONS: [PermissionActions.READ, PermissionActions.UPDATE],
        PermissionResources.REPORTS: [PermissionActions.READ, PermissionActions.EXPORT],
    },
    SYSTEM_ROLE_CODES["CITIZEN"]: {
        PermissionResources.LOCATIONS: PermissionActions.DEFAULT_READ_ONLY,
        PermissionResources.REPORTS: PermissionActions.DEFAULT_READ_ONLY,
    },
}


def flatten_permission_actions(permissions: Dict[str, List[str]]) -> Set[str]:
    """Utility for deduplicating permission action sets."""

    return {action for actions in permissions.values() for action in actions}
