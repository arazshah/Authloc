from __future__ import annotations

from typing import Any, Dict, Optional

from django.db import transaction

from .models import PermissionAuditLog


def record_permission_audit(
    *,
    action: str,
    actor=None,
    subject=None,
    role=None,
    location=None,
    payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    message: str = "",
) -> PermissionAuditLog:
    payload = payload or {}
    metadata = metadata or {}

    def _create():
        PermissionAuditLog.objects.create(
            action=action,
            actor=actor,
            subject=subject,
            role=role,
            location=location,
            payload=payload,
            metadata=metadata,
            message=message,
        )

    transaction.on_commit(_create)
    return PermissionAuditLog(
        action=action,
        actor=actor,
        subject=subject,
        role=role,
        location=location,
        payload=payload,
        metadata=metadata,
        message=message,
    )
