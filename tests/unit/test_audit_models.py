"""Unit tests for `audit` models."""
from __future__ import annotations

from unittest import mock

import pytest
from django.contrib.gis.geos import Point
from django.utils import timezone

from audit.models import AuditLog, PermissionAuditLog, SecurityAlert
from tests.factories.audit import AuditLogFactory, PermissionAuditLogFactory, SecurityAlertFactory

pytestmark = pytest.mark.audit


class TestAuditLogModel:
    def test_string_representation(self):
        log = AuditLogFactory(action=AuditLog.Actions.CREATE)
        assert str(log).startswith("create")

    def test_geo_location_defaults(self):
        with mock.patch("audit.models.gis_models.PointField"):
            log = AuditLogFactory(geo_location=None)
        assert log.geo_location is None


class TestSecurityAlertModel:
    def test_resolve_flow(self):
        alert = SecurityAlertFactory()
        assert not alert.is_resolved
        resolver = alert.user
        alert.is_resolved = True
        alert.resolved_by = resolver
        alert.resolved_at = timezone.now()
        alert.resolution_notes = "Issue resolved"
        alert.save(update_fields=["is_resolved", "resolved_by", "resolved_at", "resolution_notes"])
        alert.refresh_from_db()

        assert alert.is_resolved
        assert alert.resolved_by == resolver
        assert alert.resolution_notes == "Issue resolved"


class TestPermissionAuditLogModel:
    def test_string_representation(self):
        entry = PermissionAuditLogFactory(action=PermissionAuditLog.Actions.GRANT)
        message = str(entry)
        assert "grant" in message
        assert str(entry.location or "") in message
