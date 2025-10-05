"""Factories for the `audit` app."""
from __future__ import annotations

import factory
from django.contrib.gis.geos import Point

from audit.models import AuditLog, PermissionAuditLog, SecurityAlert
from tests.factories.authentication import StaffUserFactory, UserFactory
from tests.factories.base import UserTrackedFactory
from tests.factories.locations import LocationFactory


class AuditLogFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = AuditLog

    action = AuditLog.Actions.READ
    user = factory.SubFactory(UserFactory)
    username = factory.LazyAttribute(lambda obj: obj.user.username)
    resource_type = "locations.Location"
    resource_id = factory.Sequence(lambda n: str(n))
    resource_name = factory.Sequence(lambda n: f"Location {n}")
    old_values = factory.LazyFunction(dict)
    new_values = factory.LazyFunction(dict)
    changes_summary = factory.LazyFunction(dict)
    ip_address = factory.Faker("ipv4")
    user_agent = factory.Faker("user_agent")
    request_method = "GET"
    request_path = "/api/v1/locations/"
    request_body = factory.LazyFunction(dict)
    response_status = 200
    processing_time = factory.Faker("pyfloat", positive=True, right_digits=3, max_value=2.5)
    location = factory.SubFactory(LocationFactory)
    geo_location = factory.LazyFunction(lambda: Point(51.3890, 35.6892, srid=4326))
    risk_score = factory.Faker("pyint", min_value=0, max_value=100)
    is_suspicious = False
    metadata = factory.LazyFunction(dict)


class SecurityAlertFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = SecurityAlert

    alert_type = SecurityAlert.AlertTypes.SUSPICIOUS_LOGIN
    severity = SecurityAlert.Severity.MEDIUM
    title = factory.Sequence(lambda n: f"Security Alert {n}")
    description = factory.Faker("sentence")
    details = factory.LazyFunction(dict)
    user = factory.SubFactory(UserFactory)
    audit_log = factory.SubFactory(AuditLogFactory)
    ip_address = factory.Faker("ipv4")
    geo_location = factory.LazyFunction(lambda: Point(51.4, 35.7, srid=4326))
    is_resolved = False
    resolved_by = None
    resolved_at = None
    resolution_notes = ""


class PermissionAuditLogFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = PermissionAuditLog

    action = PermissionAuditLog.Actions.GRANT
    actor = factory.SubFactory(StaffUserFactory)
    subject = factory.SubFactory(UserFactory)
    role = factory.SubFactory("tests.factories.permissions.RoleFactory")
    location = factory.SubFactory(LocationFactory)
    payload = factory.LazyFunction(dict)
    metadata = factory.LazyFunction(dict)
    message = factory.Faker("sentence")
