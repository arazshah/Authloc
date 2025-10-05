"""Factories for the `permissions` app."""
from __future__ import annotations

import factory
from django.utils import timezone

from permissions.models import (
    FieldPermission,
    LocationAccess,
    Role,
    RoleAssignmentRequest,
    UserRole,
)
from tests.factories.authentication import StaffUserFactory, UserFactory
from tests.factories.base import UserTrackedFactory
from tests.factories.locations import LocationFactory


class RoleFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = Role

    name = factory.Sequence(lambda n: f"Role {n}")
    code = factory.Sequence(lambda n: f"role-{n}")
    description = factory.Faker("sentence")
    permissions = factory.LazyFunction(dict)
    is_system_role = False
    priority = 100
    parent_role = None
    is_active = True


class UserRoleFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = UserRole

    user = factory.SubFactory(UserFactory)
    role = factory.SubFactory(RoleFactory)
    location = factory.SubFactory(LocationFactory)
    valid_from = factory.LazyFunction(timezone.now)
    valid_until = None
    assigned_by = factory.SubFactory(StaffUserFactory)
    reason = factory.Faker("sentence")
    metadata = factory.LazyFunction(dict)
    is_active = True


class RoleAssignmentRequestFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = RoleAssignmentRequest

    user = factory.SubFactory(UserFactory)
    role = factory.SubFactory(RoleFactory)
    location = factory.SubFactory(LocationFactory)
    valid_from = factory.LazyFunction(timezone.now)
    valid_until = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(days=90))
    requested_by = factory.SubFactory(StaffUserFactory)
    approver = None
    status = RoleAssignmentRequest.Status.PENDING
    reason = factory.Faker("sentence")
    metadata = factory.LazyFunction(dict)


class LocationAccessFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = LocationAccess

    user = factory.SubFactory(UserFactory)
    location = factory.SubFactory(LocationFactory)
    role = factory.SubFactory(RoleFactory)
    can_read = True
    can_create = True
    can_update = True
    can_delete = False
    can_admin = False
    accessible_fields = factory.LazyFunction(list)
    restricted_fields = factory.LazyFunction(list)
    inherit_to_children = True
    valid_from = factory.LazyFunction(timezone.now)
    valid_until = None
    granted_by = factory.SubFactory(StaffUserFactory)
    reason = factory.Faker("sentence")
    is_active = True


class FieldPermissionFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = FieldPermission

    role = factory.SubFactory(RoleFactory)
    model_name = "locations.Location"
    field_name = "name"
    can_read = True
    can_write = False
    conditions = factory.LazyFunction(dict)
    is_active = True
