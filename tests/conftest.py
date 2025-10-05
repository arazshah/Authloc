"""Shared pytest fixtures for the Authloc project."""
from __future__ import annotations

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from tests.factories.authentication import StaffUserFactory, UserFactory
from tests.factories.locations import LocationFactory
from tests.factories.permissions import RoleFactory


@pytest.fixture
def api_client() -> APIClient:
    """Return a DRF APIClient instance."""
    return APIClient()


@pytest.fixture
def user():
    """Return a basic verified user."""
    return UserFactory()


@pytest.fixture
def staff_user():
    """Return a staff/admin user with elevated privileges."""
    return StaffUserFactory()


@pytest.fixture
def authenticated_client(api_client: APIClient, user):
    """API client already authenticated with the provided user."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def staff_client(api_client: APIClient, staff_user):
    api_client.force_authenticate(user=staff_user)
    return api_client


@pytest.fixture
def location():
    return LocationFactory()


@pytest.fixture
def role():
    return RoleFactory()


@pytest.fixture(autouse=True)
def _enable_db_access_for_all_tests(db):  # noqa: PT004
    """Enable database access for all tests by default."""
    yield
