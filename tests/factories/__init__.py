"""Factory Boy factories for Authloc tests."""
from tests.factories.authentication import UserFactory, StaffUserFactory
from tests.factories.locations import LocationFactory, LocationTypeFactory
from tests.factories.permissions import RoleFactory, UserRoleFactory
from tests.factories.audit import AuditLogFactory, SecurityAlertFactory
from tests.factories.search import SearchQueryLogFactory, PopularSearchTermFactory, SearchResultClickFactory

__all__ = [
    "UserFactory",
    "StaffUserFactory",
    "LocationTypeFactory",
    "LocationFactory",
    "RoleFactory",
    "UserRoleFactory",
    "AuditLogFactory",
    "SecurityAlertFactory",
    "SearchQueryLogFactory",
    "PopularSearchTermFactory",
    "SearchResultClickFactory",
]
