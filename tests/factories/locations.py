"""Factories for the `locations` app."""
from __future__ import annotations

import factory
from django.contrib.gis.geos import Point

from locations.models import Location, LocationType, TrustedLocation, LocationVerification
from tests.factories.base import UserTrackedFactory
from tests.factories.authentication import UserFactory


class LocationTypeFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    """Factory for `locations.LocationType`."""

    class Meta:
        model = LocationType

    name = factory.Sequence(lambda n: f"Location Type {n}")
    name_fa = factory.Sequence(lambda n: f"نوع {n}")
    code = factory.Sequence(lambda n: f"TYPE{n:03d}")
    level = 0
    icon = "map-marker"
    color = "#3366FF"
    is_active = True


class LocationFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    """Factory for `locations.Location`."""

    class Meta:
        model = Location

    name = factory.Sequence(lambda n: f"Location {n}")
    name_fa = factory.Sequence(lambda n: f"مکان {n}")
    code = factory.Sequence(lambda n: f"LOC{n:05d}")
    type = factory.SubFactory(LocationTypeFactory)
    parent = None
    geometry = None
    center_point = None
    population = factory.Faker("random_int", min=1_000, max=5_000_000)
    metadata = factory.LazyFunction(dict)
    is_active = True

    @factory.post_generation
    def ensure_path(self, create: bool, extracted, **kwargs):  # noqa: D401 - factory hook
        """Trigger save to ensure hierarchy fields are populated."""
        if create:
            self.refresh_from_db()


class TrustedLocationFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = TrustedLocation

    user = factory.SubFactory(UserFactory)
    name = factory.Sequence(lambda n: f"Trusted Location {n}")
    location = factory.LazyFunction(lambda: Point(51.3890, 35.6892, srid=4326))
    radius_meters = 150
    is_active = True


class LocationVerificationFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = LocationVerification

    user = factory.SubFactory(UserFactory)
    trusted_location = factory.SubFactory(TrustedLocationFactory)
    reported_location = factory.LazyFunction(lambda: Point(51.3890, 35.6892, srid=4326))
    accuracy_meters = factory.Faker("pyfloat", positive=True, right_digits=2, min_value=0.5, max_value=20.0)
    status = LocationVerification.Status.REVIEW
    ip_address = factory.Faker("ipv4")
    user_agent = factory.Faker("user_agent")
    metadata = factory.LazyFunction(dict)
