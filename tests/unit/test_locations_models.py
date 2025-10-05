"""Unit tests for `locations` models."""
from __future__ import annotations

from django.core.exceptions import ValidationError
from django.contrib.gis.geos import Point, Polygon
from django.utils import timezone
import pytest

from locations.models import Location, LocationType
from tests.factories.locations import (
    LocationFactory,
    LocationTypeFactory,
    TrustedLocationFactory,
    LocationVerificationFactory,
)

pytestmark = pytest.mark.gis


class TestLocationModel:
    def test_clean_rejects_invalid_parent_level(self):
        parent_type = LocationTypeFactory(level=LocationType.Levels.COUNTRY)
        child_type = LocationTypeFactory(level=LocationType.Levels.CITY)
        parent = LocationFactory(type=parent_type, parent=None)
        child = LocationFactory.build(type=child_type, parent=parent)

        with pytest.raises(ValidationError):
            child.clean()

    def test_save_updates_path_and_propagates_to_children(self):
        country_type = LocationTypeFactory(level=LocationType.Levels.COUNTRY)
        province_type = LocationTypeFactory(level=LocationType.Levels.PROVINCE)
        country = LocationFactory(type=country_type, parent=None)
        province = LocationFactory(type=province_type, parent=country)

        assert province.path.startswith(f"{country.pk}/")

        new_country = LocationFactory(type=country_type, parent=None)
        province.parent = new_country
        province.save()
        province.refresh_from_db()

        assert province.path.startswith(f"{new_country.pk}/")

    def test_geometry_metrics_calculated_on_save(self):
        polygon = Polygon(((0, 0), (1, 0), (1, 1), (0, 0)))
        location_type = LocationTypeFactory(level=LocationType.Levels.COUNTRY)
        location = LocationFactory(type=location_type, geometry=polygon, parent=None)

        assert location.area_sqm is not None
        assert location.perimeter_m is not None
        assert isinstance(location.center_point, Point)

    def test_tree_helpers(self):
        root_type = LocationTypeFactory(level=LocationType.Levels.COUNTRY)
        city_type = LocationTypeFactory(level=LocationType.Levels.CITY)
        root = LocationFactory(type=root_type, parent=None)
        city = LocationFactory(type=city_type, parent=root)

        assert city.is_descendant_of(root)
        assert root.is_ancestor_of(city)
        assert not root.is_descendant_of(city)


class TestTrustedLocation:
    def test_unique_name_per_user(self):
        trusted = TrustedLocationFactory()
        with pytest.raises(ValidationError):
            duplicate = TrustedLocationFactory.build(user=trusted.user, name=trusted.name)
            duplicate.full_clean()


class TestLocationVerification:
    def test_status_defaults_to_review(self):
        verification = LocationVerificationFactory()
        assert verification.status == verification.Status.REVIEW
        assert verification.reported_location.srid == 4326

    def test_metadata_default(self):
        verification = LocationVerificationFactory(metadata={"signal": "weak"})
        assert verification.metadata["signal"] == "weak"
