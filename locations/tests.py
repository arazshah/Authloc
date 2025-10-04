from __future__ import annotations

from django.contrib.gis.geos import Point, Polygon
from django.core.management import call_command
from django.test import TestCase

from .models import Location, LocationType
from .utils import (
    calculate_area,
    calculate_distance,
    check_point_in_polygon,
    export_to_geojson,
    find_locations_within_radius,
    find_nearest_location,
    import_from_csv,
    import_from_geojson,
)


class LocationHierarchyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.country_type = LocationType.objects.create(
            name="Country",
            name_fa="کشور",
            code="country",
            level=0,
        )
        cls.province_type = LocationType.objects.create(
            name="Province",
            name_fa="استان",
            code="province",
            level=1,
        )
        cls.city_type = LocationType.objects.create(
            name="City",
            name_fa="شهر",
            code="city",
            level=2,
        )
        cls.district_type = LocationType.objects.create(
            name="District",
            name_fa="منطقه",
            code="district",
            level=3,
        )

        cls.country = Location.objects.create(
            name="Iran",
            name_fa="ایران",
            code="IRN",
            type=cls.country_type,
            center_point=Point(53.6880, 32.4279, srid=4326),
        )

        cls.province = Location.objects.create(
            name="Tehran Province",
            name_fa="استان تهران",
            code="IRN-THR",
            type=cls.province_type,
            parent=cls.country,
            center_point=Point(51.3890, 35.6892, srid=4326),
        )

        cls.city = Location.objects.create(
            name="Tehran",
            name_fa="تهران",
            code="IRN-THR-TEH",
            type=cls.city_type,
            parent=cls.province,
            center_point=Point(51.3890, 35.6892, srid=4326),
            population=8846782,
        )

        district_polygon = Polygon(
            (
                (51.36, 35.70),
                (51.42, 35.70),
                (51.42, 35.76),
                (51.36, 35.76),
                (51.36, 35.70),
            ),
            srid=4326,
        )
        cls.district = Location.objects.create(
            name="District 1",
            name_fa="منطقه ۱",
            code="IRN-THR-TEH-01",
            type=cls.district_type,
            parent=cls.city,
            geometry=district_polygon,
        )

    def test_materialized_path_updates_correctly(self):
        self.country.refresh_from_db()
        self.province.refresh_from_db()
        self.city.refresh_from_db()
        expected_country_path = f"{self.country.pk}/"
        expected_city_path = f"{self.country.pk}/{self.province.pk}/{self.city.pk}/"
        self.assertEqual(self.country.path, expected_country_path)
        self.assertEqual(self.city.path, expected_city_path)

    def test_tree_relationship_helpers(self):
        ancestors = list(self.city.get_ancestors())
        self.assertEqual(ancestors, [self.country, self.province])

        descendants = list(self.country.get_descendants())
        self.assertIn(self.province, descendants)
        self.assertIn(self.city, descendants)
        self.assertIn(self.district, descendants)

        siblings = list(self.province.get_siblings())
        self.assertEqual(siblings, [])

        self.assertTrue(self.country.is_ancestor_of(self.district))
        self.assertTrue(self.district.is_descendant_of(self.country))
        self.assertFalse(self.country.is_descendant_of(self.country))

    def test_geometry_metrics_are_calculated(self):
        self.district.refresh_from_db()
        self.assertIsNotNone(self.district.center_point)
        self.assertIsNotNone(self.district.area_sqm)
        self.assertGreater(self.district.area_sqm, 0)
        self.assertIsNotNone(self.district.perimeter_m)
        self.assertGreater(self.district.perimeter_m, 0)


class LocationUtilitiesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.country_type = LocationType.objects.create(name="Country", code="country", level=0)
        cls.city_type = LocationType.objects.create(name="City", code="city", level=1)

        cls.country = Location.objects.create(
            name="Iran",
            code="IRN",
            type=cls.country_type,
            center_point=Point(53.6880, 32.4279, srid=4326),
        )
        cls.city = Location.objects.create(
            name="Tehran",
            code="IRN-THR-TEH",
            type=cls.city_type,
            parent=cls.country,
            center_point=Point(51.3890, 35.6892, srid=4326),
            population=8846782,
        )

    def test_find_locations_within_radius(self):
        point = Point(51.4, 35.70, srid=4326)
        nearby = find_locations_within_radius(point, 15000)
        self.assertIn(self.city, list(nearby))

    def test_find_nearest_location(self):
        point = Point(51.3, 35.7, srid=4326)
        nearest = list(find_nearest_location(point, location_type=self.city_type, limit=1))
        self.assertEqual(nearest[0], self.city)

    def test_check_point_in_polygon(self):
        polygon = Polygon(
            (
                (51.35, 35.68),
                (51.45, 35.68),
                (51.45, 35.75),
                (51.35, 35.75),
                (51.35, 35.68),
            ),
            srid=4326,
        )
        inside_point = Point(51.40, 35.70, srid=4326)
        outside_point = Point(51.60, 35.90, srid=4326)
        self.assertTrue(check_point_in_polygon(inside_point, polygon))
        self.assertFalse(check_point_in_polygon(outside_point, polygon))

    def test_calculate_area_and_distance(self):
        polygon = Polygon(
            (
                (51.35, 35.68),
                (51.45, 35.68),
                (51.45, 35.75),
                (51.35, 35.75),
                (51.35, 35.68),
            ),
            srid=4326,
        )
        area = calculate_area(polygon)
        self.assertGreater(area, 0)

        point_a = Point(51.39, 35.68, srid=4326)
        point_b = Point(51.41, 35.70, srid=4326)
        distance = calculate_distance(point_a, point_b)
        self.assertGreater(distance, 0)

    def test_import_from_csv(self):
        csv_content = "name,code\nDistrict X,IRN-THR-TEH-CSV\n"
        created_locations = import_from_csv(
            csv_content,
            location_type=self.city_type,
            parent=self.country,
        )
        self.assertEqual(len(created_locations), 1)
        self.assertTrue(Location.objects.filter(code="IRN-THR-TEH-CSV").exists())


class GeoJSONImportExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.country_type = LocationType.objects.create(name="Country", code="country", level=0)
        cls.city_type = LocationType.objects.create(name="City", code="city", level=1)
        cls.district_type = LocationType.objects.create(name="District", code="district", level=2)

        cls.country = Location.objects.create(
            name="Iran",
            code="IRN",
            type=cls.country_type,
        )
        cls.city = Location.objects.create(
            name="Tehran",
            code="IRN-THR-TEH",
            type=cls.city_type,
            parent=cls.country,
            center_point=Point(51.3890, 35.6892, srid=4326),
        )

    def test_import_from_geojson_creates_locations(self):
        feature_geometry = {
            "type": "Polygon",
            "coordinates": [
                [
                    [51.4, 35.7],
                    [51.45, 35.7],
                    [51.45, 35.75],
                    [51.4, 35.75],
                    [51.4, 35.7],
                ]
            ],
        }
        geojson_payload = {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "properties": {
                        "name": "District 1",
                        "code": "IRN-THR-TEH-GJ",
                        "type_code": self.district_type.code,
                        "parent_code": self.city.code,
                        "population": 500000,
                    },
                    "geometry": feature_geometry,
                }
            ],
        }

        created_locations = import_from_geojson(geojson_payload, default_type=self.district_type)
        self.assertEqual(len(created_locations), 1)
        created = created_locations[0]
        self.assertEqual(created.parent, self.city)
        self.assertIsNotNone(created.geometry)
        self.assertGreater(created.area_sqm, 0)

    def test_export_to_geojson_returns_feature_collection(self):
        collection = export_to_geojson([self.city])
        self.assertEqual(collection["type"], "FeatureCollection")
        self.assertEqual(len(collection["features"]), 1)
        feature = collection["features"][0]
        self.assertEqual(feature["properties"]["code"], self.city.code)


class SeedCommandTests(TestCase):
    def test_seed_command_populates_locations(self):
        call_command("seed_iran_locations", verbosity=0)
        country = Location.objects.get(code="IR")
        self.assertIsNotNone(country)
        tehran_province = Location.objects.get(code="THR")
        self.assertEqual(tehran_province.parent, country)
        tehran_city = Location.objects.get(code="THR-TEH")
        self.assertEqual(tehran_city.parent, tehran_province)

