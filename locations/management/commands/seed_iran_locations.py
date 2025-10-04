from __future__ import annotations

from django.contrib.gis.geos import Point
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from locations.models import Location, LocationType


class Command(BaseCommand):
    help = "Seed hierarchical location data for Iran, including provinces, major cities, and districts."

    COUNTRY_CODE = "IR"

    PROVINCES = [
        {
            "name": "Tehran Province",
            "name_fa": "استان تهران",
            "code": "THR",
            "center": (51.3890, 35.6892),
            "cities": [
                {
                    "name": "Tehran",
                    "name_fa": "تهران",
                    "code": "THR-TEH",
                    "center": (51.3890, 35.6892),
                    "population": 8846782,
                    "districts": [
                        {
                            "name": "District 1",
                            "name_fa": "منطقه ۱",
                            "code": "THR-TEH-01",
                            "center": (51.4215, 35.8040),
                        },
                        {
                            "name": "District 2",
                            "name_fa": "منطقه ۲",
                            "code": "THR-TEH-02",
                            "center": (51.3347, 35.7289),
                        },
                    ],
                },
                {
                    "name": "Karaj",
                    "name_fa": "کرج",
                    "code": "THR-KAR",
                    "center": (50.9915, 35.8355),
                    "population": 1592492,
                    "districts": [],
                },
            ],
        },
        {
            "name": "Isfahan Province",
            "name_fa": "استان اصفهان",
            "code": "ESF",
            "center": (51.6790, 32.6546),
            "cities": [
                {
                    "name": "Isfahan",
                    "name_fa": "اصفهان",
                    "code": "ESF-ISF",
                    "center": (51.6776, 32.6572),
                    "population": 1961260,
                    "districts": [],
                },
                {
                    "name": "Kashan",
                    "name_fa": "کاشان",
                    "code": "ESF-KAS",
                    "center": (51.4409, 33.9817),
                    "population": 396987,
                    "districts": [],
                },
            ],
        },
        {
            "name": "Fars Province",
            "name_fa": "استان فارس",
            "code": "FAR",
            "center": (52.5319, 29.1044),
            "cities": [
                {
                    "name": "Shiraz",
                    "name_fa": "شیراز",
                    "code": "FAR-SHI",
                    "center": (52.5319, 29.5918),
                    "population": 1565572,
                    "districts": [],
                }
            ],
        },
    ]

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete existing seeded locations before recreating them.",
        )

    def handle(self, *args, **options):
        try:
            with transaction.atomic():
                self._ensure_location_types()
                country = self._create_country(options.get("reset"))
                self._create_provinces(country)
        except Exception as exc:  # pragma: no cover - defensive logging
            raise CommandError(f"Failed to seed Iran locations: {exc}") from exc

        self.stdout.write(self.style.SUCCESS("Successfully seeded Iran locations."))

    def _ensure_location_types(self) -> None:
        type_levels = {
            0: {"code": "country", "name": "Country", "name_fa": "کشور"},
            1: {"code": "province", "name": "Province", "name_fa": "استان"},
            2: {"code": "city", "name": "City", "name_fa": "شهر"},
            3: {"code": "district", "name": "District", "name_fa": "منطقه"},
        }
        for level, payload in type_levels.items():
            LocationType.objects.update_or_create(
                code=payload["code"],
                defaults={
                    "name": payload["name"],
                    "name_fa": payload["name_fa"],
                    "level": level,
                    "is_active": True,
                },
            )

    def _create_country(self, reset: bool) -> Location:
        country_type = LocationType.objects.get(code="country")
        country_defaults = {
            "name": "Iran",
            "name_fa": "ایران",
            "center_point": Point(53.6880, 32.4279, srid=4326),
            "is_active": True,
        }
        country, created = Location.objects.update_or_create(
            code=self.COUNTRY_CODE,
            parent=None,
            defaults={"type": country_type, **country_defaults},
        )
        if reset and not created:
            country.get_descendants(include_self=False).delete()
        return country

    def _create_provinces(self, country: Location) -> None:
        province_type = LocationType.objects.get(code="province")
        city_type = LocationType.objects.get(code="city")
        district_type = LocationType.objects.get(code="district")

        for province_payload in self.PROVINCES:
            province, _ = Location.objects.update_or_create(
                code=province_payload["code"],
                parent=country,
                defaults={
                    "name": province_payload["name"],
                    "name_fa": province_payload["name_fa"],
                    "type": province_type,
                    "center_point": Point(*province_payload["center"], srid=4326),
                    "is_active": True,
                },
            )

            for city_payload in province_payload.get("cities", []):
                city, _ = Location.objects.update_or_create(
                    code=city_payload["code"],
                    parent=province,
                    defaults={
                        "name": city_payload["name"],
                        "name_fa": city_payload["name_fa"],
                        "type": city_type,
                        "center_point": Point(*city_payload["center"], srid=4326),
                        "population": city_payload.get("population"),
                        "is_active": True,
                    },
                )

                for district_payload in city_payload.get("districts", []):
                    Location.objects.update_or_create(
                        code=district_payload["code"],
                        parent=city,
                        defaults={
                            "name": district_payload["name"],
                            "name_fa": district_payload["name_fa"],
                            "type": district_type,
                            "center_point": Point(*district_payload["center"], srid=4326),
                            "is_active": True,
                        },
                    )
