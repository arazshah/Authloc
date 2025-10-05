from __future__ import annotations

import time
from datetime import timedelta

from django.contrib.gis.geos import Point
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.models import CustomUser
from audit.models import AuditLog
from core.cache_utils import cache_key_generator, cache_manager
from locations.models import Location, LocationType
from search.models import PopularSearchTerm, SearchQueryLog


class SearchPerformanceTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="tester",
            email="tester@example.com",
            password="pass1234",
        )
        cls.user.is_staff = True
        cls.user.save(update_fields=["is_staff"])

        cls.location_type = LocationType.objects.create(
            name="City",
            code="CITY",
            level=LocationType.Levels.CITY,
        )
        cls.location = Location.objects.create(
            name="Sample City",
            code="SAMPLE",
            type=cls.location_type,
            geometry=Point(51.3890, 35.6892, srid=4326),
            center_point=Point(51.3890, 35.6892, srid=4326),
            created_by=cls.user,
            updated_by=cls.user,
        )

        cls.audit_log = AuditLog.objects.create(
            action=AuditLog.Actions.READ,
            user=cls.user,
            username=cls.user.username,
            resource_type="location",
            resource_id=str(cls.location.pk),
            resource_name=cls.location.name,
            request_method="GET",
            request_path="/api/test/",
            response_status=200,
            executed_at=timezone.now(),
        )

        PopularSearchTerm.objects.create(
            query_text="sample",
            normalized_query="sample",
            total_count=10,
            average_duration_ms=100.0,
        )

        SearchQueryLog.objects.create(
            query_text="sample",
            normalized_query="sample",
            target="locations",
            filters={},
            result_count=1,
            duration_ms=120,
            latency_ms=120,
            executed_at=timezone.now() - timedelta(days=1),
            request_metadata={},
            performance_bucket="fast",
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def test_location_search_performance(self):
        payload = {
            "query": "",
            "include_facets": True,
            "pagination": {"page": 1, "page_size": 10},
        }
        url = reverse("search:locations")

        start = time.perf_counter()
        response = self.client.post(url, payload, format="json")
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertLess(elapsed_ms, 500, "Location search should complete in < 500ms")
        data = response.json()
        self.assertGreaterEqual(data["pagination"]["total"], 1)
        self.assertLessEqual(data["duration_ms"], 1000)
        self.assertGreaterEqual(SearchQueryLog.objects.filter(target="locations").count(), 1)

    def test_suggestions_are_cached(self):
        prefix = "sample"
        cache_key = cache_key_generator.generate_cache_key("search", "suggestions", prefix)
        cache_manager.cache.delete(cache_key)

        url = reverse("search:suggestions", kwargs={"query": prefix})
        first_response = self.client.get(url)
        self.assertEqual(first_response.status_code, status.HTTP_200_OK)
        cached = cache_manager.cache.get(cache_key)
        self.assertIsNotNone(cached)
        second_response = self.client.get(url)
        self.assertEqual(second_response.status_code, status.HTTP_200_OK)
        self.assertEqual(first_response.json(), second_response.json())

    def test_advanced_search_aggregate_performance(self):
        payload = {
            "query": "",
            "targets": ["locations", "users", "audit_logs"],
            "include_facets": False,
            "pagination": {"page": 1, "page_size": 5},
            "filters": {},
        }
        url = reverse("search:advanced")

        start = time.perf_counter()
        response = self.client.post(url, payload, format="json")
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertLess(elapsed_ms, 800, "Advanced search should complete in < 800ms")
        data = response.json()
        self.assertIn("results", data)
        self.assertIn("locations", data["results"])
        self.assertIn("users", data["results"])
        self.assertIn("audit_logs", data["results"])
        self.assertLessEqual(data.get("duration_ms", 0), 1500)
