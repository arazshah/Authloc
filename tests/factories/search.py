"""Factories for the `search` app."""
from __future__ import annotations

import factory
from django.utils import timezone

from search.models import PopularSearchTerm, SearchQueryLog, SearchResultClick
from tests.factories.authentication import UserFactory
from tests.factories.base import UserTrackedFactory


class SearchQueryLogFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = SearchQueryLog

    query_text = factory.Sequence(lambda n: f"query {n}")
    normalized_query = factory.LazyAttribute(lambda obj: obj.query_text.lower())
    target = SearchQueryLog.Target.LOCATIONS
    filters = factory.LazyFunction(dict)
    result_count = factory.Faker("pyint", min_value=0, max_value=100)
    duration_ms = factory.Faker("pyint", min_value=10, max_value=1500)
    executed_at = factory.LazyFunction(timezone.now)
    request_metadata = factory.LazyFunction(dict)
    abandoned = False
    latency_ms = factory.LazyAttribute(lambda obj: obj.duration_ms)
    performance_bucket = factory.Iterator(["fast", "moderate", "slow"])


class SearchResultClickFactory(UserTrackedFactory, factory.django.DjangoModelFactory):
    class Meta:
        model = SearchResultClick

    query = factory.SubFactory(SearchQueryLogFactory)
    object_type = "locations"
    object_id = factory.Sequence(lambda n: str(n))
    position = factory.Sequence(lambda n: n)
    metadata = factory.LazyFunction(dict)


class PopularSearchTermFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PopularSearchTerm

    query_text = factory.Sequence(lambda n: f"popular query {n}")
    normalized_query = factory.LazyAttribute(lambda obj: obj.query_text.lower())
    total_count = factory.Faker("pyint", min_value=1, max_value=1000)
    average_duration_ms = factory.Faker("pyfloat", positive=True, right_digits=2, max_value=5000)
    last_result_count = factory.Faker("pyint", min_value=0, max_value=100)
