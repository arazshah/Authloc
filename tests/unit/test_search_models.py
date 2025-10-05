"""Unit tests for `search` models."""
from __future__ import annotations

import pytest

from search.models import PopularSearchTerm, SearchQueryLog
from tests.factories.search import PopularSearchTermFactory, SearchQueryLogFactory

pytestmark = pytest.mark.search


class TestSearchQueryLog:
    def test_query_log_str(self):
        log = SearchQueryLogFactory(query_text="Test Query", target=SearchQueryLog.Target.USERS)
        assert "Test Query" in str(log)

    def test_performance_bucket_population(self):
        log = SearchQueryLogFactory(performance_bucket="fast")
        assert log.performance_bucket == "fast"


class TestPopularSearchTerm:
    def test_update_from_log_creates_entry(self):
        log = SearchQueryLogFactory(query_text="Central Park")
        term = PopularSearchTerm.update_from_log(log)
        assert term.query_text == "Central Park"
        assert term.total_count >= 1

    def test_update_from_log_updates_existing_entry(self):
        log = SearchQueryLogFactory(query_text="Museum", duration_ms=200)
        term = PopularSearchTerm.update_from_log(log)
        updated_log = SearchQueryLogFactory(query_text="Museum", duration_ms=100)
        updated_term = PopularSearchTerm.update_from_log(updated_log)

        assert updated_term.pk == term.pk
        assert updated_term.total_count >= 2
        assert updated_term.average_duration_ms > 0
