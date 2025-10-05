"""Base factory utilities."""
from __future__ import annotations

import factory
from django.contrib.auth import get_user_model
from factory import LazyAttribute


class TimeStampedFactory(factory.django.DjangoModelFactory):
    """Base factory providing timestamp auto attributes."""

    class Meta:
        abstract = True


class UserTrackedFactory(TimeStampedFactory):
    """Base factory that sets created_by/updated_by when available."""

    @factory.lazy_attribute
    def created_by(self):
        user_model = get_user_model()
        if user_model.objects.exists():
            return user_model.objects.order_by("-date_joined").first()
        return None

    @factory.lazy_attribute
    def updated_by(self):
        return self.created_by
