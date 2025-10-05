"""Factories for the `authentication` app."""
from __future__ import annotations

import datetime as dt
import factory
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

from authentication.models import LoginActivity, PasswordHistory, UserSession

User = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):
    """Factory for `authentication.CustomUser`."""

    class Meta:
        model = User
        django_get_or_create = ("username",)

    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    national_code = factory.Sequence(lambda n: f"{n:010d}")
    phone_number = factory.Sequence(lambda n: f"0912{n:07d}")
    employee_id = factory.Sequence(lambda n: f"EMP{n:05d}")
    department = factory.Faker("job")
    position = factory.Faker("job")
    is_verified = True
    preferred_language = "en"

    @factory.post_generation
    def password(self, create: bool, extracted: str | None, **kwargs):  # noqa: D401 - factory hook
        """Set a usable password."""
        password = extracted or "password123"
        self.set_password(password)
        if create:
            self.save(update_fields=["password"])


class StaffUserFactory(UserFactory):
    """Factory for staff/superuser accounts."""

    is_staff = True
    is_superuser = True


class PasswordHistoryFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PasswordHistory

    user = factory.SubFactory(UserFactory)
    password = factory.LazyAttribute(lambda _: make_password("password123"))


class UserSessionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UserSession

    user = factory.SubFactory(UserFactory)
    session_type = "api"
    ip_address = factory.Faker("ipv4")
    user_agent = factory.Faker("user_agent")
    is_active = True


class LoginActivityFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LoginActivity

    user = factory.SubFactory(UserFactory)
    ip_address = factory.Faker("ipv4")
    user_agent = factory.Faker("user_agent")
    is_suspicious = False
    successful = True
    location = factory.Faker("city")
