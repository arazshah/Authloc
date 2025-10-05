"""Unit tests for authentication models."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from authentication.constants import ACCOUNT_LOCK_DURATION, MAX_FAILED_LOGIN_ATTEMPTS
from authentication.models import CustomUser, PasswordHistory, UserSession
from tests.factories.authentication import (
    StaffUserFactory,
    UserFactory,
    UserSessionFactory,
)

pytestmark = pytest.mark.auth


class TestCustomUserModel:
    """Tests for `authentication.models.CustomUser`."""

    def test_register_failed_login_increments_and_locks_account(self):
        user = UserFactory(failed_login_attempts=0, account_locked_until=None)

        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
            user.register_failed_login()

        user.refresh_from_db()
        assert user.failed_login_attempts == 0
        assert user.account_locked_until is not None
        assert user.account_locked_until > timezone.now()

    def test_reset_failed_attempts_clears_state(self):
        lock_until = timezone.now() + ACCOUNT_LOCK_DURATION
        user = UserFactory(failed_login_attempts=3, account_locked_until=lock_until)

        user.reset_failed_attempts()
        user.refresh_from_db()

        assert user.failed_login_attempts == 0
        assert user.account_locked_until is None

    def test_save_creates_password_history(self):
        user = UserFactory(password="secret123")
        histories = PasswordHistory.objects.filter(user=user)
        assert histories.count() == 1
        assert histories.first().password == user.password

    def test_save_updates_password_history_on_change(self):
        user = UserFactory(password="secret123")
        original_history_count = PasswordHistory.objects.filter(user=user).count()

        user.set_password("newsecret456")
        user.save()

        histories = PasswordHistory.objects.filter(user=user)
        assert histories.count() == original_history_count + 1
        assert histories.first().password == user.password

    def test_password_history_prunes_old_entries(self):
        user = UserFactory()
        for index in range(MAX_FAILED_LOGIN_ATTEMPTS + 2):
            user.set_password(f"password{index}")
            user.save()

        assert PasswordHistory.objects.filter(user=user).count() <= 5


class TestUserSessionModel:
    """Tests for `authentication.models.UserSession`."""

    def test_session_string_representation(self):
        session = UserSessionFactory()
        assert str(session).startswith("Session")

    def test_user_session_updates_last_seen_on_refresh(self):
        session = UserSessionFactory(is_active=True)
        original_last_seen = session.last_seen_at

        CustomUser.objects.filter(pk=session.user.pk).update(last_login=timezone.now())
        session.refresh_from_db()

        assert session.last_seen_at >= original_last_seen

    def test_user_session_can_be_inactivated(self):
        session = UserSessionFactory(is_active=True)
        session.is_active = False
        session.save(update_fields=["is_active"])

        session.refresh_from_db()
        assert not session.is_active
