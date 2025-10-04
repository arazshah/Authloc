"""Field validators for the `authentication` app."""
from __future__ import annotations

import re
import string

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


NATIONAL_CODE_REGEX = re.compile(r"^(\d{10})$")
PHONE_NUMBER_REGEX = re.compile(r"^09\d{9}$")


def validate_national_code(value: str) -> None:
    """Validate Iranian national identification code using the control digit."""

    match = NATIONAL_CODE_REGEX.fullmatch(value or "")
    if not match:
        raise ValidationError(_("Enter a valid 10-digit national code."))

    digits = [int(char) for char in match.group(1)]
    if len({*digits}) == 1:
        raise ValidationError(_("Invalid national code."))

    checksum = sum(d * (10 - idx) for idx, d in enumerate(digits[:-1]))
    remainder = checksum % 11
    check_digit = digits[-1]

    if remainder < 2:
        if check_digit != remainder:
            raise ValidationError(_("Invalid national code."))
    elif check_digit != (11 - remainder):
        raise ValidationError(_("Invalid national code."))


def validate_phone_number(value: str) -> None:
    """Validate Iranian mobile phone numbers in the 09xxxxxxxxx format."""

    if not PHONE_NUMBER_REGEX.fullmatch(value or ""):
        raise ValidationError(_("Enter a valid Iranian phone number (09xxxxxxxxx)."))


class PasswordStrengthValidator:
    """Ensure strong passwords according to project policy."""

    min_length = 8

    def validate(self, password: str, user=None):
        if len(password or "") < self.min_length:
            raise ValidationError(
                _("Password must be at least %(min_length)d characters long."),
                code="password_too_short",
                params={"min_length": self.min_length},
            )

        if not any(ch.isupper() for ch in password):
            raise ValidationError(_("Password must contain at least one uppercase letter."), code="password_no_uppercase")

        if not any(ch.islower() for ch in password):
            raise ValidationError(_("Password must contain at least one lowercase letter."), code="password_no_lowercase")

        if not any(ch.isdigit() for ch in password):
            raise ValidationError(_("Password must contain at least one digit."), code="password_no_digit")

        if not any(ch in string.punctuation for ch in password):
            raise ValidationError(_("Password must contain at least one special character."), code="password_no_special")

    def get_help_text(self):
        return _(
            "Your password must contain at least 8 characters, including uppercase, lowercase, digits, and special characters."
        )


class PasswordHistoryValidator:
    """Prevent reuse of recent passwords."""

    def __init__(self, history_size: int = 5):
        self.history_size = history_size

    def validate(self, password: str, user=None):
        if user is None or not getattr(user, "pk", None):
            return

        from .models import PasswordHistory

        if PasswordHistory.is_recent_password(user, password, limit=self.history_size):
            raise ValidationError(
                _(f"You cannot reuse any of your last {self.history_size} passwords."),
                code="password_in_history",
            )

    def get_help_text(self):
        return _(f"You cannot reuse your most recent {self.history_size} passwords.")
