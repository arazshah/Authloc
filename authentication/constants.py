"""Reusable constants for the `authentication` app."""
from __future__ import annotations

from datetime import timedelta

OTP_EXPIRY = timedelta(minutes=5)
OTP_RESEND_INTERVAL = timedelta(seconds=30)
MAX_FAILED_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
PASSWORD_HISTORY_SIZE = 5
