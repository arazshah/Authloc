"""Utility helpers for the `authentication` app."""
from __future__ import annotations

import logging
import random
import string
from typing import Optional, Tuple

from django.http import HttpRequest

logger = logging.getLogger(__name__)


def generate_otp_code(length: int = 6) -> str:
    """Generate a numeric one-time password."""

    return "".join(random.choices(string.digits, k=length))


def get_client_ip(request: HttpRequest) -> Tuple[Optional[str], bool]:
    """Return the client IP address and whether it came from a proxy."""

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
        return ip, True
    return request.META.get("REMOTE_ADDR"), False


def mask_phone_number(phone_number: str) -> str:
    """Mask the middle digits of a phone number for display."""

    if not phone_number or len(phone_number) < 7:
        return phone_number
    return f"{phone_number[:3]}****{phone_number[-3:]}"
