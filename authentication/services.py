"""Domain services for the `authentication` app."""
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

import pyotp

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from rest_framework_simplejwt.tokens import RefreshToken

from .constants import OTP_EXPIRY, OTP_RESEND_INTERVAL
from .models import CustomUser, LoginActivity, UserSession
from .utils import generate_otp_code, get_client_ip

logger = logging.getLogger(__name__)


def normalize_identifier(identifier: str) -> str:
    return (identifier or "").strip().lower()


def get_user_by_identifier(identifier: str) -> Optional[CustomUser]:
    identifier = normalize_identifier(identifier)
    if not identifier:
        return None

    try:
        return CustomUser.objects.get(email__iexact=identifier)
    except CustomUser.DoesNotExist:
        pass

    try:
        return CustomUser.objects.get(phone_number=identifier)
    except CustomUser.DoesNotExist:
        pass

    try:
        return CustomUser.objects.get(username__iexact=identifier)
    except CustomUser.DoesNotExist:
        return None


def normalize_jti(value) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def generate_and_send_otp(user: CustomUser, *, reason: str = "verification") -> str:
    code = generate_otp_code()
    now = timezone.now()
    if user.last_otp_sent_at and now - user.last_otp_sent_at < OTP_RESEND_INTERVAL:
        raise ValidationError(
            _("A verification code was sent recently. Please wait before requesting a new one."),
            code="otp_rate_limited",
        )
    user.verification_code = code
    user.verification_code_expires_at = now + OTP_EXPIRY
    user.last_otp_sent_at = now
    user.save(update_fields=["verification_code", "verification_code_expires_at", "last_otp_sent_at"])
    logger.info("Sent OTP %s to user %s for %s", code, user.pk, reason)
    return code


def validate_otp(user: CustomUser, code: str) -> bool:
    if not code or not user.verification_code:
        return False
    if user.verification_code_expires_at and timezone.now() > user.verification_code_expires_at:
        return False
    return code == user.verification_code


def clear_otp(user: CustomUser) -> None:
    user.verification_code = ""
    user.verification_code_expires_at = None
    user.last_otp_sent_at = None
    user.save(update_fields=["verification_code", "verification_code_expires_at", "last_otp_sent_at"])


def create_user_session(user: CustomUser, refresh_token: RefreshToken, request) -> UserSession:
    ip_address, _ = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:512]
    location = ""
    jti = normalize_jti(refresh_token.get("jti"))
    session = UserSession.objects.create(
        user=user,
        refresh_token_jti=jti,
        ip_address=ip_address,
        user_agent=user_agent,
        device=request.META.get("HTTP_DEVICE", "")[:128],
        location=location,
        session_type="api",
    )
    return session


def deactivate_session_by_jti(user: CustomUser, jti: str) -> None:
    jti_uuid = normalize_jti(jti)
    if not jti_uuid:
        return
    UserSession.objects.filter(user=user, refresh_token_jti=jti_uuid).update(is_active=False)


def record_login_activity(*, user: CustomUser, request, successful: bool, is_suspicious: bool = False) -> LoginActivity:
    ip_address, _ = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:512]
    location = ""
    activity = LoginActivity.objects.create(
        user=user,
        ip_address=ip_address,
        user_agent=user_agent,
        location=location,
        is_suspicious=is_suspicious,
        successful=successful,
    )
    return activity


def detect_suspicious_login(user: CustomUser, ip_address: Optional[str]) -> bool:
    if not ip_address:
        return False
    if not user.last_login_ip:
        return False
    return user.last_login_ip != ip_address


def ensure_two_factor_secret(user: CustomUser) -> str:
    if user.two_factor_secret:
        return user.two_factor_secret
    user.two_factor_secret = pyotp.random_base32()
    user.save(update_fields=["two_factor_secret"])
    return user.two_factor_secret


def verify_two_factor_code(user: CustomUser, code: str) -> bool:
    if not user.two_factor_enabled:
        return True
    if not user.two_factor_secret:
        return False
    totp = pyotp.TOTP(user.two_factor_secret)
    return bool(code and totp.verify(code, valid_window=1))
