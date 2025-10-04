"""REST API views for authentication endpoints."""
from __future__ import annotations

import logging

from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserSession
from .serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    LogoutSerializer,
    ProfileSerializer,
    RegisterSerializer,
    ResetPasswordSerializer,
    TokenRefreshSerializer,
    VerifyOTPSerializer,
)
from .services import (
    create_user_session,
    deactivate_session_by_jti,
    get_user_by_identifier,
    normalize_jti,
    record_login_activity,
)
from .throttles import LoginRateThrottle, OTPRequestRateThrottle
from .utils import mask_phone_number

logger = logging.getLogger(__name__)

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRequestRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        logger.info("User %s registered. OTP dispatched.", user.pk)

        return Response(
            {
                "detail": _("Registration successful. Please verify the one-time code."),
                "phone_number": mask_phone_number(user.phone_number),
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRequestRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": _("Account verified successfully.")}, status=status.HTTP_200_OK)


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            identifier = request.data.get("identifier")
            user = get_user_by_identifier(identifier)
            if user:
                try:
                    record_login_activity(user=user, request=request, successful=False)
                except Exception:  # pragma: no cover - defensive logging
                    logger.exception("Failed to record failed login activity for user %s", user.pk)
            raise exc

        user = serializer.validated_data["user"]
        ip_address = serializer.validated_data.get("ip_address")
        is_suspicious = serializer.validated_data.get("is_suspicious", False)

        refresh = RefreshToken.for_user(user)
        session = create_user_session(user, refresh, request)

        now = timezone.now()
        user.reset_failed_attempts()
        update_fields = ["failed_login_attempts", "account_locked_until", "last_successful_login", "last_login_ip"]
        user.last_successful_login = now
        if ip_address:
            user.last_login_ip = ip_address
        user.save(update_fields=update_fields)

        record_login_activity(user=user, request=request, successful=True, is_suspicious=is_suspicious)

        access_token = refresh.access_token

        return Response(
            {
                "access": str(access_token),
                "refresh": str(refresh),
                "token_type": "Bearer",
                "expires_in": int(access_token.lifetime.total_seconds()),
                "two_factor_enabled": user.two_factor_enabled,
                "session": {
                    "id": str(session.pk),
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "created_at": session.created_at,
                },
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data["refresh"]

        try:
            token = RefreshToken(refresh_token)
        except TokenError as exc:
            raise InvalidToken({"detail": _("Invalid refresh token."), "code": str(exc)}) from exc

        if str(token["user_id"]) != str(request.user.pk):
            raise InvalidToken({"detail": _("Token does not belong to the authenticated user.")})

        try:
            token.blacklist()
        except TokenError as exc:
            logger.warning("Attempted to blacklist token but failed: %s", exc)
            raise InvalidToken({"detail": _("Invalid refresh token."), "code": str(exc)}) from exc

        deactivate_session_by_jti(request.user, token["jti"])

        return Response({"detail": _("Logged out successfully.")}, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data["refresh"]

        try:
            token = RefreshToken(refresh_token)
        except TokenError as exc:
            raise InvalidToken({"detail": _("Invalid refresh token."), "code": str(exc)}) from exc

        user_id = token.get("user_id")
        user = User.objects.filter(pk=user_id).first()
        if not user:
            raise InvalidToken({"detail": _("Invalid token payload.")})

        access_token = token.access_token

        jti_uuid = normalize_jti(token.get("jti"))
        if jti_uuid:
            UserSession.objects.filter(user=user, refresh_token_jti=jti_uuid, is_active=True).update(
                last_seen_at=timezone.now()
            )

        return Response(
            {
                "access": str(access_token),
                "refresh": str(token),
                "token_type": "Bearer",
                "expires_in": int(access_token.lifetime.total_seconds()),
            },
            status=status.HTTP_200_OK,
        )


class ProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_object(self):
        return self.request.user


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": _("Password updated successfully.")}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRequestRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        status_code = status.HTTP_200_OK
        if result.get("detail") == _("A verification code has been sent."):
            status_code = status.HTTP_202_ACCEPTED
        return Response(result, status=status_code)
