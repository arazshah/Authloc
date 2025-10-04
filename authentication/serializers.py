"""Serializers for the `authentication` API."""
from __future__ import annotations

from typing import Optional

from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .services import (
    clear_otp,
    detect_suspicious_login,
    generate_and_send_otp,
    get_user_by_identifier,
    ensure_two_factor_secret,
    validate_otp,
    verify_two_factor_code,
)
from .utils import mask_phone_number

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "national_code",
            "phone_number",
            "password",
            "employee_id",
            "department",
            "position",
            "preferred_language",
        )
        extra_kwargs = {
            "preferred_language": {"default": "en", "required": False},
        }

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        user.is_verified = False
        user.save(update_fields=["is_verified"])
        try:
            generate_and_send_otp(user, reason="registration")
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"detail": exc.messages[0]}) from exc
        return user


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    otp_code = serializers.CharField(write_only=True, required=False, allow_blank=True)

    def _validate_identifier(self, identifier: str) -> Optional[User]:
        return get_user_by_identifier(identifier)

    def validate(self, attrs):
        request = self.context.get("request")
        identifier = attrs.get("identifier")
        password = attrs.get("password")
        otp_code = attrs.get("otp_code")

        user = self._validate_identifier(identifier)
        if not user:
            raise serializers.ValidationError({"identifier": _("Invalid credentials provided.")})

        if user.is_account_locked:
            raise serializers.ValidationError({"detail": _("Account is temporarily locked due to failed attempts.")})

        if not user.check_password(password):
            user.register_failed_login()
            raise serializers.ValidationError({"identifier": _("Invalid credentials provided.")})

        if not user.is_verified:
            raise serializers.ValidationError({"detail": _("Account is not verified. Please verify OTP first.")})

        if user.two_factor_enabled:
            if not otp_code:
                raise serializers.ValidationError({"otp_code": _("Two-factor code is required.")})
            if not user.two_factor_secret:
                ensure_two_factor_secret(user)
            if not verify_two_factor_code(user, otp_code):
                raise serializers.ValidationError({"otp_code": _("Invalid two-factor code.")})

        attrs["user"] = user
        attrs["is_suspicious"] = False

        if request:
            ip_address = request.META.get("REMOTE_ADDR")
            attrs["ip_address"] = ip_address
            attrs["is_suspicious"] = detect_suspicious_login(user, ip_address)

        return attrs


class ProfileSerializer(serializers.ModelSerializer):
    two_factor_secret = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "national_code",
            "phone_number",
            "employee_id",
            "department",
            "position",
            "preferred_language",
            "two_factor_enabled",
            "two_factor_secret",
            "last_login",
            "last_login_ip",
        )
        read_only_fields = ("username", "email", "national_code", "phone_number", "last_login", "last_login_ip")

    def update(self, instance, validated_data):
        two_factor_enabled = validated_data.get("two_factor_enabled", instance.two_factor_enabled)
        instance = super().update(instance, validated_data)

        if two_factor_enabled and not instance.two_factor_secret:
            ensure_two_factor_secret(instance)
        elif not two_factor_enabled:
            instance.two_factor_secret = ""
            instance.save(update_fields=["two_factor_secret"])
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, style={"input_type": "password"})
    new_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate_current_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Current password is incorrect."))
        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value, user=self.context["request"].user)
        return value

    def save(self, **kwargs):
        user = self.context["request"].user
        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.reset_failed_attempts()
        user.save()
        clear_otp(user)
        return user


class ResetPasswordSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    verification_code = serializers.CharField(required=False, allow_blank=True)
    new_password = serializers.CharField(required=False, allow_blank=True, style={"input_type": "password"})

    def validate(self, attrs):
        identifier = attrs.get("identifier")
        user = get_user_by_identifier(identifier)
        if not user:
            raise serializers.ValidationError({"identifier": _("No account found for this identifier.")})
        attrs["user"] = user

        code = attrs.get("verification_code")
        password = attrs.get("new_password")
        if code:
            if not password:
                raise serializers.ValidationError({"new_password": _("New password is required.")})
            password_validation.validate_password(password, user=user)
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        code = self.validated_data.get("verification_code")
        password = self.validated_data.get("new_password")

        if not code:
            try:
                generate_and_send_otp(user, reason="password_reset")
            except DjangoValidationError as exc:
                raise serializers.ValidationError({"detail": exc.messages[0]}) from exc
            return {
                "detail": _("A verification code has been sent."),
                "phone_number": mask_phone_number(user.phone_number),
            }

        if not validate_otp(user, code):
            raise serializers.ValidationError({"verification_code": _("Invalid or expired verification code.")})

        user.set_password(password)
        user.reset_failed_attempts()
        user.save()
        clear_otp(user)
        return {"detail": _("Password has been reset successfully.")}


class VerifyOTPSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    verification_code = serializers.CharField()

    def validate(self, attrs):
        identifier = attrs.get("identifier")
        user = get_user_by_identifier(identifier)
        if not user:
            raise serializers.ValidationError({"identifier": _("Account not found.")})
        attrs["user"] = user
        return attrs

    def save(self, **kwargs):
        user: User = self.validated_data["user"]
        code = self.validated_data["verification_code"]
        if not validate_otp(user, code):
            raise serializers.ValidationError({"verification_code": _("Invalid or expired verification code.")})
        user.is_verified = True
        user.save(update_fields=["is_verified"])
        clear_otp(user)
        return user


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class TwoFactorSetupSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()

    def validate_enabled(self, value):
        if not isinstance(value, bool):
            raise serializers.ValidationError(_("Invalid value."))
        return value
