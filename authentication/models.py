from __future__ import annotations

import uuid

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .constants import ACCOUNT_LOCK_DURATION, MAX_FAILED_LOGIN_ATTEMPTS
from .validators import validate_national_code, validate_phone_number


class CustomUserManager(BaseUserManager):
    """Manager for the custom `User` model."""

    use_in_migrations = True

    def _create_user(self, username: str, email: str, password: str, **extra_fields):
        if not username:
            raise ValueError("The username must be set")
        if not email:
            raise ValueError("The email address must be set")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.full_clean(exclude={"password"})
        user.save(using=self._db)
        return user

    def create_user(self, username: str, email: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username: str, email: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)
        extra_fields.setdefault("failed_login_attempts", 0)
        extra_fields.setdefault("account_locked_until", None)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(username, email, password, **extra_fields)


class CustomUser(AbstractUser):
    """Custom user model for Authloc with security enhancements."""

    email = models.EmailField("email address", unique=True)
    national_code = models.CharField(
        max_length=10,
        unique=True,
        validators=[validate_national_code],
        help_text=_("Iranian national code (10 digits)."),
    )
    phone_number = models.CharField(
        max_length=11,
        unique=True,
        validators=[validate_phone_number],
        help_text=_("Iranian phone number in 09xxxxxxxxx format."),
    )
    employee_id = models.CharField(max_length=64, blank=True)
    department = models.CharField(max_length=128, blank=True)
    position = models.CharField(max_length=128, blank=True)

    is_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, blank=True)
    verification_code_expires_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)

    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True)

    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    preferred_language = models.CharField(max_length=16, default="en")
    last_successful_login = models.DateTimeField(null=True, blank=True)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    last_otp_sent_at = models.DateTimeField(null=True, blank=True)

    objects = CustomUserManager()

    REQUIRED_FIELDS = ["email", "national_code", "phone_number"]

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        db_table = "authentication_user"
        indexes = [
            models.Index(fields=["national_code"]),
            models.Index(fields=["phone_number"]),
            models.Index(fields=["email"]),
        ]

    def __str__(self) -> str:
        return self.get_full_name() or self.username

    @property
    def is_account_locked(self) -> bool:
        if self.account_locked_until is None:
            return False
        return timezone.now() < self.account_locked_until

    def lock_account(self) -> None:
        self.account_locked_until = timezone.now() + ACCOUNT_LOCK_DURATION
        self.failed_login_attempts = 0
        self.save(update_fields=["account_locked_until", "failed_login_attempts"])

    def register_failed_login(self) -> None:
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        self.last_failed_login = timezone.now()
        updates = ["failed_login_attempts", "last_failed_login"]
        if self.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            self.account_locked_until = timezone.now() + ACCOUNT_LOCK_DURATION
            updates.append("account_locked_until")
            self.failed_login_attempts = 0
        self.save(update_fields=updates)

    def reset_failed_attempts(self) -> None:
        if self.failed_login_attempts or self.account_locked_until:
            self.failed_login_attempts = 0
            self.account_locked_until = None
            self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        old_password_hash = None
        if not is_new and self.pk:
            old_password_hash = type(self).objects.only("password").get(pk=self.pk).password
        super().save(*args, **kwargs)
        history_created = False
        if is_new and self.password:
            PasswordHistory.objects.create(user=self, password=self.password)
            history_created = True
        elif old_password_hash is not None and old_password_hash != self.password:
            PasswordHistory.objects.create(user=self, password=self.password)
            history_created = True
        if history_created:
            PasswordHistory.prune_for_user(self)


class PasswordHistory(models.Model):
    """Stores historical password hashes to prevent reuse."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_history")
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Password history for {self.user_id} at {self.created_at:%Y-%m-%d %H:%M:%S}"

    @classmethod
    def prune_for_user(cls, user: "CustomUser", limit: int = 5) -> None:
        ids_to_keep = cls.objects.filter(user=user).order_by("-created_at").values_list("id", flat=True)[:limit]
        cls.objects.filter(user=user).exclude(id__in=list(ids_to_keep)).delete()

    @classmethod
    def is_recent_password(cls, user: "CustomUser", raw_password: str, limit: int = 5) -> bool:
        recent_passwords = cls.objects.filter(user=user).order_by("-created_at")[:limit]
        for entry in recent_passwords:
            if check_password(raw_password, entry.password):
                return True
        return False


class UserSession(models.Model):
    """Tracks active user sessions and token usage."""

    SESSION_TYPES = (
        ("web", "Web"),
        ("mobile", "Mobile"),
        ("api", "API"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions")
    session_type = models.CharField(max_length=16, choices=SESSION_TYPES, default="api")
    refresh_token_jti = models.UUIDField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    device = models.CharField(max_length=128, blank=True)
    location = models.CharField(max_length=256, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["refresh_token_jti"]),
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self) -> str:
        return f"Session {self.pk} for {self.user}"


class LoginActivity(models.Model):
    """Stores login activities for security auditing and anomaly detection."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="login_activities")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    location = models.CharField(max_length=256, blank=True)
    is_suspicious = models.BooleanField(default=False)
    successful = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self) -> str:
        state = "successful" if self.successful else "failed"
        return f"{state} login for {self.user} at {self.created_at:%Y-%m-%d %H:%M:%S}"
