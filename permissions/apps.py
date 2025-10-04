from django.apps import AppConfig


class PermissionsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "permissions"

    def ready(self) -> None:
        # Import signal handlers to keep permission cache coherent.
        from . import signals  # noqa: F401  # pragma: no cover

        return super().ready()
