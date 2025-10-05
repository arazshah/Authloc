from django.apps import AppConfig


class SearchConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "search"
    verbose_name = "Search"

    def ready(self) -> None:
        # Importing analytics signals ensures they are registered on startup
        from . import signals  # noqa: F401  # pragma: no cover

        return super().ready()
