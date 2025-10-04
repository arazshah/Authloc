from .base import *  # noqa

DEBUG = True
DJANGO_DEBUG = True
ENVIRONMENT = "development"

ALLOWED_HOSTS = ["localhost", "127.0.0.1"][0:]

INSTALLED_APPS += [  # noqa: F405
    "debug_toolbar",
]

MIDDLEWARE.insert(2, "debug_toolbar.middleware.DebugToolbarMiddleware")  # noqa: F405

INTERNAL_IPS = ["127.0.0.1", "0.0.0.0"]

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

CORS_ALLOW_ALL_ORIGINS = True

REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] += (  # type: ignore # noqa: F405
    "rest_framework.renderers.BrowsableAPIRenderer",
)
