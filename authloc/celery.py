import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", os.getenv("DJANGO_SETTINGS_MODULE", "authloc.settings"))

app = Celery("authloc")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    from django.conf import settings

    return {
        "request_id": getattr(self.request, "id", None),
        "args": self.request.args,
        "kwargs": self.request.kwargs,
        "settings_module": settings.SETTINGS_MODULE,
    }
