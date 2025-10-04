from django.contrib.auth.models import AbstractUser
from django.contrib.gis.db import models


class User(AbstractUser):
    phone_number = models.CharField(max_length=32, blank=True)
    is_phone_verified = models.BooleanField(default=False)
    last_known_location = models.PointField(null=True, blank=True, geography=True)
    location_accuracy = models.FloatField(null=True, blank=True)
    last_location_update = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self) -> str:
        return self.get_full_name() or self.username
