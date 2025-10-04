from django.contrib import admin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    search_fields = ("username", "email", "national_code", "phone_number")
    list_display = ("username", "email", "is_active", "is_staff", "is_verified")
