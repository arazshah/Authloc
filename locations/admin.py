from django.contrib import admin
from leaflet.admin import LeafletGeoAdmin

from .models import Location, LocationType, LocationVerification, TrustedLocation


@admin.register(LocationType)
class LocationTypeAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "level", "is_active", "created_at", "updated_at")
    list_filter = ("level", "is_active")
    search_fields = ("name", "name_fa", "code")
    ordering = ("level", "name")
    readonly_fields = ("created_at", "updated_at")


@admin.register(Location)
class LocationAdmin(LeafletGeoAdmin):
    list_display = ("name", "code", "type", "level", "parent", "is_active")
    list_filter = ("type__level", "type", "is_active")
    search_fields = ("name", "name_fa", "code", "postal_code")
    ordering = ("path",)
    readonly_fields = ("level", "path", "area_sqm", "perimeter_m", "created_at", "updated_at")
    autocomplete_fields = ("type", "parent")
    raw_id_fields = ("parent",)
    fieldsets = (
        (None, {"fields": ("name", "name_fa", "code", "type", "parent", "is_active")}),
        (
            "Spatial information",
            {"fields": ("geometry", "center_point", "area_sqm", "perimeter_m")},
        ),
        (
            "Additional details",
            {"fields": ("population", "postal_code", "description", "metadata", "path", "level")},
        ),
        (
            "Audit",
            {"fields": ("created_by", "updated_by", "created_at", "updated_at")},
        ),
    )

    def get_queryset(self, request):  # pragma: no cover - admin helper
        queryset = super().get_queryset(request)
        return queryset.select_related("type", "parent", "created_by", "updated_by")


@admin.register(TrustedLocation)
class TrustedLocationAdmin(LeafletGeoAdmin):
    list_display = ("name", "user", "radius_meters", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name", "user__username", "user__email")
    autocomplete_fields = ("user",)


@admin.register(LocationVerification)
class LocationVerificationAdmin(admin.ModelAdmin):
    list_display = ("user", "trusted_location", "status", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("user__username", "user__email", "trusted_location__name")
    autocomplete_fields = ("user", "trusted_location")
