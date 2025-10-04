from django.contrib import admin

from .models import Role, RoleAssignmentRequest, UserRole


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "is_system_role", "priority", "parent_role", "is_active")
    list_filter = ("is_system_role", "is_active")
    search_fields = ("name", "code", "description")
    autocomplete_fields = ("parent_role",)
    ordering = ("priority", "name")


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "location", "is_active", "valid_from", "valid_until")
    list_filter = ("is_active", "role")
    search_fields = ("user__username", "user__email", "role__name", "role__code")
    autocomplete_fields = ("user", "role", "location", "assigned_by")


@admin.register(RoleAssignmentRequest)
class RoleAssignmentRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "status", "requested_by", "approver", "created_at")
    list_filter = ("status", "role", "created_at")
    search_fields = (
        "user__username",
        "user__email",
        "role__name",
        "role__code",
        "requested_by__username",
        "requested_by__email",
    )
    autocomplete_fields = ("user", "role", "location", "requested_by", "approver", "created_user_role")
