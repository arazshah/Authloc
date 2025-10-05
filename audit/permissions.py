from rest_framework.permissions import BasePermission


class IsSecurityAuditor(BasePermission):
    """
    Custom permission to only allow access to security auditors.

    This permission allows access to users who have been designated as
    security auditors. In a production system, this would be based on
    user roles or permissions.
    """

    def has_permission(self, request, view):
        # For now, allow any authenticated user
        # In production, this should check for specific roles/permissions
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # For now, allow any authenticated user to access objects
        # In production, this should check for specific object-level permissions
        return request.user and request.user.is_authenticated
