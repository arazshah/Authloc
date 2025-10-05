from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import AuditLogViewSet, AuditReportsViewSet, SecurityAlertViewSet, UserActivityViewSet

# Create a router for the audit API
router = DefaultRouter()
router.register(r'logs', AuditLogViewSet, basename='audit-log')
router.register(r'security-alerts', SecurityAlertViewSet, basename='security-alert')
router.register(r'user-activity', UserActivityViewSet, basename='user-activity')
router.register(r'reports', AuditReportsViewSet, basename='audit-reports')

app_name = 'audit'

urlpatterns = [
    # Include router URLs
    path('api/v1/', include(router.urls)),
]
