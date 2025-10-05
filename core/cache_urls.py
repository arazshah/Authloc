"""
Cache management API URLs.
"""

from django.urls import path
from . import cache_api

app_name = 'cache'

urlpatterns = [
    path('stats/', cache_api.cache_stats, name='cache_stats'),
    path('clear/', cache_api.cache_clear, name='cache_clear'),
    path('warm/', cache_api.cache_warm, name='cache_warm'),
    path('invalidate-user/', cache_api.cache_invalidate_user, name='cache_invalidate_user'),
    path('health/', cache_api.cache_health, name='cache_health'),
]
