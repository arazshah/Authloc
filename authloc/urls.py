"""
URL configuration for authloc project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, re_path

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from authloc.schema import APITestPlaygroundView, PostmanCollectionView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/auth/", include("authentication.urls", namespace="authentication")),
    path("api/v1/locations/", include("locations.urls", namespace="locations")),
    path("api/v1/permissions/", include("permissions.urls", namespace="permissions")),
    path("api/v1/search/", include("search.urls", namespace="search")),
    path("", include("audit.urls", namespace="audit")),
    path("api/schema/", SpectacularAPIView.as_view(api_version="1.0"), name="api-schema"),
    path(
        "api/schema/swagger/",
        SpectacularSwaggerView.as_view(url_name="api-schema"),
        name="api-swagger-ui",
    ),
    path(
        "api/schema/redoc/",
        SpectacularRedocView.as_view(url_name="api-schema"),
        name="api-redoc",
    ),
    path(
        "api/schema/postman/",
        PostmanCollectionView.as_view(),
        name="api-postman",
    ),
    path(
        "api/playground/",
        APITestPlaygroundView.as_view(),
        name="api-playground",
    ),
]
