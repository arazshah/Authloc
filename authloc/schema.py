"""Custom schema utilities and documentation endpoints for Authloc."""
from __future__ import annotations

import json
from typing import Any, Iterable

from django.http import HttpRequest, HttpResponse
from django.urls import reverse_lazy
from django.views.generic import TemplateView
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.views import SpectacularAPIView


class PostmanCollectionView(SpectacularAPIView):
    """Serve the OpenAPI schema as a Postman collection download."""

    content_type = "application/json"
    allowed_methods: Iterable[str] = {"get", "post", "put", "patch", "delete"}

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        schema_response = super().get(request, *args, **kwargs)
        schema = json.loads(schema_response.rendered_content)
        collection = self._convert_to_postman(schema)
        return HttpResponse(
            json.dumps(collection, indent=2),
            content_type=self.content_type,
            headers={"Content-Disposition": "attachment; filename=authloc-postman.json"},
        )

    def _convert_to_postman(self, schema: dict[str, Any]) -> dict[str, Any]:
        info = schema.get("info", {})
        servers = schema.get("servers", [])
        base_url = servers[0]["url"] if servers else "{{base_url}}"
        items = self._build_items(schema.get("paths", {}), base_url)

        return {
            "info": {
                "name": info.get("title", "Authloc API"),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                "description": info.get("description", "Authloc API collection"),
            },
            "item": items,
            "variable": [
                {"key": "base_url", "value": base_url},
                {"key": "access_token", "value": ""},
            ],
        }

    def _build_items(self, paths: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
        folders: dict[str, list[dict[str, Any]]] = {}
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.lower() not in self.allowed_methods:
                    continue
                tag = (operation.get("tags") or ["General"])[0]
                folders.setdefault(tag, []).append(
                    self._build_item(base_url, path, method, operation)
                )

        folder_items = []
        for tag, operations in sorted(folders.items()):
            folder_items.append({"name": tag, "item": operations})
        return folder_items

    def _build_item(self, base_url: str, path: str, method: str, operation: dict[str, Any]) -> dict[str, Any]:
        raw_url = base_url.rstrip("/") + path
        request: dict[str, Any] = {
            "method": method.upper(),
            "header": self._build_headers(operation),
            "url": {
                "raw": raw_url,
                "host": ["{{base_url}}"],
                "path": [segment for segment in path.strip("/").split("/") if segment],
                "query": self._build_query_params(operation),
                "variable": self._build_path_variables(operation),
            },
        }

        body = self._build_request_body(operation)
        if body:
            request["body"] = body

        return {
            "name": operation.get("summary") or operation.get("operationId") or raw_url,
            "request": request,
            "response": [],
        }

    def _build_query_params(self, operation: dict[str, Any]) -> list[dict[str, Any]]:
        params = []
        for parameter in operation.get("parameters", []):
            if parameter.get("in") != "query":
                continue
            params.append(
                {
                    "key": parameter.get("name"),
                    "value": parameter.get("example", ""),
                    "description": parameter.get("description", ""),
                }
            )
        return params

    def _build_path_variables(self, operation: dict[str, Any]) -> list[dict[str, Any]]:
        variables = []
        for parameter in operation.get("parameters", []):
            if parameter.get("in") != "path":
                continue
            variables.append(
                {
                    "key": parameter.get("name"),
                    "value": parameter.get("example", ""),
                    "description": parameter.get("description", ""),
                }
            )
        return variables

    def _build_request_body(self, operation: dict[str, Any]) -> dict[str, Any] | None:
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        if not content:
            return None

        media_type = next(iter(content))
        media_schema = content[media_type]

        example = media_schema.get("example")
        if example is None:
            examples = media_schema.get("examples") or {}
            if examples:
                example = next(iter(examples.values())).get("value")
        if example is None:
            example = {}

        body = {
            "mode": "raw",
            "raw": json.dumps(example, indent=2) if isinstance(example, (dict, list)) else str(example),
            "options": {"raw": {"language": "json" if "json" in media_type else "text"}},
        }

        return body

    def _build_headers(self, operation: dict[str, Any]) -> list[dict[str, Any]]:
        headers = []
        security = operation.get("security") or spectacular_settings.SECURITY_DEFAULT
        if security:
            headers.append(
                {
                    "key": "Authorization",
                    "value": "Bearer {{access_token}}",
                    "description": "JWT access token",
                }
            )
        request_body = operation.get("requestBody") or {}
        if request_body.get("content"):
            headers.append(
                {
                    "key": "Content-Type",
                    "value": next(iter(request_body["content"].keys()), "application/json"),
                }
            )
        return headers


class APITestPlaygroundView(TemplateView):
    """Simple interactive playground for manual API exploration."""

    template_name = "api/playground.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context.update(
            {
                "schema_url": reverse_lazy("api-schema"),
                "swagger_url": reverse_lazy("api-swagger-ui"),
            }
        )
        return context


__all__ = ["APITestPlaygroundView", "PostmanCollectionView"]
