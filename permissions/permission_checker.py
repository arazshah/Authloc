from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union
from uuid import UUID

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from locations.models import Location

from .models import FieldPermission, LocationAccess

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TIMEOUT = 300  # seconds

_ACTION_ATTRIBUTE_MAP: Dict[str, str] = {
    "read": "can_read",
    "view": "can_read",
    "list": "can_read",
    "retrieve": "can_read",
    "detail": "can_read",
    "create": "can_create",
    "add": "can_create",
    "write": "can_update",
    "update": "can_update",
    "partial_update": "can_update",
    "edit": "can_update",
    "patch": "can_update",
    "delete": "can_delete",
    "destroy": "can_delete",
    "remove": "can_delete",
    "admin": "can_admin",
    "manage": "can_admin",
}

_FIELD_ACTION_MAP: Dict[str, str] = {
    "read": "read",
    "view": "read",
    "list": "read",
    "retrieve": "read",
    "detail": "read",
    "create": "write",
    "add": "write",
    "write": "write",
    "update": "write",
    "partial_update": "write",
    "edit": "write",
    "patch": "write",
    "delete": "write",
    "destroy": "write",
    "remove": "write",
    "admin": "write",
    "manage": "write",
}


@dataclass(frozen=True)
class AccessRecord:
    """Serialized snapshot of a `LocationAccess` entry for caching."""

    id: UUID
    user_id: UUID
    location_id: Optional[UUID]
    location_path: Optional[str]
    inherit_to_children: bool
    role_id: UUID
    role_code: Optional[str]
    can_read: bool
    can_create: bool
    can_update: bool
    can_delete: bool
    can_admin: bool
    accessible_fields: Tuple[str, ...]
    restricted_fields: Tuple[str, ...]


@dataclass(frozen=True)
class FieldPermissionRecord:
    """Serialized snapshot of a `FieldPermission` entry for caching."""

    role_id: UUID
    model_name: str
    field_name: str
    can_read: bool
    can_write: bool
    conditions: Any


class PermissionChecker:
    """Evaluate location and field-level permissions with caching support."""

    cache_timeout: int = DEFAULT_CACHE_TIMEOUT

    def __init__(
        self,
        user,
        *,
        reference_time: Optional[Any] = None,
        cache_timeout: Optional[int] = None,
    ) -> None:
        self.user = user
        self.user_id: Optional[UUID] = getattr(user, "pk", None)
        self.reference_time = reference_time or timezone.now()
        if cache_timeout is not None:
            self.cache_timeout = cache_timeout
        self._cache_prefix = (
            f"permission-checker:{self.user_id}" if self.user_id else "permission-checker:anonymous"
        )
        self._access_records: Optional[Tuple[AccessRecord, ...]] = None
        self._field_permission_cache: Dict[Tuple[str, Tuple[UUID, ...]], Tuple[FieldPermissionRecord, ...]] = {}
        self._location_cache: Dict[UUID, Location] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def can_access_location(self, location: Optional[Location | UUID | str], action: str) -> bool:
        """Return whether the current user can perform ``action`` at ``location``."""

        action_attr = self._normalize_action(action)
        location_instance = self._get_location_instance(location)
        relevant_records = self._get_relevant_records(location_instance)
        for record in relevant_records:
            if getattr(record, action_attr, False):
                return True
        return False

    def get_accessible_fields(self, location, model_name: str) -> Dict[str, Dict[str, Any]]:
        """Return field accessibility metadata for ``model_name`` at ``location``."""

        normalized_model = self._normalize_model_name(model_name)
        location_instance = self._get_location_instance(location)
        location_cache_key = self._location_cache_key(normalized_model, location_instance)

        cached = cache.get(location_cache_key)
        if cached is not None:
            return cached

        relevant_records = self._get_relevant_records(location_instance)
        field_matrix = self._build_field_matrix(relevant_records, normalized_model)
        cache.set(location_cache_key, field_matrix, self.cache_timeout)
        self._register_field_cache_key(location_cache_key)
        return field_matrix

    def filter_fields(
        self,
        data: Any,
        location,
        model_name: str,
        action: str = "read",
    ) -> Any:
        """Filter ``data`` to include only fields the user may access for ``action``."""

        if data is None:
            return data

        access_map = self.get_accessible_fields(location, model_name)
        mode = self._normalize_field_action(action)
        rules = access_map.get(mode, {})
        allowed = rules.get("allow")
        restricted = set(rules.get("deny", set()))
        conditional = rules.get("conditional", {}) or {}

        def _filter_item(item: Any) -> Any:
            if not isinstance(item, Mapping):
                return item

            keys = list(item.keys())
            allowed_keys = set(keys)
            if allowed is not None:
                allowed_keys &= set(allowed)
            allowed_keys -= restricted

            result = item.__class__() if isinstance(item, OrderedDict) else {}
            for key in keys:
                if key not in allowed_keys:
                    continue
                conditions = conditional.get(key)
                if conditions and not self._conditions_satisfied(item, conditions):
                    continue
                result[key] = item[key]
            return result

        if isinstance(data, list):
            return [_filter_item(item) for item in data]
        return _filter_item(data)

    def get_accessible_locations(self, action: str) -> Sequence[Location]:
        """Return an iterable of locations accessible for ``action``."""

        if not self.user_id:
            return []

        action_attr = self._normalize_action(action)
        access_records = self._get_access_records()

        include_all = False
        direct_location_ids: set[UUID] = set()
        descendant_paths: set[str] = set()

        for record in access_records:
            if not getattr(record, action_attr, False):
                continue
            if record.location_id is None:
                include_all = True
                break
            if record.inherit_to_children and record.location_path:
                descendant_paths.add(record.location_path)
            else:
                direct_location_ids.add(record.location_id)

        if include_all:
            return Location.objects.filter(is_active=True)

        clauses: List[Q] = []
        if direct_location_ids:
            clauses.append(Q(pk__in=list(direct_location_ids)))
        for path in descendant_paths:
            clauses.append(Q(path__startswith=path))

        if not clauses:
            return Location.objects.none()

        combined_q = clauses[0]
        for clause in clauses[1:]:
            combined_q |= clause

        return Location.objects.filter(is_active=True).filter(combined_q)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------
    def invalidate_cache(self) -> None:
        """Invalidate cached permission data for this user."""

        if not self.user_id:
            return
        cache.delete(self._cache_key("access-records"))
        index_key = self._cache_key("field-index")
        field_keys: Sequence[str] = cache.get(index_key) or []
        for key in field_keys:
            cache.delete(key)
        cache.delete(index_key)
        pattern = f"{self._cache_prefix}:fields:*"
        try:
            cache.delete_pattern(pattern)
        except (AttributeError, NotImplementedError):
            logger.debug("Cache backend does not support delete_pattern; skipping pattern-based purge.")

    # ------------------------------------------------------------------
    # Class helpers
    # ------------------------------------------------------------------
    @classmethod
    def invalidate_for_user(cls, user_id: Union[UUID, str, None]) -> None:
        if not user_id:
            return
        prefix = f"permission-checker:{user_id}"
        access_key = f"{prefix}:access-records"
        cache.delete(access_key)
        index_key = f"{prefix}:field-index"
        field_keys: Sequence[str] = cache.get(index_key) or []
        for key in field_keys:
            cache.delete(key)
        cache.delete(index_key)
        pattern = f"{prefix}:fields:*"
        try:
            cache.delete_pattern(pattern)
        except (AttributeError, NotImplementedError):
            logger.debug("Cache backend does not support delete_pattern; skipping pattern-based purge.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _get_access_records(self) -> Tuple[AccessRecord, ...]:
        if self._access_records is not None:
            return self._access_records

        if not self.user_id:
            self._access_records = tuple()
            return self._access_records

        cache_key = self._cache_key("access-records")
        cached = cache.get(cache_key)
        if cached is not None:
            self._access_records = cached
            return cached

        records = self._fetch_access_records()
        cache.set(cache_key, records, self.cache_timeout)
        self._access_records = records
        return records

    def _fetch_access_records(self) -> Tuple[AccessRecord, ...]:
        if not self.user_id:
            return tuple()

        qs = (
            LocationAccess.objects.active(self.reference_time)
            .filter(user_id=self.user_id)
            .select_related("location", "role")
        )

        records: List[AccessRecord] = []
        for access in qs:
            location_path = getattr(access.location, "path", None)
            accessible_fields = tuple((access.accessible_fields or []) or [])
            restricted_fields = tuple((access.restricted_fields or []) or [])
            records.append(
                AccessRecord(
                    id=access.pk,
                    user_id=access.user_id,
                    location_id=access.location_id,
                    location_path=location_path,
                    inherit_to_children=access.inherit_to_children,
                    role_id=access.role_id,
                    role_code=getattr(access.role, "code", None),
                    can_read=access.can_read,
                    can_create=access.can_create,
                    can_update=access.can_update,
                    can_delete=access.can_delete,
                    can_admin=access.can_admin,
                    accessible_fields=accessible_fields,
                    restricted_fields=restricted_fields,
                )
            )
        return tuple(records)

    def _get_relevant_records(self, location: Optional[Location]) -> Tuple[AccessRecord, ...]:
        access_records = self._get_access_records()
        if not access_records:
            return tuple()

        if location is None:
            return tuple(record for record in access_records if record.location_id is None)

        location_path = getattr(location, "path", None)
        if location_path is None and location.pk:
            refreshed = self._get_location_instance(location.pk)
            location_path = getattr(refreshed, "path", "") if refreshed else ""
        elif location_path is None:
            location_path = ""

        relevant: List[AccessRecord] = []
        for record in access_records:
            if record.location_id is None:
                relevant.append(record)
                continue
            if location.pk and record.location_id == location.pk:
                relevant.append(record)
                continue
            if (
                record.inherit_to_children
                and record.location_path
                and location_path.startswith(record.location_path)
            ):
                relevant.append(record)
        return tuple(relevant)

    def _build_field_matrix(
        self,
        records: Tuple[AccessRecord, ...],
        model_name: str,
    ) -> Dict[str, Dict[str, Any]]:
        if not records:
            empty_matrix = {
                "read": {"allow": set(), "deny": set(), "conditional": {}},
                "write": {"allow": set(), "deny": set(), "conditional": {}},
            }
            return empty_matrix

        allowlist_fields: set[str] = set()
        allowlist_active = False
        allow_all_fallback = False
        restricted_common: set[str] = set()
        role_ids: set[UUID] = set()

        for record in records:
            if record.accessible_fields:
                allowlist_active = True
                allowlist_fields.update(record.accessible_fields)
            else:
                allow_all_fallback = True
            restricted_common.update(record.restricted_fields)
            if record.role_id:
                role_ids.add(record.role_id)

        field_permissions = self._get_field_permissions(tuple(sorted(role_ids)), model_name)

        explicit_read_allow: set[str] = set()
        explicit_write_allow: set[str] = set()
        restricted_read_extra: set[str] = set()
        restricted_write_extra: set[str] = set()
        conditional_read: Dict[str, List[Any]] = {}
        conditional_write: Dict[str, List[Any]] = {}

        for perm in field_permissions:
            field_name = perm.field_name
            if perm.can_read:
                explicit_read_allow.add(field_name)
                if perm.conditions:
                    conditional_read.setdefault(field_name, []).append(perm.conditions)
            else:
                restricted_read_extra.add(field_name)
            if perm.can_write:
                explicit_write_allow.add(field_name)
                if perm.conditions:
                    conditional_write.setdefault(field_name, []).append(perm.conditions)
            else:
                restricted_write_extra.add(field_name)

        allow_read: Optional[set[str]]
        allow_write: Optional[set[str]]
        if allowlist_active and not allow_all_fallback:
            allow_read = set(allowlist_fields)
            allow_write = set(allowlist_fields)
        else:
            allow_read = None
            allow_write = None

        if allow_read is not None:
            allow_read.update(explicit_read_allow)
        if allow_write is not None:
            allow_write.update(explicit_write_allow)

        restricted_read = restricted_common | restricted_read_extra
        restricted_write = restricted_common | restricted_write_extra

        matrix = {
            "read": {
                "allow": allow_read,
                "deny": restricted_read,
                "conditional": {
                    field: tuple(conditions) for field, conditions in conditional_read.items()
                },
            },
            "write": {
                "allow": allow_write,
                "deny": restricted_write,
                "conditional": {
                    field: tuple(conditions) for field, conditions in conditional_write.items()
                },
            },
        }
        return matrix

    def _get_field_permissions(
        self,
        role_ids: Tuple[UUID, ...],
        model_name: str,
    ) -> Tuple[FieldPermissionRecord, ...]:
        if not role_ids:
            return tuple()

        cache_key = (model_name, role_ids)
        if cache_key in self._field_permission_cache:
            return self._field_permission_cache[cache_key]

        cache_store_key = self._cache_key(
            "field-permissions",
            model_name,
            ",".join(str(role_id) for role_id in role_ids),
        )
        cached = cache.get(cache_store_key)
        if cached is not None:
            self._field_permission_cache[cache_key] = cached
            return cached

        queryset = FieldPermission.objects.filter(
            role_id__in=list(role_ids),
            model_name__iexact=model_name,
            is_active=True,
        )
        records = tuple(
            FieldPermissionRecord(
                role_id=permission.role_id,
                model_name=permission.model_name,
                field_name=permission.field_name,
                can_read=permission.can_read,
                can_write=permission.can_write,
                conditions=permission.conditions or {},
            )
            for permission in queryset
        )
        cache.set(cache_store_key, records, self.cache_timeout)
        self._field_permission_cache[cache_key] = records
        return records

    def _register_field_cache_key(self, cache_key: str) -> None:
        if not self.user_id:
            return
        index_key = self._cache_key("field-index")
        try:
            stored_keys: List[str] = cache.get(index_key) or []
            if cache_key not in stored_keys:
                stored_keys.append(cache_key)
                cache.set(index_key, stored_keys, self.cache_timeout)
        except Exception:  # pragma: no cover - defensive logging only
            logger.exception("Failed to register field cache key %s", cache_key)

    def _normalize_action(self, action: str) -> str:
        if not action:
            raise ValueError("Action is required for permission checks.")
        action_lower = action.lower()
        attr = _ACTION_ATTRIBUTE_MAP.get(action_lower)
        if not attr:
            raise ValueError(f"Unsupported action '{action}'.")
        return attr

    def _normalize_field_action(self, action: str) -> str:
        if not action:
            raise ValueError("Action is required for field permission checks.")
        action_lower = action.lower()
        mode = _FIELD_ACTION_MAP.get(action_lower)
        if not mode:
            raise ValueError(f"Unsupported action '{action}'.")
        return mode

    def _normalize_model_name(self, model_name: str) -> str:
        if not model_name:
            raise ValueError("model_name is required.")
        return model_name.strip()

    def _location_cache_key(self, model_name: str, location: Optional[Location]) -> str:
        location_id = getattr(location, "pk", None)
        location_identifier = location_id or "global"
        return self._cache_key("fields", model_name, location_identifier)

    def _cache_key(self, suffix: str, *parts: Any) -> str:
        part_str = ":".join(str(part) for part in parts if part is not None)
        if part_str:
            return f"{self._cache_prefix}:{suffix}:{part_str}"
        return f"{self._cache_prefix}:{suffix}"

    def _get_location_instance(self, location: Optional[Location | UUID | str]) -> Optional[Location]:
        if location is None:
            return None
        if isinstance(location, Location):
            if location.pk is None:
                return None
            if getattr(location, "path", None) is None:
                try:
                    location = Location.objects.only("id", "path").get(pk=location.pk)
                except Location.DoesNotExist:
                    return None
            return location
        try:
            location_uuid = UUID(str(location))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid location identifier '{location}'.") from exc
        if location_uuid in self._location_cache:
            return self._location_cache[location_uuid]
        try:
            instance = Location.objects.only("id", "path").get(pk=location_uuid)
        except Location.DoesNotExist:
            return None
        self._location_cache[location_uuid] = instance
        return instance

    def _conditions_satisfied(self, data: Mapping[str, Any], conditions: Any) -> bool:
        if conditions in (None, {}, []):
            return True
        if isinstance(conditions, list):
            return all(self._conditions_satisfied(data, condition) for condition in conditions)
        if isinstance(conditions, dict):
            if "all" in conditions:
                return all(self._conditions_satisfied(data, cond) for cond in conditions["all"])
            if "any" in conditions:
                return any(self._conditions_satisfied(data, cond) for cond in conditions["any"])
            field_path = conditions.get("field")
            operator = conditions.get("operator", "eq")
            value = conditions.get("value")
            actual = self._resolve_field_value(data, field_path)
            return self._apply_operator(actual, operator, value)
        return bool(conditions)

    def _resolve_field_value(self, data: Mapping[str, Any], field_path: Optional[str]) -> Any:
        if not field_path:
            return None
        parts = field_path.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, Mapping):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            if callable(current):
                try:
                    current = current()
                except TypeError:
                    pass
            if current is None:
                break
        return current

    def _apply_operator(self, actual: Any, operator: str, expected: Any) -> bool:
        try:
            if operator == "eq":
                return actual == expected
            if operator == "ne":
                return actual != expected
            if operator == "in":
                return actual in expected
            if operator == "not_in":
                return actual not in expected
            if operator == "contains":
                return expected in actual
            if operator == "not_contains":
                return expected not in actual
            if operator == "gt":
                return actual > expected
            if operator == "gte":
                return actual >= expected
            if operator == "lt":
                return actual < expected
            if operator == "lte":
                return actual <= expected
            if operator == "startswith":
                return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
            if operator == "endswith":
                return isinstance(actual, str) and isinstance(expected, str) and actual.endswith(expected)
            if operator == "exists":
                return actual is not None
            if operator == "not_exists":
                return actual is None
        except TypeError:
            return False
        return False


__all__ = ["PermissionChecker", "AccessRecord", "FieldPermissionRecord"]
