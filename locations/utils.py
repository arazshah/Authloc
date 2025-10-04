from __future__ import annotations

import csv
import io
import json
from typing import Iterable, Sequence

from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import GEOSGeometry, Point, Polygon
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from .models import Location, LocationType


def _to_point(value: Point | Sequence[float] | str) -> Point:
    if isinstance(value, Point):
        return value
    if isinstance(value, str):
        geometry = GEOSGeometry(value)
        if not isinstance(geometry, Point):
            raise ValueError("Provided WKT does not represent a Point geometry")
        return geometry
    try:
        longitude, latitude = value  # type: ignore[misc]
        return Point(float(longitude), float(latitude), srid=4326)
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("Unable to convert value to Point geometry") from exc


def find_locations_within_radius(point: Point | Sequence[float] | str, radius_meters: float, *, queryset=None):
    point_geom = _to_point(point)
    qs = queryset or Location.objects.all()
    qs = qs.filter(center_point__isnull=False)
    return qs.annotate(distance=Distance("center_point", point_geom)).filter(distance__lte=radius_meters)


def find_nearest_location(
    point: Point | Sequence[float] | str,
    *,
    location_type: LocationType | str | None = None,
    limit: int = 1,
    queryset=None,
):
    point_geom = _to_point(point)
    qs = queryset or Location.objects.all()
    qs = qs.filter(center_point__isnull=False)
    if isinstance(location_type, LocationType):
        qs = qs.filter(type=location_type)
    elif isinstance(location_type, str):
        qs = qs.filter(type__code=location_type)
    return qs.annotate(distance=Distance("center_point", point_geom)).order_by("distance")[:limit]


def check_point_in_polygon(point: Point | Sequence[float] | str, polygon: Polygon | str) -> bool:
    point_geom = _to_point(point)
    if isinstance(polygon, str):
        poly_geom = GEOSGeometry(polygon)
    else:
        poly_geom = polygon
    if poly_geom.srid is None:
        poly_geom.srid = 4326
    return point_geom.within(poly_geom)


def calculate_area(geometry: GEOSGeometry) -> float:
    geom = geometry.clone()
    if geom.srid is None:
        geom.srid = 4326
    geom.transform(3857)
    return geom.area


def calculate_distance(geom_a: GEOSGeometry, geom_b: GEOSGeometry) -> float:
    clone_a = geom_a.clone()
    clone_b = geom_b.clone()
    if clone_a.srid is None:
        clone_a.srid = 4326
    if clone_b.srid is None:
        clone_b.srid = 4326
    clone_a.transform(3857)
    clone_b.transform(3857)
    return clone_a.distance(clone_b)


def import_from_geojson(
    geojson: str | dict,
    *,
    default_type: LocationType | None = None,
    created_by=None,
) -> list[Location]:
    if isinstance(geojson, str):
        payload = json.loads(geojson)
    else:
        payload = geojson

    features = payload.get("features", [])
    created_locations: list[Location] = []

    with transaction.atomic():
        for feature in features:
            properties = feature.get("properties", {})
            geom = feature.get("geometry")
            if not geom:
                continue
            geometry = GEOSGeometry(json.dumps(geom))

            type_code = properties.get("type_code")
            location_type = default_type
            if type_code:
                location_type = LocationType.objects.filter(code=type_code).first()
            if not location_type:
                raise ValueError("Unable to resolve LocationType for feature")

            parent_code = properties.get("parent_code")
            parent = None
            if parent_code:
                parent = Location.objects.filter(code=parent_code).first()

            location = Location(
                name=properties.get("name") or properties.get("NAME") or properties.get("Name") or location_type.name,
                name_fa=properties.get("name_fa", ""),
                code=properties.get("code") or properties.get("CODE") or properties.get("Code") or "",
                type=location_type,
                parent=parent,
                geometry=geometry,
                center_point=geometry.centroid if geometry.geom_type != "Point" else geometry,
                population=properties.get("population"),
                postal_code=properties.get("postal_code", ""),
                description=properties.get("description", ""),
                metadata={k: v for k, v in properties.items() if k not in {"name", "name_fa", "code", "type_code", "parent_code"}},
            )
            if created_by:
                location.created_by = created_by
                location.updated_by = created_by
            location.save()
            created_locations.append(location)

    return created_locations


def export_to_geojson(locations: Iterable[Location]) -> dict:
    features = []
    for location in locations:
        geometry = location.geometry or location.center_point
        if not geometry:
            continue
        features.append(
            {
                "type": "Feature",
                "properties": {
                    "id": str(location.pk),
                    "name": location.name,
                    "name_fa": location.name_fa,
                    "code": location.code,
                    "type_code": location.type.code,
                    "level": location.level,
                    "parent": str(location.parent_id) if location.parent_id else None,
                    "population": location.population,
                    "postal_code": location.postal_code,
                    "metadata": location.metadata,
                },
                "geometry": json.loads(geometry.geojson),
            }
        )
    return {
        "type": "FeatureCollection",
        "features": features,
    }


def import_from_csv(file: UploadedFile | io.IOBase | str, *, location_type: LocationType, parent: Location | None = None, created_by=None) -> list[Location]:
    if isinstance(file, UploadedFile):
        data = file.read().decode("utf-8")
    elif isinstance(file, io.IOBase):
        data = file.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
    else:
        data = file

    reader = csv.DictReader(io.StringIO(data))
    created_locations: list[Location] = []
    with transaction.atomic():
        for row in reader:
            location = Location(
                name=row.get("name") or row.get("Name") or "",
                name_fa=row.get("name_fa") or row.get("Name_fa") or "",
                code=row.get("code") or row.get("Code") or "",
                type=location_type,
                parent=parent,
                population=row.get("population") or None,
                postal_code=row.get("postal_code") or "",
                metadata={k: v for k, v in row.items() if k not in {"name", "name_fa", "code", "population", "postal_code"}},
            )
            if created_by:
                location.created_by = created_by
                location.updated_by = created_by
            location.save()
            created_locations.append(location)
    return created_locations


__all__ = [
    "find_locations_within_radius",
    "find_nearest_location",
    "check_point_in_polygon",
    "calculate_area",
    "calculate_distance",
    "import_from_geojson",
    "export_to_geojson",
    "import_from_csv",
]
