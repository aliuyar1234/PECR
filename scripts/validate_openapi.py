from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "docs" / "openapi" / "pecr.v1.yaml"
MANIFEST_PATH = ROOT / "docs" / "openapi" / "contract_manifest.json"
ROUTE_RE = re.compile(r'\.route\("([^"]+)",\s*(get|post)\(')


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def extract_routes(path: Path) -> dict[str, list[str]]:
    routes: dict[str, set[str]] = {}
    for route, method in ROUTE_RE.findall(path.read_text(encoding="utf-8")):
        routes.setdefault(route, set()).add(method.lower())
    return {route: sorted(methods) for route, methods in sorted(routes.items())}


def resolve_ref(openapi: dict, schema: dict) -> dict:
    current = schema
    while "$ref" in current:
        ref = current["$ref"]
        if not ref.startswith("#/components/schemas/"):
            raise AssertionError(f"unsupported ref {ref}")
        name = ref.rsplit("/", 1)[-1]
        current = openapi["components"]["schemas"][name]
    return current


def get_schema(openapi: dict, locator: dict) -> dict:
    locator_type = locator["type"]
    if locator_type == "component":
        return resolve_ref(openapi, openapi["components"]["schemas"][locator["name"]])
    path_item = openapi["paths"][locator["path"]][locator["method"]]
    if locator_type == "path_request":
        schema = path_item["requestBody"]["content"]["application/json"]["schema"]
        return resolve_ref(openapi, schema)
    if locator_type == "path_response":
        schema = path_item["responses"][locator["status"]]["content"]["application/json"]["schema"]
        return resolve_ref(openapi, schema)
    raise AssertionError(f"unsupported locator type {locator_type}")


def schema_fields(schema: dict) -> tuple[set[str], set[str]]:
    if schema.get("type") != "object":
        raise AssertionError(f"expected object schema, got {schema.get('type')!r}")
    if schema.get("additionalProperties") is not False:
        raise AssertionError("object schema must set additionalProperties: false")
    required = set(schema.get("required", []))
    properties = set(schema.get("properties", {}).keys())
    optional = properties - required
    return required, optional


def validate_route_sets(openapi: dict, manifest: dict) -> int:
    checked = 0
    for name, route_set in manifest["route_sets"].items():
        source = ROOT / route_set["source"]
        actual = extract_routes(source)
        expected = {
            route: sorted(methods) for route, methods in sorted(route_set["routes"].items())
        }
        if actual != expected:
            raise AssertionError(
                f"{name} routes drifted for {source}: expected {expected}, got {actual}"
            )
        for route, methods in expected.items():
            for method in methods:
                if method not in openapi["paths"].get(route, {}):
                    raise AssertionError(f"OpenAPI is missing {method.upper()} {route}")
                checked += 1
    return checked


def validate_schemas(openapi: dict, manifest: dict) -> int:
    checked = 0
    for name, entry in manifest["schemas"].items():
        schema = get_schema(openapi, entry["source"])
        required, optional = schema_fields(schema)
        expected_required = set(entry["required"])
        expected_optional = set(entry["optional"])
        if required != expected_required or optional != expected_optional:
            raise AssertionError(
                f"{name} drifted: expected required={sorted(expected_required)} "
                f"optional={sorted(expected_optional)}, got required={sorted(required)} "
                f"optional={sorted(optional)}"
            )
        checked += 1
    return checked


def main() -> int:
    openapi = load_yaml(OPENAPI_PATH)
    manifest = load_json(MANIFEST_PATH)
    route_count = validate_route_sets(openapi, manifest)
    schema_count = validate_schemas(openapi, manifest)
    print(
        f"PASS: validated {route_count} documented routes and {schema_count} documented schemas"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
