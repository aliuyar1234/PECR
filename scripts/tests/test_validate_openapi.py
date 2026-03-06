from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "validate_openapi.py"
SPEC = importlib.util.spec_from_file_location("validate_openapi", MODULE_PATH)
assert SPEC and SPEC.loader
validate_openapi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_openapi)


class ValidateOpenApiTests(unittest.TestCase):
    def test_extract_routes_reads_axum_route_macros(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "http.rs"
            path.write_text(
                'Router::new().route("/healthz", get(healthz)).route("/v1/run", post(run));',
                encoding="utf-8",
            )
            self.assertEqual(
                validate_openapi.extract_routes(path),
                {"/healthz": ["get"], "/v1/run": ["post"]},
            )

    def test_validate_route_sets_detects_drift(self) -> None:
        openapi = {"paths": {"/healthz": {"get": {}}}}
        manifest = {
            "route_sets": {
                "gateway": {
                    "source": "tmp.rs",
                    "routes": {"/healthz": ["get"], "/readyz": ["get"]},
                }
            },
            "schemas": {},
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "tmp.rs"
            source.write_text('Router::new().route("/healthz", get(healthz));', encoding="utf-8")
            original_root = validate_openapi.ROOT
            try:
                validate_openapi.ROOT = Path(tmp_dir)
                with self.assertRaises(AssertionError):
                    validate_openapi.validate_route_sets(openapi, manifest)
            finally:
                validate_openapi.ROOT = original_root

    def test_resolve_ref_and_schema_fields_follow_component_aliases(self) -> None:
        openapi = {
            "components": {
                "schemas": {
                    "PolicyDecision": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["allow", "cacheable"],
                        "properties": {
                            "allow": {"type": "boolean"},
                            "cacheable": {"type": "boolean"},
                            "reason": {"type": "string"},
                        },
                    },
                    "PolicySimulationResponse": {"$ref": "#/components/schemas/PolicyDecision"},
                }
            },
            "paths": {
                "/v1/policies/simulate": {
                    "post": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/PolicySimulationResponse"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
        schema = validate_openapi.get_schema(
            openapi,
            {
                "type": "path_response",
                "path": "/v1/policies/simulate",
                "method": "post",
                "status": "200",
            },
        )
        required, optional = validate_openapi.schema_fields(schema)
        self.assertEqual(required, {"allow", "cacheable"})
        self.assertEqual(optional, {"reason"})

    def test_manifest_files_are_well_formed(self) -> None:
        manifest = validate_openapi.load_json(validate_openapi.MANIFEST_PATH)
        openapi = validate_openapi.load_yaml(validate_openapi.OPENAPI_PATH)
        route_count = validate_openapi.validate_route_sets(openapi, manifest)
        schema_count = validate_openapi.validate_schemas(openapi, manifest)
        self.assertGreater(route_count, 0)
        self.assertGreater(schema_count, 0)


if __name__ == "__main__":
    unittest.main()
