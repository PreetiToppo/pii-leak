import pytest

from piileak.normalize import SpecError, canonical_path, detect_format, flatten_schema, normalize


def test_formats_detected(v1_spec, v2_spec):
    assert detect_format(v1_spec) == "swagger2"
    assert detect_format(v2_spec) == "openapi3"
    with pytest.raises(SpecError):
        detect_format({"foo": 1})


def test_canonical_path_strips_version_and_params():
    assert canonical_path("/v2/users/{user_id}") == "/users/{}"
    assert canonical_path("/api/v10/orders/{oid}/items") == "/api/orders/{}/items"
    assert canonical_path("/v1/x", strip_version=False) == "/v1/x"


def test_same_api_in_both_formats_normalises_identically(v1_spec):
    """The same User schema written as Swagger 2.0 and OpenAPI 3.0 must match."""
    oas3 = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "/v1"}],
        "paths": {
            "/users/{user_id}": {
                "get": {
                    "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/User"}}},
                        }
                    },
                }
            },
            "/orders": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Order"}}
                                }
                            },
                        }
                    }
                }
            },
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "country": {"type": "string"},
                    },
                },
                "Order": {"type": "object", "properties": {"id": {"type": "integer"}, "total": {"type": "number"}}},
            }
        },
    }
    a, b = normalize(v1_spec), normalize(oas3)
    assert a.endpoints.keys() == b.endpoints.keys()
    for k in a.endpoints:
        assert a.endpoints[k].response_fields == b.endpoints[k].response_fields


def test_array_and_nested_paths(v2_spec):
    ep = normalize(v2_spec).endpoints["GET /orders"]
    assert "[].customer_email" in ep.response_fields
    user = normalize(v2_spec).endpoints["GET /users/{}"]
    assert user.response_fields["bank.ifsc"] == "string"


def test_recursive_schema_terminates():
    root = {
        "definitions": {
            "Node": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "children": {"type": "array", "items": {"$ref": "#/definitions/Node"}},
                },
            }
        }
    }
    out = flatten_schema({"$ref": "#/definitions/Node"}, root)
    assert "id" in out and "children" in out


def test_allof_merges_properties():
    root = {"definitions": {"Base": {"type": "object", "properties": {"id": {"type": "integer"}}}}}
    extra = {"type": "object", "properties": {"email": {"type": "string"}}}
    schema = {"allOf": [{"$ref": "#/definitions/Base"}, extra]}
    assert set(flatten_schema(schema, root)) == {"id", "email"}


def test_strip_prefix_matches_whole_segments_only():
    assert canonical_path("/api/v3/user/{id}", strip_prefixes=["/api"]) == "/user/{}"
    assert canonical_path("/api/v3/user/{id}", strip_prefixes=["/api/v3"]) == "/user/{}"
    assert canonical_path("/api/user", strip_prefixes=["api"]) == "/user"  # leading slash optional
    assert canonical_path("/apiary/user", strip_prefixes=["/api"]) == "/apiary/user"  # not a segment match
    assert canonical_path("/api", strip_prefixes=["/api"]) == "/"
    assert canonical_path("/user", strip_prefixes=["/api"]) == "/user"  # nothing to strip
    assert canonical_path("/api/user", strip_prefixes=["/", ""]) == "/api/user"  # empty prefixes are ignored
