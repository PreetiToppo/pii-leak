"""Regression tests for a real-world finding.

Scanning Swagger Petstore v2 (basePath /v2) against v3 (server /api/v3) reported every endpoint as
changed and every PII field as new, because '/api' stayed in the v3 endpoint keys. These specs mirror
the shape of the real ones so the problem cannot come back unnoticed.
"""

import httpx

from piileak.models import Severity
from piileak.scanner import gate_failures, scan

USER_FIELDS = ["id", "username", "firstName", "lastName", "email", "password", "phone", "userStatus"]
TYPES = {"id": "integer", "userStatus": "integer"}


def _props():
    return {name: {"type": TYPES.get(name, "string")} for name in USER_FIELDS}


V2 = {
    "swagger": "2.0",
    "info": {"title": "Petstore", "version": "1.0"},
    "basePath": "/v2",
    "paths": {
        "/user/{username}": {
            "get": {
                "parameters": [{"name": "username", "in": "path", "required": True, "type": "string"}],
                "responses": {"200": {"description": "ok", "schema": {"$ref": "#/definitions/User"}}},
            }
        }
    },
    "definitions": {"User": {"type": "object", "properties": _props()}},
}

V3 = {
    "openapi": "3.0.4",
    "info": {"title": "Petstore", "version": "1.0"},
    "servers": [{"url": "/api/v3"}],
    "paths": {
        "/user/{username}": {
            "get": {
                "parameters": [{"name": "username", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/User"}}},
                    }
                },
            }
        }
    },
    "components": {"schemas": {"User": {"type": "object", "properties": _props()}}},
}

USER_JSON = {
    "id": 1,
    "username": "user1",
    "firstName": "first name 1",
    "lastName": "last name 1",
    "email": "email1@test.com",
    "password": "12345",
    "phone": "12345",
    "userStatus": 1,
}


async def test_without_prefix_everything_looks_new_and_a_warning_explains_why(detector):
    result = await scan(V2, V3, "", detector, probe=False)
    assert any("none of the 1 old endpoints match" in w and "--strip-prefix" in w for w in result.warnings)
    assert {f.field for f in gate_failures(result, Severity.MEDIUM)} >= {"password", "email", "phone"}


async def test_strip_prefix_matches_endpoints_and_the_false_alarm_disappears(detector):
    result = await scan(V2, V3, "", detector, probe=False, strip_prefixes=["/api"])
    assert result.warnings == []
    assert result.diffs == []  # the API did not change, so nothing is new
    assert gate_failures(result, Severity.LOW) == []


async def test_prefix_given_with_version_behaves_the_same(detector):
    result = await scan(V2, V3, "", detector, probe=False, strip_prefixes=["/api/v3"])
    assert result.warnings == [] and result.diffs == []


async def test_param_override_probes_the_real_user_and_old_fields_stay_pre_existing(detector):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json=USER_JSON)

    result = await scan(
        V2,
        V3,
        "http://test",
        detector,
        probe_all=True,
        strip_prefixes=["/api"],
        param_overrides={"username": "user1"},
        transport=httpx.MockTransport(handler),
    )
    assert seen == ["/api/v3/user/user1"]
    assert any(f.field == "email" and not f.is_new_field for f in result.findings)  # reported, never gating
    assert gate_failures(result, Severity.LOW) == []


async def test_default_param_value_is_used_without_an_override(detector):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json=USER_JSON)

    await scan(
        V2, V3, "http://test", detector, probe_all=True, strip_prefixes=["/api"], transport=httpx.MockTransport(handler)
    )
    assert seen == ["/api/v3/user/1"]


async def test_no_probe_never_touches_the_network(detector):
    result = await scan(V2, V3, "", detector, probe=False)
    assert result.probes == [] and result.probing is False
