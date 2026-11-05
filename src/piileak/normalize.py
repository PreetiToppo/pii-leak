"""Turn Swagger 2.0 / OpenAPI 3.x documents into NormalizedSpec.

Why: the two formats describe the same API differently (definitions vs
components/schemas, body parameter vs requestBody, produces vs content, ...).
Diffing the raw documents flags those format differences as 'changes'.
Normalising first means a diff only reports real API differences.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .models import Endpoint, NormalizedSpec, Param

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
VERSION_SEGMENT = re.compile(r"^v\d+(\.\d+)?$", re.IGNORECASE)
MAX_DEPTH = 10


class SpecError(ValueError):
    pass


def load_spec(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text) if str(path).endswith(".json") else yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        raise SpecError(f"Could not parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError(f"{path} is not a JSON/YAML object")
    return data


def detect_format(raw: dict) -> str:
    if str(raw.get("swagger", "")).startswith("2"):
        return "swagger2"
    if str(raw.get("openapi", "")).startswith("3"):
        return "openapi3"
    raise SpecError("Not a Swagger 2.0 or OpenAPI 3.x document")


# ---------------------------------------------------------------- $ref / schema
def resolve_ref(root: dict, ref: str) -> Any:
    """Resolve a local JSON pointer. Works for '#/definitions/X' (2.0) and
    '#/components/schemas/X' (3.x) alike."""
    if not ref.startswith("#/"):
        raise SpecError(f"Only local $ref supported, got {ref!r}")
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise SpecError(f"Unresolvable $ref {ref!r}")
        node = node[part]
    return node


def _deref(node: Any, root: dict) -> Any:
    for _ in range(20):  # guard against ref loops
        if isinstance(node, dict) and "$ref" in node:
            node = resolve_ref(root, node["$ref"])
        else:
            break
    return node if isinstance(node, dict) else {}


def _type_of(schema: dict) -> str:
    t = schema.get("type")
    if isinstance(t, list):  # OpenAPI 3.1: ["string", "null"]
        t = next((x for x in t if x != "null"), "null")
    if t is None:
        if "properties" in schema:
            return "object"
        if "items" in schema:
            return "array"
        return "any"
    return t


def flatten_schema(schema: Any, root: dict, prefix: str = "", _seen: tuple = (), _depth: int = 0) -> dict[str, str]:
    """Flatten a schema into {"a.b[].c": "string"}. Handles $ref, allOf/oneOf/anyOf,
    arrays and recursive schemas."""
    out: dict[str, str] = {}
    if not isinstance(schema, dict) or _depth > MAX_DEPTH:
        return out

    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in _seen:  # recursive model, stop
            return out
        return flatten_schema(resolve_ref(root, ref), root, prefix, _seen + (ref,), _depth + 1)

    for key in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(key, []) or []:
            out.update(flatten_schema(sub, root, prefix, _seen, _depth + 1))

    for name, sub in (schema.get("properties") or {}).items():
        path = f"{prefix}.{name}" if prefix else name
        out[path] = _type_of(_deref(sub, root))
        out.update(flatten_schema(sub, root, path, _seen, _depth + 1))

    if _type_of(schema) == "array" and "items" in schema:
        item_prefix = f"{prefix}[]"
        item = _deref(schema["items"], root)
        if _type_of(item) not in ("object", "array", "any"):
            out[item_prefix] = _type_of(item)
        out.update(flatten_schema(schema["items"], root, item_prefix, _seen, _depth + 1))

    extra = schema.get("additionalProperties")
    if isinstance(extra, dict):
        out.update(flatten_schema(extra, root, f"{prefix}.*" if prefix else "*", _seen, _depth + 1))
    return out


# ---------------------------------------------------------------- endpoints
def canonical_path(full_path: str, strip_version: bool = True, strip_prefixes: Sequence[str] = ()) -> str:
    """Canonical endpoint path: version segments dropped, {param} names replaced by {}.

    strip_prefixes removes a leading base path such as /api so that /api/v3/user/{id} in one spec
    matches /user/{username} in another. Prefixes match whole segments only and are themselves
    normalised the same way, so "/api/v3" and "/api" behave identically.
    """
    segs = []
    for seg in (s for s in full_path.split("/") if s):
        if strip_version and VERSION_SEGMENT.match(seg):
            continue
        if seg.startswith("{") and seg.endswith("}"):
            seg = "{}"
        segs.append(seg)
    path = "/" + "/".join(segs)
    for raw_prefix in strip_prefixes:
        prefix = canonical_path(raw_prefix, strip_version)
        if prefix == "/":
            continue
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix) :]
    return path


def _parse_param(p: Any, root: dict, fmt: str) -> Param | None:
    p = _deref(p, root)
    if not p or "name" not in p or "in" not in p:
        return None
    schema = _deref(p.get("schema", {}), root) if fmt == "openapi3" else p
    example = p.get("example", schema.get("example", schema.get("default")))
    if example is None and schema.get("enum"):
        example = schema["enum"][0]
    return Param(
        name=p["name"],
        location=p["in"],
        required=bool(p.get("required", p["in"] == "path")),
        type=_type_of(schema) if schema.get("type") or schema.get("properties") else "string",
        example=example,
    )


def _response_fields(op: dict, root: dict, fmt: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for code, resp in (op.get("responses") or {}).items():
        if not str(code).startswith("2"):
            continue
        resp = _deref(resp, root)
        if fmt == "swagger2":
            fields.update(flatten_schema(resp.get("schema"), root))
        else:
            for media, body in (resp.get("content") or {}).items():
                if "json" in media or media == "*/*":
                    fields.update(flatten_schema(body.get("schema"), root))
    return fields


def _request_fields(op: dict, params: list[Any], root: dict, fmt: str) -> dict[str, str]:
    if fmt == "swagger2":
        for p in params:
            p = _deref(p, root)
            if p.get("in") == "body":
                return flatten_schema(p.get("schema"), root)
        return {}
    body = _deref(op.get("requestBody", {}), root)
    for media, content in (body.get("content") or {}).items():
        if "json" in media:
            return flatten_schema(content.get("schema"), root)
    return {}


def _base_path(raw: dict, fmt: str) -> str:
    if fmt == "swagger2":
        return raw.get("basePath", "") or ""
    servers = raw.get("servers") or []
    if servers:
        return urlparse(servers[0].get("url", "")).path.rstrip("/")
    return ""


def normalize(raw: dict, strip_version: bool = True, strip_prefixes: Sequence[str] = ()) -> NormalizedSpec:
    fmt = detect_format(raw)
    base = _base_path(raw, fmt).rstrip("/")
    spec = NormalizedSpec(source_format=fmt, title=(raw.get("info") or {}).get("title", ""))

    for path, item in (raw.get("paths") or {}).items():
        item = _deref(item, raw)
        path_params = item.get("parameters", []) or []
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            all_params = path_params + (op.get("parameters", []) or [])
            parsed = [x for x in (_parse_param(p, raw, fmt) for p in all_params) if x]
            full_path = f"{base}{path}"
            ep = Endpoint(
                method=method.upper(),
                key_path=canonical_path(full_path, strip_version, strip_prefixes),
                full_path=full_path,
                params=[x for x in parsed if x.location != "body"],
                request_fields=_request_fields(op, all_params, raw, fmt),
                response_fields=_response_fields(op, raw, fmt),
            )
            spec.endpoints[ep.key] = ep
    return spec
