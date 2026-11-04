"""Internal, format-agnostic data model. Both Swagger 2.0 and OpenAPI 3.x are
converted into these types, so every later stage only deals with one shape."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


class Param(BaseModel):
    name: str
    location: str  # path | query | header | cookie | formData
    required: bool = False
    type: str = "string"
    example: Any = None


class Endpoint(BaseModel):
    method: str
    key_path: str  # canonical path: version segment stripped, params -> {}
    full_path: str  # real path (basePath/server path included), used for probing
    params: list[Param] = Field(default_factory=list)
    request_fields: dict[str, str] = Field(default_factory=dict)
    response_fields: dict[str, str] = Field(default_factory=dict)  # "a.b[].c" -> type

    @property
    def key(self) -> str:
        return f"{self.method} {self.key_path}"


class NormalizedSpec(BaseModel):
    source_format: str  # "swagger2" | "openapi3"
    title: str = ""
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)


class EndpointDiff(BaseModel):
    key: str
    endpoint: Endpoint
    is_new_endpoint: bool
    added_fields: list[str] = Field(default_factory=list)
    type_changed_fields: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    endpoint: str
    field: str  # canonical path, e.g. "items[].email"
    entity: str  # AADHAAR, PAN, EMAIL_ADDRESS, ...
    severity: Severity
    source: str  # "response" (seen in a live probe) | "spec" (field name only)
    score: float = 1.0
    sample: str | None = None  # masked, never the raw value
    is_new_field: bool = True  # introduced by this migration? only these gate the build
    suppressed: bool = False  # accepted via .piileak-ignore.yaml (still reported, never gates)
    suppression_reason: str | None = None


class ProbeResult(BaseModel):
    endpoint: str
    url: str | None = None
    status: str  # ok | skipped | error
    http_status: int | None = None
    detail: str = ""
    # parsed JSON body; excluded from serialisation so reports never contain raw PII
    body: Any = Field(default=None, exclude=True)


class ScanResult(BaseModel):
    diffs: list[EndpointDiff]
    probes: list[ProbeResult]
    findings: list[Finding]
    suppression_warnings: list[str] = Field(default_factory=list)
