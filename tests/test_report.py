"""Report formats. Raw PII must never appear in any of them."""

import json
from datetime import date

import httpx

from examples.demo_api import app
from piileak.models import Severity
from piileak.report import render_json, render_sarif, render_text
from piileak.scanner import scan
from piileak.suppressions import Suppression

RAW_VALUES = ["2345 6789 0124", "ABCPE1234F", "asha.rao@example.com", "98765", "SBIN0001234"]


async def run(detector, v1_spec, v2_spec, suppressions=None):
    return await scan(
        v1_spec,
        v2_spec,
        "http://test",
        detector,
        transport=httpx.ASGITransport(app=app),
        suppressions=suppressions,
        today=date(2026, 11, 4),
    )


async def test_sarif_structure(detector, v1_spec, v2_spec):
    result = await run(detector, v1_spec, v2_spec)
    sarif = json.loads(render_sarif(result, "examples/specs/v2_openapi3.json"))
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    [run_] = sarif["runs"]
    assert run_["tool"]["driver"]["name"] == "PIILeak"

    new = [f for f in result.findings if f.is_new_field]
    assert len(run_["results"]) == len(new) > 0
    rule_ids = {r["id"] for r in run_["tool"]["driver"]["rules"]}
    assert len(rule_ids) == len(run_["tool"]["driver"]["rules"])  # unique
    assert {r["ruleId"] for r in run_["results"]} <= rule_ids

    levels = {r["ruleId"]: r["level"] for r in run_["results"]}
    assert levels["PIILEAK-AADHAAR"] == "error" and levels["PIILEAK-EMAIL_ADDRESS"] == "warning"
    assert levels["PIILEAK-IFSC"] == "note"

    fingerprints = [r["partialFingerprints"]["piileak/v1"] for r in run_["results"]]
    assert len(set(fingerprints)) == len(fingerprints)
    loc = run_["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "examples/specs/v2_openapi3.json"
    assert loc["logicalLocations"][0]["fullyQualifiedName"].count("::") == 1


async def test_sarif_marks_suppressed_findings(detector, v1_spec, v2_spec):
    sup = Suppression(endpoint="GET /users/*", field="email", reason="approved in SEC-1", expires=date(2027, 1, 1))
    result = await run(detector, v1_spec, v2_spec, [sup])
    sarif = json.loads(render_sarif(result, "spec.json"))
    suppressed = [r for r in sarif["runs"][0]["results"] if "suppressions" in r]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["justification"] == "approved in SEC-1"


async def test_no_format_contains_raw_pii(detector, v1_spec, v2_spec):
    result = await run(detector, v1_spec, v2_spec)
    blobs = [
        render_text(result, Severity.MEDIUM),
        render_json(result, Severity.MEDIUM),
        render_sarif(result, "spec.json"),
    ]
    for blob in blobs:
        for raw in RAW_VALUES:
            assert raw not in blob


async def test_text_report_shows_suppressed_section_and_warnings(detector, v1_spec, v2_spec):
    sup = Suppression(endpoint="*", field="phone", reason="legacy field", expires=date(2026, 11, 8))
    result = await run(detector, v1_spec, v2_spec, [sup])
    text = render_text(result, Severity.MEDIUM)
    assert "Suppressed by .piileak-ignore.yaml" in text and "accepted: legacy field" in text
    assert "Suppression warnings:" in text and "expires in 4 day" in text
