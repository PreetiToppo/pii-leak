from __future__ import annotations

import hashlib
import json
from typing import Any

from . import __version__
from .models import Finding, ScanResult, Severity
from .scanner import gate_failures

_ICON = {Severity.HIGH: "HIGH  ", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW   "}
_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _row(f: Finding) -> str:
    where = "seen in response" if f.source == "response" else "field name only"
    sample = f"  value={f.sample}" if f.sample else ""
    return f"  [{_ICON[f.severity]}] {f.endpoint}  {f.field}  -> {f.entity} ({where}){sample}"


def _suppressed_row(f: Finding) -> str:
    return f"{_row(f)}\n      accepted: {f.suppression_reason}"


def render_text(result: ScanResult, fail_on: Severity) -> str:
    failures = gate_failures(result, fail_on)
    live = [f for f in result.findings if not f.suppressed]
    suppressed = [f for f in result.findings if f.suppressed]
    pre_existing = [f for f in live if not f.is_new_field]
    other_new = [f for f in live if f.is_new_field and f not in failures]
    ok = sum(p.status == "ok" for p in result.probes)
    lines = [
        "PIILeak scan",
        f"  endpoints changed : {len(result.diffs)}",
        f"  probed ok         : {ok}/{len(result.probes)}",
    ]
    for p in result.probes:
        if p.status != "ok":
            lines.append(f"    - {p.endpoint}: {p.status} ({p.detail})")
    lines.append("")
    if failures:
        lines.append(f"NEW PII exposure introduced by this migration ({len(failures)}):")
        lines += [_row(f) for f in failures]
    if other_new:
        lines += ["", f"New findings below the --fail-on threshold ({len(other_new)}):"]
        lines += [_row(f) for f in other_new]
    if suppressed:
        lines += ["", f"Suppressed by .piileak-ignore.yaml ({len(suppressed)}):"]
        lines += [_suppressed_row(f) for f in suppressed]
    if pre_existing:
        lines += ["", f"Pre-existing (not gating) ({len(pre_existing)}):"]
        lines += [_row(f) for f in pre_existing]
    if result.suppression_warnings:
        lines += ["", "Suppression warnings:"]
        lines += [f"  - {w}" for w in result.suppression_warnings]
    lines.append("")
    lines.append(f"RESULT: {'FAIL' if failures else 'PASS'}")
    return "\n".join(lines)


def render_json(result: ScanResult, fail_on: Severity) -> str:
    payload = result.model_dump(mode="json")
    failures = gate_failures(result, fail_on)
    payload["gate"] = {
        "fail_on": fail_on.value,
        "failed": bool(failures),
        "failures": [f.model_dump(mode="json") for f in failures],
    }
    return json.dumps(payload, indent=2)


def _fingerprint(f: Finding) -> str:
    """Stable identity so GitHub can track the same alert across runs."""
    return hashlib.sha256(f"{f.endpoint}|{f.field}|{f.entity}".encode()).hexdigest()


def render_sarif(result: ScanResult, spec_uri: str) -> str:
    """SARIF 2.1.0 for GitHub code scanning.

    Findings describe API fields, not source lines, so each result is anchored to the new spec
    file (spec_uri must be repo-relative) and the endpoint/field go in a logical location.
    Only findings introduced by this migration are included. Masked samples are left out.
    """
    findings = [f for f in result.findings if f.is_new_field]
    entities = sorted({f.entity for f in findings})
    rules = [
        {
            "id": f"PIILEAK-{entity}",
            "name": f"Exposed{entity.title().replace('_', '')}",
            "shortDescription": {"text": f"{entity} exposed by an API migration"},
            "fullDescription": {
                "text": f"A new or changed API response exposes {entity} data that the previous version did not."
            },
        }
        for entity in entities
    ]
    results: list[dict[str, Any]] = []
    for f in findings:
        evidence = "seen in a live response" if f.source == "response" else "field name only"
        entry: dict[str, Any] = {
            "ruleId": f"PIILEAK-{f.entity}",
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.entity} exposed by {f.endpoint} in field '{f.field}' ({evidence})."},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": spec_uri},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {"name": f.field, "fullyQualifiedName": f"{f.endpoint}::{f.field}", "kind": "member"}
                    ],
                }
            ],
            "partialFingerprints": {"piileak/v1": _fingerprint(f)},
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": f.suppression_reason or ""}]
        results.append(entry)
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PIILeak",
                        "version": __version__,
                        "informationUri": "https://github.com/PreetiToppo/pii-leak",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
