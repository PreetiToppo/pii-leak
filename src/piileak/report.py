from __future__ import annotations

import json

from .models import Finding, ScanResult, Severity
from .scanner import gate_failures

_ICON = {Severity.HIGH: "HIGH  ", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW   "}


def _row(f: Finding) -> str:
    where = "seen in response" if f.source == "response" else "field name only"
    sample = f"  value={f.sample}" if f.sample else ""
    return f"  [{_ICON[f.severity]}] {f.endpoint}  {f.field}  -> {f.entity} ({where}){sample}"


def render_text(result: ScanResult, fail_on: Severity) -> str:
    failures = gate_failures(result, fail_on)
    pre_existing = [f for f in result.findings if not f.is_new_field]
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
    other_new = [f for f in result.findings if f.is_new_field and f not in failures]
    if other_new:
        lines += ["", f"New findings below the --fail-on threshold ({len(other_new)}):"]
        lines += [_row(f) for f in other_new]
    if pre_existing:
        lines += ["", f"Pre-existing (not gating) ({len(pre_existing)}):"]
        lines += [_row(f) for f in pre_existing]
    lines.append("")
    lines.append(f"RESULT: {'FAIL' if failures else 'PASS'}")
    return "\n".join(lines)


def render_json(result: ScanResult, fail_on: Severity) -> str:
    payload = result.model_dump(mode="json")
    payload["gate"] = {
        "fail_on": fail_on.value,
        "failed": bool(gate_failures(result, fail_on)),
        "failures": [f.model_dump(mode="json") for f in gate_failures(result, fail_on)],
    }
    return json.dumps(payload, indent=2)
