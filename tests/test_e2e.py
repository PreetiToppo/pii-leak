"""End to end: specs -> diff -> probe the demo app in-process -> detect -> gate."""

import httpx

from examples.demo_api import app
from piileak.models import Severity
from piileak.report import render_json, render_text
from piileak.scanner import gate_failures, scan

TRANSPORT = httpx.ASGITransport(app=app)


async def run(detector, old, new, **kw):
    return await scan(old, new, "http://test", detector, transport=TRANSPORT, **kw)


async def test_v2_migration_is_caught(detector, v1_spec, v2_spec):
    result = await run(detector, v1_spec, v2_spec)
    found = {(f.field, f.entity) for f in result.findings}
    assert ("aadhaar_number", "AADHAAR") in found
    assert ("tax_id", "PAN") in found  # sensitive value, innocent field name
    assert ("bank.upi_id", "UPI_ID") in found
    assert ("[].customer_email", "EMAIL_ADDRESS") in found
    assert any(f.field == "phone" for f in result.findings)  # undocumented in the v2 spec
    assert gate_failures(result, Severity.MEDIUM)
    assert {p.endpoint: p.status for p in result.probes}["POST /users"] == "skipped"


async def test_clean_migration_passes(detector, v1_spec):
    """Same API on both sides: nothing is new, so the gate must pass."""
    result = await run(detector, v1_spec, v1_spec, probe_all=True)
    assert not gate_failures(result, Severity.LOW)
    assert any(p.status == "ok" for p in result.probes)


async def test_reports_never_contain_raw_pii(detector, v1_spec, v2_spec):
    result = await run(detector, v1_spec, v2_spec)
    blob = render_json(result, Severity.MEDIUM) + render_text(result, Severity.MEDIUM)
    for raw in ["2345 6789 0124", "ABCPE1234F", "asha.rao@example.com", "98765"]:
        assert raw not in blob


async def test_static_only_catches_names_when_probe_fails(detector, v1_spec, v2_spec):
    # a transport that always fails: only name-based (static) findings can remain
    def boom(request):
        raise httpx.ConnectError("down")

    result = await scan(v1_spec, v2_spec, "http://test", detector, transport=httpx.MockTransport(boom))
    assert all(f.source == "spec" for f in result.findings)
    assert any(f.entity == "AADHAAR" for f in result.findings)
