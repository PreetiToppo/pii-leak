"""Suppression file: parsing, matching, expiry and its effect on the gate."""

from datetime import date

import httpx
import pytest

from examples.demo_api import app
from piileak.models import Finding, Severity
from piileak.scanner import gate_failures, scan
from piileak.suppressions import (
    Suppression,
    SuppressionError,
    _glob,
    apply_suppressions,
    load_suppressions,
)

TODAY = date(2026, 11, 4)


def finding(endpoint="GET /users/{}", field="email", entity="EMAIL_ADDRESS") -> Finding:
    return Finding(endpoint=endpoint, field=field, entity=entity, severity=Severity.MEDIUM, source="response")


def supp(**kw) -> Suppression:
    base = {"endpoint": "GET /users/{}", "field": "email", "reason": "approved", "expires": date(2027, 6, 1)}
    return Suppression(**{**base, **kw})


# ------------------------------------------------------------------ glob
def test_glob_wildcards_and_literal_brackets():
    assert _glob("GET /users/*", "GET /users/{}")
    assert _glob("*", "anything at all")
    assert _glob("[].customer_email", "[].customer_email")
    assert _glob("items[].*", "items[].email")
    assert not _glob("items[].email", "items[].phone")
    assert not _glob("GET /users", "GET /users/{}")


# ------------------------------------------------------------------ loading
def write(tmp_path, text):
    path = tmp_path / ".piileak-ignore.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_valid_file(tmp_path):
    path = write(
        tmp_path,
        "suppressions:\n  - endpoint: 'GET /users/{}'\n    field: email\n    entity: EMAIL_ADDRESS\n"
        "    reason: Needed by the HR portal (SEC-123)\n    expires: 2027-03-01\n",
    )
    [s] = load_suppressions(path)
    assert s.expires == date(2027, 3, 1) and s.entity == "EMAIL_ADDRESS"


@pytest.mark.parametrize(
    "body, message",
    [
        ("suppressions:\n  - {endpoint: a, field: b, expires: 2027-01-01}\n", "reason"),
        ("suppressions:\n  - {endpoint: a, field: b, reason: x}\n", "expires"),
        ("suppressions:\n  - {endpoint: a, field: b, reason: '  ', expires: 2027-01-01}\n", "reason must not be empty"),
        ("suppressions:\n  - {endpoint: a, field: b, reason: x, expiry: 2027-01-01}\n", "expiry"),
        ("suppressions:\n  - {endpoint: a, field: b, reason: x, expires: not-a-date}\n", "expires"),
        ("suppressions: nope\n", "must be a list"),
        ("suppressions: [unclosed\n", "not valid YAML"),
    ],
)
def test_invalid_files_are_rejected_with_a_helpful_message(tmp_path, body, message):
    with pytest.raises(SuppressionError, match=message):
        load_suppressions(write(tmp_path, body))


def test_empty_file_and_missing_file(tmp_path):
    assert load_suppressions(write(tmp_path, "")) == []
    with pytest.raises(SuppressionError, match="cannot read"):
        load_suppressions(tmp_path / "missing.yaml")


# ------------------------------------------------------------------ applying
def test_matching_finding_is_suppressed_with_reason():
    [out], warnings = apply_suppressions([finding()], [supp()], TODAY)
    assert out.suppressed and out.suppression_reason == "approved" and warnings == []


def test_entity_restriction_and_wildcards():
    kept, _ = apply_suppressions([finding(entity="PAN")], [supp(entity="EMAIL_ADDRESS")], TODAY)
    assert not kept[0].suppressed
    [out], _ = apply_suppressions([finding(field="bank.upi_id")], [supp(endpoint="*", field="bank.*")], TODAY)
    assert out.suppressed


def test_expired_suppression_is_ignored_and_reported():
    [out], warnings = apply_suppressions([finding()], [supp(expires=date(2026, 11, 3))], TODAY)
    assert not out.suppressed
    assert any("expired suppression ignored" in w for w in warnings)


def test_unused_and_expiring_soon_are_reported():
    _, warnings = apply_suppressions([finding()], [supp(field="phone", expires=date(2026, 11, 10))], TODAY)
    assert any("unused suppression" in w for w in warnings)
    assert any("expires in 6 day" in w for w in warnings)


# ------------------------------------------------------------------ end to end
async def test_suppressing_one_field_only_removes_that_failure(detector, v1_spec, v2_spec):
    result = await scan(
        v1_spec,
        v2_spec,
        "http://test",
        detector,
        transport=httpx.ASGITransport(app=app),
        suppressions=[supp(endpoint="GET /users/*", field="email")],
        today=TODAY,
    )
    by_field = {f.field: f for f in result.findings}
    assert by_field["email"].suppressed
    failing = {f.field for f in gate_failures(result, Severity.MEDIUM)}
    assert "email" not in failing and {"aadhaar_number", "tax_id"} <= failing
