from piileak.models import Endpoint, Finding, NormalizedSpec, ProbeResult, Severity


def test_severity_rank_ordering():
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank


def test_endpoint_key():
    ep = Endpoint(method="GET", key_path="/users/{}", full_path="/v2/users/{id}")
    assert ep.key == "GET /users/{}"


def test_probe_body_is_never_serialised():
    pr = ProbeResult(endpoint="GET /x", status="ok", body={"aadhaar": "2345 6789 0124"})
    assert "body" not in pr.model_dump()
    assert "2345" not in pr.model_dump_json()
    assert pr.body == {"aadhaar": "2345 6789 0124"}  # still available in memory for scanning


def test_finding_json_roundtrip():
    f = Finding(
        endpoint="GET /u",
        field="email",
        entity="EMAIL_ADDRESS",
        severity=Severity.MEDIUM,
        source="response",
        sample="****om",
    )
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_defaults_are_not_shared():
    a, b = NormalizedSpec(source_format="openapi3"), NormalizedSpec(source_format="openapi3")
    a.endpoints["k"] = Endpoint(method="GET", key_path="/", full_path="/")
    assert b.endpoints == {}
    e1 = Endpoint(method="GET", key_path="/", full_path="/")
    e2 = Endpoint(method="GET", key_path="/", full_path="/")
    e1.params.append(None)  # type: ignore[arg-type]
    assert e2.params == []
