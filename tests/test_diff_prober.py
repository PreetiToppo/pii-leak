from piileak.diff import diff_specs
from piileak.normalize import normalize
from piileak.prober import build_url_parts


def test_diff_finds_added_fields_and_new_endpoints(v1_spec, v2_spec):
    diffs = {d.key: d for d in diff_specs(normalize(v1_spec), normalize(v2_spec))}
    assert set(diffs) == {"GET /users/{}", "POST /users", "GET /orders", "GET /health"}
    assert diffs["GET /health"].is_new_endpoint
    assert "aadhaar_number" in diffs["GET /users/{}"].added_fields
    assert diffs["GET /orders"].added_fields == ["[].customer_email"]


def test_no_diff_when_specs_match(v1_spec):
    n = normalize(v1_spec)
    assert diff_specs(n, n) == []
    assert len(diff_specs(n, n, include_unchanged=True)) == 2


def test_url_building_uses_param_examples(v2_spec):
    ep = normalize(v2_spec).endpoints["GET /users/{}"]
    path, query, headers = build_url_parts(ep)
    assert path == "/v2/users/1" and query == {} and headers == {}
