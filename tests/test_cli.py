from pathlib import Path

from piileak.cli import main

SPECS = Path(__file__).parent.parent / "examples" / "specs"
BASE = ["scan", "--old", str(SPECS / "v1_swagger2.json"), "--new", str(SPECS / "v2_openapi3.json")]


def test_private_target_is_refused_by_default(capsys):
    code = main([*BASE, "--base-url", "http://127.0.0.1:9"])
    assert code == 2
    assert "non-public" in capsys.readouterr().err


def test_allow_private_runs_and_static_findings_fail_the_gate(capsys):
    # nothing listens on port 9, so probes fail; field-name findings still gate the build
    code = main([*BASE, "--base-url", "http://127.0.0.1:9", "--allow-private", "--max-retries", "0"])
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT: FAIL" in out and "AADHAAR" in out


def test_bad_spec_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    code = main(["scan", "--old", str(bad), "--new", str(bad), "--base-url", "http://127.0.0.1:9", "--allow-private"])
    assert code == 2
