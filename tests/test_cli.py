import json
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


# ------------------------------------------------------------------ SARIF output and suppressions
OFFLINE = [*BASE, "--base-url", "http://127.0.0.1:9", "--allow-private", "--max-retries", "0"]


def ignore_file(tmp_path, expires="2099-01-01"):
    path = tmp_path / "ignore.yaml"
    path.write_text(
        "suppressions:\n  - endpoint: '*'\n    field: '*'\n"
        f"    reason: accepted for the test\n    expires: {expires}\n",
        encoding="utf-8",
    )
    return path


def test_sarif_is_written_to_file_and_text_still_printed(tmp_path, capsys):
    out = tmp_path / "result.sarif"
    code = main([*OFFLINE, "--format", "sarif", "--output", str(out)])
    assert code == 1
    assert "RESULT: FAIL" in capsys.readouterr().out
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("v2_openapi3.json") and "\\" not in uri


def test_ignore_file_turns_a_failing_gate_into_a_pass(tmp_path, capsys):
    code = main([*OFFLINE, "--ignore-file", str(ignore_file(tmp_path))])
    out = capsys.readouterr().out
    assert code == 0 and "RESULT: PASS" in out and "accepted: accepted for the test" in out


def test_expired_suppression_does_not_hide_findings(tmp_path, capsys):
    code = main([*OFFLINE, "--ignore-file", str(ignore_file(tmp_path, expires="2000-01-01"))])
    out = capsys.readouterr().out
    assert code == 1 and "expired suppression ignored" in out


def test_default_ignore_file_is_picked_up_from_cwd(tmp_path, monkeypatch, capsys):
    ignore_file(tmp_path).rename(tmp_path / ".piileak-ignore.yaml")
    monkeypatch.chdir(tmp_path)
    assert main(OFFLINE) == 0


def test_invalid_or_missing_ignore_file_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("suppressions:\n  - {endpoint: a, field: b}\n", encoding="utf-8")
    assert main([*OFFLINE, "--ignore-file", str(bad)]) == 2
    assert "invalid" in capsys.readouterr().err
    assert main([*OFFLINE, "--ignore-file", str(tmp_path / "nope.yaml")]) == 2
