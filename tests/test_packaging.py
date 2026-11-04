"""Release hygiene: the version lives in two places and must never drift apart."""

from importlib.metadata import entry_points, version

import piileak


def test_installed_metadata_version_matches_package_version():
    assert version("piileak") == piileak.__version__


def test_console_script_is_registered():
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts["piileak"] == "piileak.cli:main"
