import json
from pathlib import Path

import pytest

from piileak.detector import PiiDetector

SPECS = Path(__file__).parent.parent / "examples" / "specs"


@pytest.fixture(scope="session")
def detector():
    return PiiDetector()


@pytest.fixture(scope="session")
def v1_spec():
    return json.loads((SPECS / "v1_swagger2.json").read_text())


@pytest.fixture(scope="session")
def v2_spec():
    return json.loads((SPECS / "v2_openapi3.json").read_text())
