"""PII detection: value-level (Presidio + spaCy + custom recognizers) and
name-level (field names like 'aadhaar_number' that hint at sensitive data)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .models import Severity
from .recognizers import custom_recognizers

ENTITY_SEVERITY: dict[str, Severity] = {
    "AADHAAR": Severity.HIGH,
    "PAN": Severity.HIGH,
    "CREDIT_CARD": Severity.HIGH,
    "US_SSN": Severity.HIGH,
    "SECRET": Severity.HIGH,
    "BANK_ACCOUNT": Severity.HIGH,
    "IBAN_CODE": Severity.HIGH,
    "UPI_ID": Severity.MEDIUM,
    "EMAIL_ADDRESS": Severity.MEDIUM,
    "PHONE_NUMBER": Severity.MEDIUM,
    "IN_MOBILE": Severity.MEDIUM,
    "DATE_OF_BIRTH": Severity.MEDIUM,
    "ADDRESS": Severity.MEDIUM,
    "SALARY": Severity.MEDIUM,
    "PERSON": Severity.LOW,
    "IFSC": Severity.LOW,
    "IP_ADDRESS": Severity.LOW,
}
_NAME_ONLY = ("SECRET", "BANK_ACCOUNT", "DATE_OF_BIRTH", "ADDRESS", "SALARY")  # no value recognizer
DEFAULT_ENTITIES = [e for e in ENTITY_SEVERITY if e not in _NAME_ONLY]

# (entity, regex on snake_case leaf field name)
NAME_HINTS: list[tuple[str, re.Pattern]] = [
    ("AADHAAR", re.compile(r"aadhaar|aadhar|uidai")),
    ("PAN", re.compile(r"^pan$|^pan_(no|number|card)|_pan$")),
    ("US_SSN", re.compile(r"^ssn$|social_security")),
    ("SECRET", re.compile(r"password|passwd|secret|api_?key|access_token|refresh_token|private_key")),
    ("CREDIT_CARD", re.compile(r"card_(no|number|num)|credit_card|cvv")),
    ("BANK_ACCOUNT", re.compile(r"account_(no|number|num)|^iban$")),
    ("UPI_ID", re.compile(r"upi|vpa")),
    ("IFSC", re.compile(r"ifsc")),
    ("EMAIL_ADDRESS", re.compile(r"e_?mail")),
    ("PHONE_NUMBER", re.compile(r"phone|mobile|msisdn")),
    ("DATE_OF_BIRTH", re.compile(r"^dob$|birth_?date|date_of_birth")),
    ("ADDRESS", re.compile(r"address|postal_code|pincode|zip")),
    ("SALARY", re.compile(r"salary|compensation|^ctc$")),
]


def to_snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def leaf_name(path: str) -> str:
    leaf = re.split(r"[.\[\]]+", path.rstrip("[]"))
    leaf = [p for p in leaf if p]
    return to_snake(leaf[-1]) if leaf else ""


def name_hint(path: str) -> str | None:
    leaf = leaf_name(path)
    for entity, rx in NAME_HINTS:
        if rx.search(leaf):
            return entity
    return None


def mask(value: str) -> str:
    """Never put raw PII in reports or logs."""
    v = str(value)
    return "*" * len(v) if len(v) <= 4 else "*" * (len(v) - 2) + v[-2:]


def canonical_field(path: str) -> str:
    """'items[3].email' -> 'items[].email' so response paths match spec paths."""
    return re.sub(r"\[\d+\]", "[]", path)


def walk_leaves(node: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (path, scalar) for every scalar in a JSON document."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk_leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_leaves(v, f"{path}[{i}]")
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
        yield path, node


def _make_tldextract_offline() -> None:
    """Presidio's email/url validators call tldextract, which downloads the public
    suffix list on first use. CI runners are often offline, so use the bundled copy."""
    try:
        import tldextract
        from tldextract import tldextract as _mod

        _mod.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
    except Exception:  # noqa: BLE001  (best effort only)
        pass


class PiiDetector:
    def __init__(
        self,
        model: str = "en_core_web_sm",
        entities: list[str] | None = None,
        min_score: float = 0.5,
        include_person: bool = False,
    ):
        _make_tldextract_offline()
        nlp = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            }
        ).create_engine()
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(nlp_engine=nlp, languages=["en"])
        for rec in custom_recognizers():
            registry.add_recognizer(rec)
        self.analyzer = AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en"])
        self.entities = list(entities or DEFAULT_ENTITIES)
        if include_person and "PERSON" not in self.entities:
            self.entities.append("PERSON")
        if not include_person and "PERSON" in self.entities and entities is None:
            self.entities.remove("PERSON")
        self.min_score = min_score
        self._cache: dict[str, list[tuple[str, float]]] = {}

    def scan_value(self, value: Any) -> list[tuple[str, float, str]]:
        """Return [(entity, score, masked_sample)] for one scalar value."""
        text = str(value)
        if not text or len(text) > 2000:
            return []
        if text not in self._cache:
            results = self.analyzer.analyze(
                text=text, language="en", entities=self.entities, score_threshold=self.min_score
            )
            # keep the best result per entity
            best: dict[str, float] = {}
            for r in results:
                best[r.entity_type] = max(best.get(r.entity_type, 0), r.score)
            self._cache[text] = sorted(best.items())
        masked = mask(text)
        return [(ent, score, masked) for ent, score in self._cache[text]]
