"""Accepted-risk suppressions (.piileak-ignore.yaml).

WHY: a gate that cannot be told "we know about this one" gets disabled. Every suppression
therefore needs a reason and an expiry date, so accepted risk is reviewed again later,
and suppressed findings stay visible in reports instead of vanishing.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from .models import Finding

DEFAULT_IGNORE_FILE = ".piileak-ignore.yaml"
EXPIRY_WARNING_DAYS = 14


class SuppressionError(ValueError):
    """The ignore file is unreadable or invalid."""


def _glob(pattern: str, text: str) -> bool:
    """Only '*' is a wildcard. (fnmatch would treat the '[]' in paths like items[].email as a class.)"""
    regex = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.match(regex, text) is not None


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo like "expiry:" must be an error, not silently ignored

    endpoint: str
    field: str
    entity: str = "*"
    reason: str
    expires: date

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reason must not be empty")
        return value.strip()

    def label(self) -> str:
        return f"{self.endpoint} {self.field} {self.entity}"

    def matches(self, finding: Finding) -> bool:
        return (
            _glob(self.endpoint, finding.endpoint)
            and _glob(self.field, finding.field)
            and (self.entity == "*" or self.entity.upper() == finding.entity.upper())
        )


def load_suppressions(path: str | Path) -> list[Suppression]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SuppressionError(f"cannot read ignore file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SuppressionError(f"{path} is not valid YAML: {exc}") from exc
    if raw is None:
        return []
    items = raw.get("suppressions") if isinstance(raw, dict) else None
    if items is None:
        return []
    if not isinstance(items, list):
        raise SuppressionError(f"{path}: 'suppressions' must be a list")
    out: list[Suppression] = []
    for index, item in enumerate(items, start=1):
        try:
            out.append(Suppression.model_validate(item))
        except ValidationError as exc:
            detail = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'entry'}: {e['msg']}" for e in exc.errors())
            raise SuppressionError(f"{path}: suppression #{index} is invalid ({detail})") from exc
    return out


def apply_suppressions(
    findings: list[Finding], suppressions: list[Suppression], today: date
) -> tuple[list[Finding], list[str]]:
    """Mark matching findings as suppressed. Returns (findings, warnings).

    Expired suppressions are ignored (the finding comes back), unused ones are reported so
    they can be deleted, and ones expiring soon are flagged.
    """
    warnings: list[str] = []
    active: list[Suppression] = []
    for s in suppressions:
        if s.expires < today:
            warnings.append(f"expired suppression ignored: {s.label()} (expired {s.expires})")
        else:
            active.append(s)
            days_left = (s.expires - today).days
            if days_left <= EXPIRY_WARNING_DAYS:
                warnings.append(f"suppression expires in {days_left} day(s): {s.label()} ({s.expires})")

    used: set[int] = set()
    result: list[Finding] = []
    for finding in findings:
        hit = next((s for s in active if s.matches(finding)), None)
        if hit is None:
            result.append(finding)
        else:
            used.add(id(hit))
            result.append(finding.model_copy(update={"suppressed": True, "suppression_reason": hit.reason}))
    warnings += [f"unused suppression (matches nothing): {s.label()}" for s in active if id(s) not in used]
    return result, warnings
