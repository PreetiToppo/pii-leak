"""Custom Presidio recognizers for Indian identifiers.

Presidio's defaults are US-centric. Regex alone gives many false positives on
digit strings, so Aadhaar is also validated with the Verhoeff checksum.
"""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer

# ---- Verhoeff checksum (used by Aadhaar's last digit) -----------------------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Check digit to append to `number` (handy for generating test data)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


# ---- Recognizers -------------------------------------------------------------
class AadhaarRecognizer(PatternRecognizer):
    """12 digits, first digit 2-9, optional space/hyphen grouping, Verhoeff-valid."""

    def __init__(self):
        super().__init__(
            supported_entity="AADHAAR",
            patterns=[Pattern("aadhaar", r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)", 0.4)],
            context=["aadhaar", "aadhar", "uidai", "uid"],
        )

    def validate_result(self, pattern_text: str):
        digits = re.sub(r"[\s-]", "", pattern_text)
        return True if verhoeff_valid(digits) else False  # False drops the match


class PanRecognizer(PatternRecognizer):
    """Permanent Account Number: AAAAA9999A. 4th letter encodes holder type."""

    def __init__(self):
        super().__init__(
            supported_entity="PAN",
            patterns=[Pattern("pan", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.6)],
            context=["pan", "permanent account", "income tax"],
        )


class IfscRecognizer(PatternRecognizer):
    """Bank branch code: 4 letters + '0' + 6 alphanumerics, e.g. SBIN0001234."""

    def __init__(self):
        super().__init__(
            supported_entity="IFSC",
            patterns=[Pattern("ifsc", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.6)],
            context=["ifsc", "bank", "branch"],
        )


UPI_HANDLES = (
    "okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|apl|upi|sbi|hdfcbank|icici|axisbank|"
    "kotak|pnb|boi|cnrb|fbl|idfcbank|jupiteraxis|freecharge|airtel|postbank|aubank|rbl|yesbank"
)


class UpiRecognizer(PatternRecognizer):
    """UPI VPA (name@handle). Restricted to known PSP handles so it does not
    swallow every email address."""

    def __init__(self):
        super().__init__(
            supported_entity="UPI_ID",
            patterns=[Pattern("upi", rf"\b[\w.\-]{{2,64}}@(?:{UPI_HANDLES})\b", 0.85)],
            context=["upi", "vpa", "payment"],
        )


class IndianMobileRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_MOBILE",
            patterns=[Pattern("in_mobile", r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", 0.55)],
            context=["phone", "mobile", "contact", "whatsapp"],
        )


def custom_recognizers():
    return [AadhaarRecognizer(), PanRecognizer(), IfscRecognizer(), UpiRecognizer(), IndianMobileRecognizer()]
