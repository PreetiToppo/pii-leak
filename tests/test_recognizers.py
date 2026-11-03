import pytest

from piileak.recognizers import verhoeff_check_digit, verhoeff_valid


@pytest.mark.parametrize("base", ["23456789012", "98765432109", "50000000001"])
def test_verhoeff_roundtrip(base):
    full = base + verhoeff_check_digit(base)
    assert verhoeff_valid(full)
    wrong = base + str((int(full[-1]) + 1) % 10)
    assert not verhoeff_valid(wrong)


def entities(detector, value):
    return {e for e, _, _ in detector.scan_value(value)}


def test_aadhaar_valid_and_invalid(detector):
    assert "AADHAAR" in entities(detector, "2345 6789 0124")
    assert "AADHAAR" in entities(detector, "234567890124")
    assert "AADHAAR" not in entities(detector, "2345 6789 0123")  # bad checksum
    assert "AADHAAR" not in entities(detector, "1345 6789 0124")  # cannot start with 0/1


def test_pan_ifsc_upi(detector):
    assert "PAN" in entities(detector, "ABCPE1234F")
    assert "PAN" not in entities(detector, "ABCXE1234F")  # 4th letter invalid
    assert "IFSC" in entities(detector, "SBIN0001234")
    assert "UPI_ID" in entities(detector, "asha.rao@okaxis")


def test_email_is_not_upi(detector):
    ents = entities(detector, "asha.rao@example.com")
    assert "EMAIL_ADDRESS" in ents and "UPI_ID" not in ents


def test_indian_mobile_formats(detector):
    for v in ["+91 98765 43210", "9876543210", "+91-9876543210"]:
        assert entities(detector, v) & {"IN_MOBILE", "PHONE_NUMBER"}, v


def test_plain_text_is_clean(detector):
    assert entities(detector, "hello world") == set()
    assert entities(detector, "IN") == set()
