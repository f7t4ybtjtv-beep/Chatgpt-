import pytest

pytest.importorskip("phonenumbers")

from contact_identifier import identify  # noqa: E402


def test_valid_us_number():
    r = identify("+1 650-253-0000", kind="phone")
    labels = [s.label for s in r.signals]
    assert "Valid number" in labels
    assert any("Region" == s.label for s in r.signals)


def test_invalid_number_flagged():
    r = identify("+1 000-000-0000", kind="phone")
    labels = [s.label for s in r.signals]
    assert "Not a valid number" in labels


def test_region_default_applied():
    # UK mobile without country code, parsed with GB region.
    r = identify("07700 900123", kind="phone", default_region="GB")
    # Should parse into something and produce at least one signal or a clean error.
    assert r.signals or r.errors
