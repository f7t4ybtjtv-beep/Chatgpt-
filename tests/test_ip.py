"""Tests for the IP-address detector (offline, deterministic)."""

from contact_identifier import identify, Risk
from contact_identifier.utils import detect_kind


def test_detect_kind_ipv4():
    assert detect_kind("8.8.8.8") == "ip"


def test_detect_kind_ipv6():
    assert detect_kind("2001:4860:4860::8888") == "ip"


def test_detect_kind_bracketed_ipv6():
    assert detect_kind("[2001:db8::1]") == "ip"


def test_public_ip_is_info_level():
    r = identify("8.8.8.8")
    assert r.kind == "ip"
    labels = [s.label for s in r.signals]
    assert "Public address" in labels
    # Nothing alarming for a plain public address in offline mode.
    assert r.risk.weight < Risk.MEDIUM.weight


def test_private_ip_flagged_low():
    r = identify("192.168.1.10")
    labels = [s.label for s in r.signals]
    assert "Private / internal address" in labels
    assert r.risk == Risk.LOW


def test_loopback_flagged():
    r = identify("127.0.0.1")
    labels = [s.label for s in r.signals]
    assert "Loopback address" in labels


def test_documentation_range_is_medium():
    # 203.0.113.0/24 is reserved for documentation (RFC 5737).
    r = identify("203.0.113.9")
    labels = [s.label for s in r.signals]
    assert "Documentation-only address" in labels
    assert r.risk.weight >= Risk.MEDIUM.weight


def test_invalid_ip_forced_kind_records_error():
    r = identify("999.999.999.999", kind="ip")
    assert r.errors
    assert any("not a valid" in e for e in r.errors)


def test_ip_offline_makes_no_network_signals():
    # Without CONTACT_ID_ALLOW_NETWORK, no DNS/RDAP sourced signals appear.
    r = identify("8.8.8.8")
    assert all(s.source == "local" for s in r.signals)


def test_ip_report_json_roundtrips():
    r = identify("8.8.8.8")
    data = r.to_dict()
    assert data["kind"] == "ip"
    assert data["query"] == "8.8.8.8"
