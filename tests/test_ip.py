"""Tests du collecteur IP et de la détection d'IP (hors-ligne, déterministe)."""

from whocontacts.detect import detect_kind
from whocontacts.collectors.ip_collector import IPCollector, parse_ip
from whocontacts.identify import identify


# -- détection --------------------------------------------------------------- #
def test_detect_ipv4():
    assert detect_kind("8.8.8.8") == "ip"


def test_detect_ipv6():
    assert detect_kind("2001:4860:4860::8888") == "ip"


def test_detect_bracketed_ipv6():
    assert detect_kind("[2001:db8::1]") == "ip"


def test_plain_number_still_phone_not_ip():
    # Une IP a des points ; un numéro reste un numéro.
    assert detect_kind("0612345678") == "phone"


# -- parse ------------------------------------------------------------------- #
def test_parse_ip_valid_and_invalid():
    assert parse_ip("1.1.1.1") is not None
    assert parse_ip("[2001:db8::1]") is not None
    assert parse_ip("999.1.1.1") is None
    assert parse_ip("not-an-ip") is None


# -- classification hors-ligne ---------------------------------------------- #
def _keys(signals):
    return {s.key for s in signals}


def test_private_ip_flagged():
    sigs = IPCollector(online=False).run("192.168.1.10")
    assert "private" in _keys(sigs)


def test_loopback_flagged():
    sigs = IPCollector(online=False).run("127.0.0.1")
    assert "loopback" in _keys(sigs)


def test_documentation_range_flagged():
    sigs = IPCollector(online=False).run("203.0.113.9")
    assert "documentation" in _keys(sigs)
    doc = next(s for s in sigs if s.key == "documentation")
    assert doc.risk > 0.4


def test_public_ip_offline_has_no_network_signals():
    sigs = IPCollector(online=False).run("8.8.8.8")
    keys = _keys(sigs)
    assert "public" in keys
    assert "offline_mode" in keys
    assert "ptr" not in keys and "hosting" not in keys and "network" not in keys


def test_invalid_ip_is_soft_signal_not_crash():
    sigs = IPCollector(online=False).run("999.999.999.999")
    assert "invalid" in _keys(sigs)


# -- intégration ------------------------------------------------------------- #
def test_identify_ip_offline_report():
    rep = identify("192.168.0.1", online=False, use_ai=False)
    assert rep.kind == "ip"
    assert rep.summary  # une synthèse est produite
    data = rep.to_dict()
    assert data["kind"] == "ip"
    assert data["target"] == "192.168.0.1"
