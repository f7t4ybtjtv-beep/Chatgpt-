from contact_identifier import identify, Risk


def test_punycode_domain_flagged():
    r = identify("xn--pple-43d.com", kind="domain")  # fake "apple" lookalike
    labels = [s.label for s in r.signals]
    assert "Internationalised (punycode) domain" in labels
    assert r.risk.weight >= Risk.MEDIUM.weight


def test_suspicious_tld():
    r = identify("free-prize.top", kind="domain")
    labels = [s.label for s in r.signals]
    assert any("Low-trust TLD" in lbl for lbl in labels)


def test_username_offline_returns_candidate_urls():
    r = identify("somehandle", kind="username")
    labels = [s.label for s in r.signals]
    assert "Candidate profile URLs" in labels
    # Offline mode must not produce "found" signals.
    assert not any(s.label.startswith("Profile found") for s in r.signals)


def test_report_json_roundtrips():
    r = identify("alice@gmail.com")
    data = r.to_dict()
    assert data["query"] == "alice@gmail.com"
    assert data["kind"] == "email"
    assert "risk" in data and "signals" in data
