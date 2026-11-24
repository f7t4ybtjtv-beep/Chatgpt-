from whocontacts.collectors.domain_collector import DomainCollector, extract_domain


def _keys(signals):
    return {s.key: s for s in signals}


def test_extract_domain():
    assert extract_domain("https://sub.example.com/path?x=1") == "sub.example.com"
    assert extract_domain("alice@Example.COM") == "example.com"
    assert extract_domain("example.org:443") == "example.org"


def test_lookalike_brand_offline():
    sig = _keys(DomainCollector(online=False).run("paypa1-secure.com"))
    assert "lookalike_domain" in sig
    assert sig["lookalike_domain"].risk >= 0.7


def test_phishing_keyword_hyphen():
    sig = _keys(DomainCollector(online=False).run("paypal-login.com"))
    assert "phishing_pattern" in sig


def test_legit_subdomain_not_flagged():
    # account.google.com must NOT trigger the hyphen-keyword rule.
    sig = _keys(DomainCollector(online=False).run("account.google.com"))
    assert "phishing_pattern" not in sig
