from whocontacts.collectors.email_collector import EmailCollector
from whocontacts.utils.disposable import is_disposable


def _keys(signals):
    return {s.key: s for s in signals}


def test_disposable_detection():
    assert is_disposable("mailinator.com")
    assert is_disposable("foo.mailinator.com")
    assert not is_disposable("gmail.com")


def test_disposable_email_offline():
    sig = _keys(EmailCollector(online=False).run("x@mailinator.com"))
    assert "disposable_domain" in sig
    assert sig["disposable_domain"].risk > 0.5


def test_major_provider_offline():
    sig = _keys(EmailCollector(online=False).run("alice@gmail.com"))
    assert sig["major_provider"].value == "gmail.com"
    assert "offline_mode" in sig  # no network calls were attempted


def test_role_account():
    sig = _keys(EmailCollector(online=False).run("support@acme.com"))
    assert "role_account" in sig


def test_lookalike_domain():
    sig = _keys(EmailCollector(online=False).run("help@secure-paypa1.com"))
    assert "lookalike_domain" in sig
    assert sig["lookalike_domain"].risk >= 0.7


def test_invalid_email():
    sig = _keys(EmailCollector(online=False).run("not-an-email"))
    assert "invalid" in sig
