import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whocontacts.classify import classify, normalize  # noqa: E402


def test_email():
    assert classify("john.doe@example.com") == "email"
    assert classify("A.B+tag@Sub.Domain.CO.uk") == "email"


def test_ip():
    assert classify("8.8.8.8") == "ip"
    assert classify("2001:4860:4860::8888") == "ip"


def test_phone():
    assert classify("+33612345678") == "phone"
    assert classify("+1 (415) 555-0132") == "phone"
    assert classify("0612345678") == "phone"


def test_domain():
    assert classify("example.com") == "domain"
    assert classify("mon-site.co.uk") == "domain"


def test_url():
    assert classify("https://example.com/path") == "url"


def test_username():
    assert classify("cool_user-99") == "username"
    assert classify("@handle") == "username"


def test_unknown():
    assert classify("") == "unknown"
    assert classify("ceci est une phrase avec des espaces") == "unknown"


def test_normalize():
    assert normalize("John@Example.COM", "email") == "john@example.com"
    assert normalize("@Handle", "username") == "Handle"
    assert normalize("+33 6 12-34", "phone") == "+3361234"
    assert normalize("Example.COM.", "domain") == "example.com"
