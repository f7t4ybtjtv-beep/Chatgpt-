from contact_identifier.utils import detect_kind


def test_detect_email():
    assert detect_kind("alice@example.com") == "email"


def test_detect_domain():
    assert detect_kind("example.com") == "domain"
    assert detect_kind("sub.example.co.uk") == "domain"


def test_detect_phone():
    assert detect_kind("+1 202-555-0142") == "phone"
    assert detect_kind("07700 900123") == "phone"


def test_detect_username():
    assert detect_kind("@cool_handle") == "username"
    assert detect_kind("john.doe-42") == "username"


def test_detect_unknown():
    assert detect_kind("") == "unknown"
    assert detect_kind("hi there!") == "unknown"
