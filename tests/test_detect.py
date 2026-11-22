from whocontacts.detect import clean_username, detect_kind


def test_detect_email():
    assert detect_kind("alice@example.com") == "email"
    assert detect_kind("  Bob.Smith@mail.co.uk ") == "email"


def test_detect_url():
    assert detect_kind("https://example.com/path") == "url"
    assert detect_kind("http://sub.domain.org") == "url"


def test_detect_phone():
    assert detect_kind("+33 6 12 34 56 78") == "phone"
    assert detect_kind("0612345678") == "phone"
    assert detect_kind("(202) 555-0147") == "phone"


def test_detect_domain():
    assert detect_kind("example.com") == "domain"
    assert detect_kind("mail.google.com") == "domain"


def test_detect_username():
    assert detect_kind("@john_doe") == "username"
    assert detect_kind("john_doe") == "username"
    assert detect_kind("coolhandle42") == "username"


def test_clean_username():
    assert clean_username("@handle") == "handle"
    assert clean_username("  handle ") == "handle"


def test_empty():
    assert detect_kind("") == "unknown"
