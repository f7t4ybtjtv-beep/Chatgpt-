from contact_identifier import identify, Risk


def test_disposable_email_is_high_risk():
    r = identify("scammer@mailinator.com")
    assert r.kind == "email"
    labels = [s.label for s in r.signals]
    assert "Disposable email domain" in labels
    assert r.risk == Risk.HIGH


def test_free_provider_is_low_risk():
    r = identify("someone@gmail.com")
    labels = [s.label for s in r.signals]
    assert "Free webmail provider" in labels
    assert r.risk in (Risk.LOW, Risk.INFO)


def test_gmail_canonical_form():
    r = identify("john.doe+newsletter@gmail.com")
    canon = [s for s in r.signals if s.label == "Gmail canonical form"]
    assert canon and canon[0].value == "johndoe@gmail.com"


def test_role_address():
    r = identify("support@acme.com")
    labels = [s.label for s in r.signals]
    assert "Role / automated address" in labels


def test_custom_domain_is_info():
    r = identify("ceo@acme-corp.io")
    labels = [s.label for s in r.signals]
    assert "Custom / organisational domain" in labels


def test_summary_is_populated():
    r = identify("x@mailinator.com")
    assert r.summary
    assert "HIGH" in r.summary
