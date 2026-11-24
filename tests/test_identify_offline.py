"""End-to-end offline checks: the whole pipeline must run with no network."""

from whocontacts import identify
from whocontacts.report import render_json, render_text


def test_full_pipeline_email_offline():
    rep = identify("x@mailinator.com", online=False, use_ai=False)
    assert rep.kind == "email"
    assert 0 <= rep.score <= 100
    assert rep.score > 50  # disposable domain => suspicious
    assert rep.verdict
    assert "mailinator" in render_text(rep)


def test_full_pipeline_domain_offline():
    rep = identify("example.com", online=False, use_ai=False)
    assert rep.kind == "domain"
    assert "example.com" in rep.summary or "example.com" in render_text(rep)


def test_json_roundtrip():
    rep = identify("@someuser", online=False, use_ai=False)
    js = render_json(rep)
    assert '"kind"' in js and '"signals"' in js


def test_unknown_identifier():
    rep = identify("", online=False, use_ai=False)
    assert rep.kind in ("unknown", "username")
