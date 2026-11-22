import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whocontacts.ai.analyzer import _rule_based  # noqa: E402
from whocontacts.findings import Report  # noqa: E402
from whocontacts.modules.phone_checks import _match_prefix  # noqa: E402


def test_report_scoring_and_band():
    r = Report("x", "email")
    r.add("neutre", weight=0)
    assert r.risk_score == 25 and r.risk_band == "FAIBLE"
    r.add("risqué", weight=40)
    assert r.risk_score == 65 and r.risk_band == "MOYEN"
    r.add("très risqué", weight=40)
    assert r.risk_score == 100 and r.risk_band == "ÉLEVÉ"


def test_report_score_clamped():
    r = Report("x", "email")
    r.add("rassurant", weight=-100)
    assert r.risk_score == 0 and r.risk_band == "TRÈS FAIBLE"


def test_fact_skips_empty():
    r = Report("x", "domain")
    r.fact("a", "")
    r.fact("b", None)
    r.fact("c", "ok")
    assert r.facts == {"c": "ok"}


def test_match_prefix():
    assert _match_prefix("+33612345678")[1][0] == "FR"
    assert _match_prefix("+14155550132")[1][0] == "US/CA"
    assert _match_prefix("+212600000000")[1][0] == "MA"
    assert _match_prefix("+9990000")[0] is None


def test_rule_based_high_risk():
    rd = {"risk_score": 85, "risk_band": "ÉLEVÉ", "kind": "email",
          "signals": [{"label": "E-mail jetable", "detail": "x.com", "weight": 40}]}
    out = _rule_based(rd)
    assert out["engine"] == "rules"
    assert "arnaque" in out["likely_nature"]
    assert out["red_flags"]
    assert out["recommendations"]


def test_rule_based_low_risk():
    rd = {"risk_score": 10, "risk_band": "TRÈS FAIBLE", "kind": "domain",
          "signals": [{"label": "Domaine établi", "detail": "", "weight": -10}]}
    out = _rule_based(rd)
    assert out["confidence"] == "faible"
    assert out["key_findings"]
