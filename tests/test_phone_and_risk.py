from whocontacts.collectors.base import Signal
from whocontacts.collectors.phone_collector import PhoneCollector
from whocontacts.risk import score, top_reasons, verdict


def _keys(signals):
    return {s.key: s for s in signals}


def test_phone_parses_offline():
    sig = _keys(PhoneCollector(online=False).run("+33612345678"))
    # Either the library path (valid/line_type) or the fallback (country) ran.
    assert "input" in sig
    assert "country" in sig or "valid" in sig


def test_phone_invalid_length():
    sig = _keys(PhoneCollector(online=False).run("123"))
    assert "invalid" in sig


def test_score_bounds_and_direction():
    reassuring = [Signal("t", "a", True, risk=-0.8, confidence=0.9)]
    suspicious = [Signal("t", "b", True, risk=0.8, confidence=0.9)]
    assert score([]) == 50  # no evidence -> neutral, not "clean"
    assert 0 <= score(reassuring) <= 100
    assert score(suspicious) > score(reassuring)


def test_verdict_labels():
    assert verdict(90)[0] == "TRÈS SUSPECT"
    assert verdict(10)[0] == "FIABLE"


def test_verdict_insufficient_when_low_coverage():
    # High score but almost no evidence weight -> honest "insufficient".
    assert verdict(90, cov=0.1)[0] == "SIGNAL INSUFFISANT"
    # Enough evidence -> real verdict shows through.
    assert verdict(90, cov=1.0)[0] == "TRÈS SUSPECT"


def test_top_reasons_ranks_by_impact():
    sigs = [
        Signal("t", "weak", 1, note="weak", risk=0.1, confidence=0.2),
        Signal("t", "strong", 1, note="strong", risk=0.9, confidence=0.9),
    ]
    assert top_reasons(sigs, 1)[0].key == "strong"
