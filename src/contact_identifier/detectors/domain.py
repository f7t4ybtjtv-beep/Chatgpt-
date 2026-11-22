"""Domain detector.

Offline:
  * punycode / homoglyph ("fake lookalike") hint
  * suspicious TLD heuristics

Network (opt-in):
  * WHOIS creation date -> domain age (very young domains are a classic
    phishing / scam signal)
  * A/MX record presence
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Report, Signal, Risk
from ..utils import network_allowed

# TLDs over-represented in abuse reports (heuristic, not a blocklist).
_SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "club", "work", "click", "link", "gq", "cf",
    "ml", "ga", "tk", "rest", "country", "kim", "loan", "men", "download",
}


def run(domain: str, report: Report) -> None:
    domain = domain.strip().lower().rstrip(".")

    if domain.startswith("xn--") or ".xn--" in domain:
        report.add(Signal("domain", "Internationalised (punycode) domain", domain, Risk.MEDIUM,
                           "Uses non-ASCII characters — a common trick to mimic a real brand "
                           "(e.g. 'раypal' vs 'paypal'). Inspect carefully."))

    tld = domain.rsplit(".", 1)[-1]
    if tld in _SUSPICIOUS_TLDS:
        report.add(Signal("domain", f"Low-trust TLD: .{tld}", tld, Risk.LOW,
                           f".{tld} appears more often than average in spam/phishing. Not proof, "
                           "but a reason to be cautious."))

    if network_allowed():
        _whois_age(domain, report)
        _dns(domain, report)


def _whois_age(domain: str, report: Report) -> None:
    try:
        import whois  # type: ignore (python-whois)
    except ImportError:
        report.add_error("domain: 'python-whois' not installed — skipping age check")
        return
    try:
        info = whois.whois(domain)
    except Exception as exc:
        report.add_error(f"domain: WHOIS lookup failed ({exc})")
        return

    created = info.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if not isinstance(created, datetime):
        report.add(Signal("domain", "Registration date unknown", None, Risk.INFO,
                           "WHOIS did not return a creation date.", source="whois"))
        return

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < 30:
        risk = Risk.HIGH
        note = "Registered less than a month ago — strong phishing/scam indicator."
    elif age_days < 180:
        risk = Risk.MEDIUM
        note = "Registered within the last 6 months — be cautious."
    else:
        risk = Risk.INFO
        note = f"Established domain (~{age_days // 365} year(s) old)."
    report.add(Signal("domain", "Domain age", f"{age_days} days", risk, note, source="whois"))


def _dns(domain: str, report: Report) -> None:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return
    for rtype in ("A", "MX"):
        try:
            dns.resolver.resolve(domain, rtype, lifetime=6.0)
        except Exception:
            if rtype == "A":
                report.add(Signal("domain", "No A record", domain, Risk.LOW,
                                  "Domain does not currently resolve to a host.", source="dns"))
