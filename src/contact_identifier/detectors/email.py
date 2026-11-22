"""Email detector.

Offline-first signals:
  * syntactic validity
  * provider classification (free webmail vs. corporate vs. disposable)
  * role / no-reply address heuristics
  * Gmail dotted/plus-alias normalisation hint

Network (opt-in) signals:
  * MX records exist (domain can receive mail at all)
  * Gravatar avatar exists for the address (weak identity signal)
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path

from ..models import Report, Signal, Risk
from ..utils import http_get, network_allowed

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "tutanota.com", "fastmail.com",
}

ROLE_LOCALPARTS = {
    "admin", "administrator", "support", "info", "contact", "sales", "billing",
    "help", "service", "team", "office", "hello", "mail", "webmaster",
    "postmaster", "abuse", "security", "noreply", "no-reply", "donotreply",
}

_DATA_DIR = Path(os.environ.get("CONTACT_ID_DATA_DIR", Path(__file__).resolve().parents[3] / "data"))


@lru_cache(maxsize=1)
def _disposable_domains() -> frozenset[str]:
    path = _DATA_DIR / "disposable_domains.txt"
    out: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                out.add(line)
    except OSError:
        pass
    return frozenset(out)


def _normalize_gmail(local: str) -> str:
    """Gmail ignores dots and anything after '+'."""
    local = local.split("+", 1)[0]
    return local.replace(".", "")


def run(email: str, report: Report) -> None:
    email = email.strip().lower()
    if "@" not in email:
        report.add_error("email: no '@' found")
        return
    local, _, domain = email.partition("@")

    # --- provider classification -------------------------------------------
    if domain in _disposable_domains():
        report.add(Signal("email", "Disposable email domain", domain, Risk.HIGH,
                           "Throwaway address — the sender likely wants to stay anonymous."))
    elif domain in FREE_PROVIDERS:
        report.add(Signal("email", "Free webmail provider", domain, Risk.LOW,
                           "Common consumer provider; neutral but not tied to an organisation."))
    else:
        report.add(Signal("email", "Custom / organisational domain", domain, Risk.INFO,
                           "Address uses a non-webmail domain — check the domain itself for age/reputation."))

    # --- local-part heuristics ---------------------------------------------
    base_local = local.split("+", 1)[0]
    if base_local in ROLE_LOCALPARTS or any(base_local.startswith(p) for p in ("noreply", "no-reply", "donotreply")):
        report.add(Signal("email", "Role / automated address", local, Risk.INFO,
                           "Looks like a shared or automated mailbox rather than a specific person."))

    if "+" in local:
        report.add(Signal("email", "Plus-alias in use", local, Risk.INFO,
                           "A '+tag' sub-address; the real inbox is the part before '+'."))

    if domain in {"gmail.com", "googlemail.com"}:
        canonical = f"{_normalize_gmail(local)}@gmail.com"
        if canonical != email:
            report.add(Signal("email", "Gmail canonical form", canonical, Risk.INFO,
                               "Gmail ignores dots and '+tags'; this is the underlying account."))

    # --- network, opt-in ----------------------------------------------------
    if network_allowed():
        _mx_lookup(domain, report)
        _gravatar(email, report)


def _mx_lookup(domain: str, report: Report) -> None:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        report.add_error("email: dnspython not installed, skipping MX check")
        return
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=6.0)
        hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
        report.add(Signal("email", "Domain accepts mail (MX)", hosts, Risk.INFO,
                           f"{len(hosts)} mail server(s) configured.", source="dns"))
    except Exception:
        report.add(Signal("email", "No MX records", domain, Risk.MEDIUM,
                           "Domain cannot receive email — a reply address here is likely fake.",
                           source="dns"))


def _gravatar(email: str, report: Report) -> None:
    h = hashlib.md5(email.encode("utf-8")).hexdigest()
    resp = http_get(f"https://www.gravatar.com/avatar/{h}?d=404")
    if resp is None:
        return
    if resp.status_code == 200:
        report.add(Signal("email", "Gravatar avatar exists",
                           f"https://www.gravatar.com/{h}", Risk.INFO,
                           "A public Gravatar profile picture is linked to this address.",
                           source="gravatar"))
