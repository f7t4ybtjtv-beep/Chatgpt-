"""Detection of disposable / throwaway e-mail domains.

A curated, offline list of common disposable-mail providers. It is intentionally
small and high-precision: a hit is a strong signal, a miss means "unknown", not
"legitimate". The list can be extended via ``WHOCONTACTS_DISPOSABLE_FILE`` (one
domain per line).
"""

from __future__ import annotations

import os
from functools import lru_cache

# High-confidence disposable providers (non-exhaustive but widely seen).
_BUILTIN = {
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamail.info",
    "sharklasers.com",
    "grr.la",
    "10minutemail.com",
    "10minutemail.net",
    "temp-mail.org",
    "tempmail.com",
    "tempmailo.com",
    "throwawaymail.com",
    "yopmail.com",
    "yopmail.fr",
    "getnada.com",
    "nada.email",
    "dispostable.com",
    "trashmail.com",
    "trashmail.de",
    "maildrop.cc",
    "mailnesia.com",
    "fakeinbox.com",
    "mohmal.com",
    "emailondeck.com",
    "spam4.me",
    "mytemp.email",
    "tempinbox.com",
    "mailcatch.com",
    "moakt.com",
    "burnermail.io",
    "33mail.com",
    "jetable.org",
    "spambog.com",
    "mintemail.com",
    "tempr.email",
    "discard.email",
    "einrot.com",
    "cuvox.de",
    "dayrep.com",
    "rhyta.com",
    "teleworm.us",
}


@lru_cache(maxsize=1)
def _domains() -> frozenset:
    domains = set(_BUILTIN)
    extra = os.environ.get("WHOCONTACTS_DISPOSABLE_FILE")
    if extra and os.path.exists(extra):
        try:
            with open(extra, "r", encoding="utf-8") as fh:
                for line in fh:
                    d = line.strip().lower()
                    if d and not d.startswith("#"):
                        domains.add(d)
        except OSError:
            pass
    return frozenset(domains)


def is_disposable(domain: str) -> bool:
    """Return True if *domain* (or its registrable parent) is disposable."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return False
    if domain in _domains():
        return True
    # Match parent domain, e.g. "foo.mailinator.com" -> "mailinator.com".
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in _domains():
            return True
    return False
