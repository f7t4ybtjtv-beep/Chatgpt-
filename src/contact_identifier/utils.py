"""Small shared helpers: identifier type detection and safe network access."""

from __future__ import annotations

import os
import re
from typing import Optional

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Loose phone matcher: optional +, digits, spaces, dashes, parens, dots.
PHONE_RE = re.compile(r"^\+?[\d\s().\-]{6,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_.\-]{2,40}$")


def detect_kind(value: str) -> str:
    """Best-effort classification of a raw identifier.

    Returns one of: email, phone, domain, username, unknown.
    """
    v = value.strip()
    if EMAIL_RE.match(v):
        return "email"
    if DOMAIN_RE.match(v):
        return "domain"
    # Phone must contain enough digits to be plausible.
    digits = re.sub(r"\D", "", v)
    if PHONE_RE.match(v) and len(digits) >= 7:
        return "phone"
    if USERNAME_RE.match(v):
        return "username"
    return "unknown"


def network_allowed() -> bool:
    """Network lookups are opt-in.

    Set CONTACT_ID_ALLOW_NETWORK=1 to enable the few detectors that reach out
    to public services. Off by default so the toolkit is safe and deterministic
    in tests and offline environments.
    """
    return os.environ.get("CONTACT_ID_ALLOW_NETWORK", "").strip() in {"1", "true", "yes"}


def http_get(url: str, *, timeout: float = 6.0, headers: Optional[dict] = None):
    """Thin wrapper around requests that returns None instead of raising.

    Uses a neutral, generic User-Agent — never the operator's identity.
    """
    try:
        import requests  # imported lazily so the core has no hard dependency
    except ImportError:
        return None

    default_headers = {
        "User-Agent": "contact-identifier/0.1 (+OSINT research tool)",
        "Accept": "*/*",
    }
    if headers:
        default_headers.update(headers)
    try:
        return requests.get(url, timeout=timeout, headers=default_headers, allow_redirects=True)
    except Exception:
        return None
