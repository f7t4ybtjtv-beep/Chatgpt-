"""Detect what kind of identifier the user handed us.

Supported kinds: ``email``, ``phone``, ``domain``, ``username``, ``url``.
Detection is heuristic but deterministic and well-tested.
"""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
# A loose phone matcher: optional +, digits, spaces, dashes, dots, parens.
_PHONE_CHARS_RE = re.compile(r"^[+()\-.\s0-9]{6,}$")


def normalize(target: str) -> str:
    return (target or "").strip()


def detect_kind(target: str) -> str:
    """Return the identifier kind for *target*.

    Order matters: e-mail and URL are unambiguous; phone before domain because
    a bare numeric string is a phone, not a domain; username is the fallback.
    """
    t = normalize(target)
    if not t:
        return "unknown"

    if _EMAIL_RE.match(t):
        return "email"

    if _URL_RE.match(t):
        return "url"

    # Phone: strip formatting; mostly digits (>=6), possibly a leading '+'.
    digits = re.sub(r"[^\d]", "", t)
    if _PHONE_CHARS_RE.match(t) and 6 <= len(digits) <= 15 and "." not in _strip_plus(t):
        # Avoid catching things like "1.2.3.4" (handled: '.' excluded above).
        return "phone"

    if _DOMAIN_RE.match(t) and not t.endswith((".local",)):
        return "domain"

    # Username: strip a leading '@' that people paste from social handles.
    return "username"


def _strip_plus(t: str) -> str:
    return t[1:] if t.startswith("+") else t


def clean_username(target: str) -> str:
    return normalize(target).lstrip("@")
