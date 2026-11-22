"""Détection du type d'identifiant fourni par l'utilisateur."""
from __future__ import annotations

import ipaddress
import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Domaine : labels alphanum/tirets, TLD d'au moins 2 lettres.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,24}$"
)
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().\-]{5,20}[0-9]$")
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9._\-]{2,40}$")
URL_RE = re.compile(r"^https?://", re.I)


def classify(value: str) -> str:
    """Renvoie: 'email' | 'ip' | 'domain' | 'url' | 'phone' | 'username' | 'unknown'."""
    v = value.strip()
    if not v:
        return "unknown"

    if URL_RE.match(v):
        return "url"

    if EMAIL_RE.match(v):
        return "email"

    # IP (v4 ou v6)
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # Numéro de téléphone : surtout des chiffres, peu de lettres.
    digits = sum(c.isdigit() for c in v)
    if PHONE_RE.match(v) and digits >= 6:
        return "phone"

    if DOMAIN_RE.match(v):
        return "domain"

    if USERNAME_RE.match(v):
        return "username"

    return "unknown"


def normalize(value: str, kind: str) -> str:
    v = value.strip()
    if kind == "email":
        return v.lower()
    if kind == "domain":
        return v.lower().rstrip(".")
    if kind == "username":
        return v.lstrip("@")
    if kind == "phone":
        return re.sub(r"[^\d+]", "", v)
    return v
