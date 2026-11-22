"""Orchestrateur : classe l'identifiant, lance le bon module, ajoute l'IA."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .ai.analyzer import analyze_with_ai
from .classify import classify, normalize
from .findings import Report
from .modules import (
    domain_checks,
    email_checks,
    ip_checks,
    phone_checks,
    username_checks,
)


def investigate(value: str, with_ai: bool = True) -> dict[str, Any]:
    """Point d'entrée programmatique. Renvoie {'report': {...}, 'ai': {...}}."""
    kind = classify(value)

    # Une URL est ramenée à son domaine.
    if kind == "url":
        host = urlparse(value if "://" in value else "http://" + value).hostname or value
        value, kind = host, "domain"

    norm = normalize(value, kind)

    if kind == "email":
        report = email_checks.analyze(norm)
    elif kind == "phone":
        report = phone_checks.analyze(norm)
    elif kind == "domain":
        report = domain_checks.analyze(norm)
    elif kind == "ip":
        report = ip_checks.analyze(norm)
    elif kind == "username":
        report = username_checks.analyze(norm)
    else:
        report = Report(identifier=value, kind="unknown")
        report.add("Identifiant non reconnu",
                   "fournissez un e-mail, téléphone, pseudo, domaine ou IP",
                   weight=0, source="classify")

    rd = report.to_dict()
    ai = analyze_with_ai(rd) if with_ai else {"engine": "disabled", "verdict": "",
                                              "likely_nature": "?", "confidence": "?"}
    return {"report": rd, "ai": ai}
