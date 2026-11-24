"""Optional AI synthesis layer.

Given the collected signals, produce a short, plain-French narrative:
*who is probably behind this identifier*, *the red flags*, and *what to do*.

Two backends:
1. **Claude** (Anthropic API) when ``ANTHROPIC_API_KEY`` is set and the
   ``anthropic`` package is importable. The identifier and its *public* signals
   are sent to the API — nothing about the user running the tool.
2. **Rule-based fallback** otherwise: a deterministic template built from the
   same signals. The tool is therefore fully useful with **no** API key.

The AI is a *writer*, not a *judge*: the numeric score always comes from
:mod:`whocontacts.risk`, so enabling AI never changes the verdict, only its
explanation.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

from .collectors.base import Signal
from . import risk as _risk

_MODEL = os.environ.get("WHOCONTACTS_MODEL", "claude-opus-4-8")

_SYSTEM = (
    "Tu es un assistant de cybersécurité défensive. On te fournit un identifiant "
    "(e-mail, numéro, domaine ou pseudo) qui a contacté l'utilisateur, et des "
    "signaux OSINT publics déjà collectés. Rédige en français, en 4 à 8 phrases, "
    "une synthèse honnête et prudente : qui est-ce probablement, les signaux "
    "d'alerte éventuels, et une recommandation concrète (répondre / vérifier / "
    "se méfier / bloquer). N'invente aucune donnée au-delà des signaux fournis. "
    "Rappelle que ce sont des indices, pas des preuves. Ne propose jamais de "
    "traquer ou de harceler la personne."
)


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False


def summarize(kind: str, target: str, signals: List[Signal]) -> str:
    """Return a narrative summary, via Claude if available else rule-based."""
    if available():
        try:
            return _claude_summary(kind, target, signals)
        except Exception:
            pass  # fall through to deterministic text
    return rule_based_summary(kind, target, signals)


def _claude_summary(kind: str, target: str, signals: List[Signal]) -> str:
    import anthropic  # type: ignore

    client = anthropic.Anthropic()
    payload = {
        "type": kind,
        "identifiant": target,
        "score_suspicion_sur_100": _risk.score(signals),
        "signaux": [s.to_dict() for s in signals],
    }
    msg = client.messages.create(
        model=_MODEL,
        max_tokens=600,
        system=_SYSTEM,
        messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
    )
    parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
    return "\n".join(parts).strip() or rule_based_summary(kind, target, signals)


def rule_based_summary(kind: str, target: str, signals: List[Signal]) -> str:
    sc = _risk.score(signals)
    cov = _risk.coverage(signals)
    label, _ = _risk.verdict(sc, cov)
    reasons = _risk.top_reasons(signals, n=4)

    kind_fr = {
        "email": "cette adresse e-mail",
        "phone": "ce numéro de téléphone",
        "domain": "ce domaine",
        "ip": "cette adresse IP",
        "username": "ce pseudonyme",
        "url": "cette adresse web",
    }.get(kind, "cet identifiant")

    lines = [f"Analyse de {kind_fr} « {target} » — verdict : {label} (score {sc}/100)."]
    if reasons:
        lines.append("Éléments déterminants :")
        for s in reasons:
            arrow = "⚠️" if s.risk > 0.1 else ("✓" if s.risk < -0.1 else "•")
            lines.append(f"  {arrow} {s.note}")
    if label == "SIGNAL INSUFFISANT":
        lines.append(
            "Recommandation : trop peu d'indices publics pour conclure. Ni rassurant, "
            "ni alarmant à ce stade. Installez les dépendances optionnelles ou "
            "fournissez un identifiant plus complet (e-mail/domaine) pour affiner, "
            "et vérifiez l'identité par un canal indépendant."
        )
    elif sc >= 55:
        lines.append(
            "Recommandation : prudence. Ne cliquez sur aucun lien, ne communiquez "
            "aucune donnée personnelle ou bancaire, et vérifiez l'expéditeur par un "
            "canal indépendant avant toute action."
        )
    elif sc >= 45:
        lines.append(
            "Recommandation : incertain. Demandez une confirmation par un autre "
            "moyen et restez vigilant·e tant que l'identité n'est pas établie."
        )
    else:
        lines.append(
            "Recommandation : aucun signal fort d'arnaque, mais gardez l'esprit "
            "critique : ces indices ne prouvent pas la bonne foi de la personne."
        )
    lines.append("(Ces résultats sont des indices probabilistes issus de sources publiques, pas des preuves.)")
    return "\n".join(lines)
