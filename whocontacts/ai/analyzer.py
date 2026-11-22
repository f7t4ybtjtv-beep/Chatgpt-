"""Synthèse IA d'un rapport OSINT.

Si ANTHROPIC_API_KEY est défini et le SDK `anthropic` installé, on demande à
Claude un verdict structuré. Sinon, repli déterministe basé sur les signaux.
Aucune donnée n'est envoyée nulle part sans clé API explicitement configurée.
"""
from __future__ import annotations

import json
import os
from typing import Any

SYSTEM_PROMPT = (
    "Tu es un analyste OSINT défensif. On te fournit les résultats bruts d'une "
    "recherche en sources ouvertes sur un identifiant (e-mail, téléphone, pseudo, "
    "domaine ou IP) qui a contacté l'utilisateur. Ton rôle : aider l'utilisateur à "
    "décider s'il peut faire confiance à ce contact. "
    "Règles : (1) ne jamais inventer de fait absent des données ; (2) distinguer "
    "clairement les faits vérifiés des hypothèses ; (3) ne pas déduire l'identité "
    "civile réelle d'une personne ; (4) rester factuel et prudent ; (5) répondre en "
    "français. Fournis une évaluation du risque et des recommandations concrètes et "
    "proportionnées (ex. vérifier par un autre canal, ne pas cliquer, bloquer)."
)

RESPONSE_SCHEMA_HINT = (
    "Réponds UNIQUEMENT par un objet JSON valide avec ces clés : "
    '{"verdict": str (1 phrase), "likely_nature": str (ex: "personne réelle", '
    '"entreprise", "spam/marketing", "arnaque probable", "indéterminé"), '
    '"confidence": "faible"|"moyenne"|"élevée", "key_findings": [str], '
    '"red_flags": [str], "recommendations": [str]}.'
)


def _default_model() -> str:
    return os.environ.get("WHOCONTACTS_MODEL", "claude-3-5-sonnet-latest")


def analyze_with_ai(report_dict: dict[str, Any]) -> dict[str, Any]:
    """Renvoie {'engine': 'claude'|'rules', 'verdict':..., ...}."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        try:
            return _claude_analysis(report_dict, key)
        except Exception as e:  # repli si l'appel échoue
            out = _rule_based(report_dict)
            out["note"] = f"IA indisponible ({e}); analyse par règles utilisée."
            return out
    return _rule_based(report_dict)


def _claude_analysis(report_dict: dict[str, Any], key: str) -> dict[str, Any]:
    import anthropic  # type: ignore

    client = anthropic.Anthropic(api_key=key)
    payload = json.dumps(report_dict, ensure_ascii=False, indent=2)
    msg = client.messages.create(
        model=_default_model(),
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                f"Voici les résultats OSINT (JSON) :\n```json\n{payload}\n```\n\n"
                f"{RESPONSE_SCHEMA_HINT}"
            ),
        }],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    # Extraction du bloc JSON.
    start, end = text.find("{"), text.rfind("}")
    data = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
    data["engine"] = "claude"
    data["model"] = _default_model()
    return data


def _rule_based(report_dict: dict[str, Any]) -> dict[str, Any]:
    """Synthèse déterministe à partir des signaux et du score."""
    score = report_dict.get("risk_score", 25)
    band = report_dict.get("risk_band", "?")
    signals = report_dict.get("signals", [])
    red = [s["label"] + (f" — {s['detail']}" if s.get("detail") else "")
           for s in signals if s.get("weight", 0) >= 15]
    good = [s["label"] + (f" — {s['detail']}" if s.get("detail") else "")
            for s in signals if s.get("weight", 0) <= -5]
    neutral = [s["label"] for s in signals if -5 < s.get("weight", 0) < 15]

    if score >= 70:
        nature, verdict = "arnaque probable / à risque", (
            "Plusieurs signaux de risque : traitez ce contact avec une grande prudence.")
    elif score >= 45:
        nature, verdict = "indéterminé — prudence", (
            "Signaux mitigés : vérifiez l'identité par un autre canal avant toute action.")
    elif score >= 20:
        nature, verdict = "plutôt légitime", (
            "Peu de signaux de risque, mais aucune confirmation d'identité certaine.")
    else:
        nature, verdict = "éléments rassurants", (
            "Indices cohérents avec un contact légitime ; restez tout de même vigilant.")

    recs = []
    kind = report_dict.get("kind")
    if score >= 45:
        recs.append("Ne cliquez sur aucun lien et ne communiquez aucune donnée personnelle.")
        recs.append("Vérifiez l'identité par un canal indépendant et connu.")
    if kind == "email":
        recs.append("Survolez les liens pour voir l'URL réelle ; méfiez-vous des pièces jointes.")
    if kind == "phone":
        recs.append("En cas de doute, ne rappelez pas de numéro surtaxé ; cherchez le numéro officiel.")
    if kind == "domain":
        recs.append("Comparez le domaine au site officiel attendu (fautes de frappe, sous-domaines).")
    if not recs:
        recs.append("Conservez une vigilance normale ; recoupez si un doute apparaît.")

    return {
        "engine": "rules",
        "verdict": verdict,
        "likely_nature": nature,
        "confidence": "moyenne" if 20 <= score < 70 else ("élevée" if score >= 70 else "faible"),
        "risk_band": band,
        "key_findings": good + neutral,
        "red_flags": red,
        "recommendations": recs,
    }
