"""Mise en forme des résultats : terminal, JSON, markdown."""
from __future__ import annotations

import json
from typing import Any

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YEL = "\033[33m"
_GRN = "\033[32m"
_CYN = "\033[36m"

_BAND_COLOR = {"ÉLEVÉ": _RED, "MOYEN": _YEL, "FAIBLE": _GRN, "TRÈS FAIBLE": _GRN}


def _c(txt: str, color: str, use_color: bool) -> str:
    return f"{color}{txt}{_RESET}" if use_color else txt


def render_terminal(report: dict[str, Any], ai: dict[str, Any], use_color: bool = True) -> str:
    out: list[str] = []
    band = report["risk_band"]
    color = _BAND_COLOR.get(band, "")
    out.append(_c(f"╔══ whocontacts ─ {report['identifier']}", _BOLD, use_color))
    out.append(f"║ Type        : {report['kind']}")
    out.append(f"║ Score risque: " + _c(f"{report['risk_score']}/100  [{band}]", color, use_color))
    out.append("╠══ Faits " + "─" * 30)
    if report["facts"]:
        for k, v in report["facts"].items():
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            if isinstance(v, str) and len(v) > 110:
                v = v[:107] + "..."
            out.append(f"║ {k:<16}: {v}")
    else:
        out.append(_c("║ (aucun)", _DIM, use_color))

    out.append("╠══ Signaux " + "─" * 28)
    for s in report["signals"]:
        w = s["weight"]
        mark = _c("▲", _RED, use_color) if w >= 15 else (
            _c("△", _YEL, use_color) if w > 0 else _c("▽", _GRN, use_color))
        line = f"║ {mark} {s['label']}"
        if s.get("detail"):
            line += _c(f" — {s['detail']}", _DIM, use_color)
        if s.get("source"):
            line += _c(f"  [{s['source']}]", _DIM, use_color)
        out.append(line)

    out.append("╠══ " + _c(f"Analyse IA ({ai.get('engine','?')})", _CYN, use_color) + " " + "─" * 18)
    out.append(_c(f"║ Verdict   : {ai.get('verdict','')}", _BOLD, use_color))
    out.append(f"║ Nature    : {ai.get('likely_nature','?')}")
    out.append(f"║ Confiance : {ai.get('confidence','?')}")
    for rf in ai.get("red_flags", []):
        out.append(_c(f"║   ⚠ {rf}", _RED, use_color))
    if ai.get("recommendations"):
        out.append("║ Recommandations :")
        for rec in ai["recommendations"]:
            out.append(f"║   → {rec}")
    if ai.get("note"):
        out.append(_c(f"║ {ai['note']}", _DIM, use_color))
    if report.get("errors"):
        out.append(_c(f"║ Erreurs: {'; '.join(report['errors'][:5])}", _DIM, use_color))
    out.append("╚" + "═" * 44)
    return "\n".join(out)


def render_json(report: dict[str, Any], ai: dict[str, Any]) -> str:
    return json.dumps({"report": report, "ai": ai}, ensure_ascii=False, indent=2)


def render_markdown(report: dict[str, Any], ai: dict[str, Any]) -> str:
    md = [f"# whocontacts — `{report['identifier']}`", ""]
    md.append(f"- **Type** : {report['kind']}")
    md.append(f"- **Score de risque** : {report['risk_score']}/100 — **{report['risk_band']}**")
    md.append(f"- **Verdict IA** ({ai.get('engine','?')}) : {ai.get('verdict','')}")
    md.append(f"- **Nature probable** : {ai.get('likely_nature','?')} "
              f"(confiance {ai.get('confidence','?')})")
    md.append("")
    if report["facts"]:
        md.append("## Faits")
        for k, v in report["facts"].items():
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            md.append(f"- **{k}** : {v}")
        md.append("")
    if report["signals"]:
        md.append("## Signaux")
        for s in report["signals"]:
            tag = "⚠️" if s["weight"] >= 15 else ("•" if s["weight"] > 0 else "✓")
            d = f" — {s['detail']}" if s.get("detail") else ""
            md.append(f"- {tag} {s['label']}{d}")
        md.append("")
    if ai.get("red_flags"):
        md.append("## Signaux d'alerte")
        for rf in ai["red_flags"]:
            md.append(f"- ⚠️ {rf}")
        md.append("")
    if ai.get("recommendations"):
        md.append("## Recommandations")
        for rec in ai["recommendations"]:
            md.append(f"- {rec}")
        md.append("")
    md.append("---")
    md.append("_Généré par whocontacts (OSINT défensif, sources publiques). "
              "Les résultats sont indicatifs et ne constituent pas une identité certaine._")
    return "\n".join(md)
