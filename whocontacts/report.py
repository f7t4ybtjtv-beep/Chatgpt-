"""Human-readable rendering of a :class:`whocontacts.identify.Report`."""

from __future__ import annotations

import json

from .identify import Report

_BAR_WIDTH = 24


def _bar(score: int) -> str:
    filled = int(round(score / 100 * _BAR_WIDTH))
    return "█" * filled + "░" * (_BAR_WIDTH - filled)


def render_text(rep: Report, *, color: bool = True) -> str:
    out = []
    out.append("┌" + "─" * 58 + "┐")
    out.append(f"│ WhoContacts — qui vous contacte ? {' ' * 23}│")
    out.append("├" + "─" * 58 + "┤")
    out.append(f"│ Cible   : {rep.target[:46]:<46}│")
    out.append(f"│ Type    : {rep.kind:<46}│")
    out.append(f"│ Score   : {rep.score:>3}/100  [{_bar(rep.score)}] {' ' * 2}│")
    out.append(f"│ Verdict : {rep.emoji} {rep.verdict:<44}│")
    out.append("└" + "─" * 58 + "┘")
    out.append("")
    out.append(rep.summary)
    out.append("")
    out.append("Détail des signaux :")
    if not rep.signals:
        out.append("  (aucun)")
    for s in rep.signals:
        mark = "⚠ " if s.risk > 0.1 else ("✓ " if s.risk < -0.1 else "  ")
        val = s.value
        if isinstance(val, (list, dict)):
            val = json.dumps(val, ensure_ascii=False)
        val = str(val)
        if len(val) > 60:
            val = val[:57] + "..."
        out.append(f"  {mark}[{s.source}/{s.key}] {val}")
        if s.note:
            out.append(f"      ↳ {s.note}")
    out.append("")
    out.append("Rappel : indices issus de sources publiques, à vérifier — pas des preuves. Voir ETHICS.md.")
    return "\n".join(out)


def render_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), ensure_ascii=False, indent=2)
