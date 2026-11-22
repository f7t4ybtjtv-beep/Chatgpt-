"""Orchestrator: turn one identifier into a full, scored report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import ai, detect, risk
from .collectors.base import Signal
from .collectors.domain_collector import DomainCollector
from .collectors.email_collector import EmailCollector
from .collectors.phone_collector import PhoneCollector
from .collectors.username_collector import UsernameCollector

_COLLECTORS = {
    "email": EmailCollector,
    "phone": PhoneCollector,
    "domain": DomainCollector,
    "url": DomainCollector,
    "username": UsernameCollector,
}


@dataclass
class Report:
    target: str
    kind: str
    signals: List[Signal] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    emoji: str = ""
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "kind": self.kind,
            "score": self.score,
            "verdict": self.verdict,
            "summary": self.summary,
            "signals": [s.to_dict() for s in self.signals],
        }


def identify(
    target: str,
    *,
    online: bool = True,
    timeout: float = 8.0,
    use_ai: bool = True,
    kind: Optional[str] = None,
) -> Report:
    """Analyse *target* and return a :class:`Report`.

    ``kind`` can force the identifier type; otherwise it is auto-detected.
    ``online=False`` restricts every collector to offline analysis.
    ``use_ai=True`` adds a narrative summary (Claude if configured, else rules).
    """
    target = detect.normalize(target)
    kind = kind or detect.detect_kind(target)

    collector_cls = _COLLECTORS.get(kind)
    rep = Report(target=target, kind=kind)
    if collector_cls is None:
        rep.summary = "Type d'identifiant non reconnu. Fournissez un e-mail, un numéro, un domaine ou un pseudo."
        return rep

    collector = collector_cls(online=online, timeout=timeout)
    # Username collector needs a cleaned handle; others accept raw target.
    probe = detect.clean_username(target) if kind == "username" else target
    rep.signals = collector.run(probe)

    rep.score = risk.score(rep.signals)
    rep.verdict, rep.emoji = risk.verdict(rep.score, risk.coverage(rep.signals))
    if use_ai:
        rep.summary = ai.summarize(kind, target, rep.signals)
    else:
        rep.summary = ai.rule_based_summary(kind, target, rep.signals)
    return rep
