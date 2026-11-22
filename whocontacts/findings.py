"""Structures communes de résultat."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Signal:
    """Un fait observé. `weight` oriente le score de risque (-100 sûr .. +100 risqué)."""
    label: str
    detail: str = ""
    weight: int = 0  # négatif = rassurant, positif = suspect
    source: str = ""


@dataclass
class Report:
    identifier: str
    kind: str
    facts: dict[str, Any] = field(default_factory=dict)
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, label: str, detail: str = "", weight: int = 0, source: str = "") -> None:
        self.signals.append(Signal(label, detail, weight, source))

    def fact(self, key: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            self.facts[key] = value

    @property
    def risk_score(self) -> int:
        """Score 0..100 agrégé à partir des signaux (base neutre à 25)."""
        base = 25
        for s in self.signals:
            base += s.weight
        return max(0, min(100, base))

    @property
    def risk_band(self) -> str:
        s = self.risk_score
        if s >= 70:
            return "ÉLEVÉ"
        if s >= 45:
            return "MOYEN"
        if s >= 20:
            return "FAIBLE"
        return "TRÈS FAIBLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "kind": self.kind,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "facts": self.facts,
            "signals": [
                {"label": s.label, "detail": s.detail, "weight": s.weight, "source": s.source}
                for s in self.signals
            ],
            "errors": self.errors,
        }
