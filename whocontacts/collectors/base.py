"""Base types shared by every collector.

A **Signal** is one atomic, sourced observation about an identifier. Collectors
never decide "guilty or not" — they emit neutral, explainable signals with a
``risk`` hint in ``[-1, +1]`` (negative = reassuring, positive = suspicious).
The :mod:`whocontacts.risk` module aggregates them into a score, and the
optional AI layer turns them into prose. This separation keeps the tool
auditable: every conclusion traces back to concrete signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class Signal:
    """One sourced, explainable observation."""

    source: str              # collector id, e.g. "email"
    key: str                 # machine key, e.g. "disposable_domain"
    value: Any               # the observed value
    note: str = ""           # short human-readable explanation (French)
    risk: float = 0.0        # -1.0 reassuring .. 0 neutral .. +1.0 suspicious
    confidence: float = 0.6  # 0..1 how much to trust this signal

    def __post_init__(self) -> None:
        self.risk = max(-1.0, min(1.0, float(self.risk)))
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "key": self.key,
            "value": self.value,
            "note": self.note,
            "risk": round(self.risk, 3),
            "confidence": round(self.confidence, 3),
        }


@dataclass
class Collector:
    """Base class. Subclasses implement :meth:`collect`.

    ``online`` controls whether the collector is allowed to touch the network.
    When False, collectors must restrict themselves to offline analysis so the
    whole tool can run air-gapped.
    """

    online: bool = True
    timeout: float = 8.0
    _signals: List[Signal] = field(default_factory=list, init=False, repr=False)

    # NOTE: deliberately NOT a dataclass field (no annotation), so subclasses can
    # override it as a plain class attribute without the generated __init__
    # resetting it to the base default on every instance.
    id = "base"

    def add(self, key: str, value: Any, note: str = "", risk: float = 0.0, confidence: float = 0.6) -> None:
        self._signals.append(
            Signal(source=self.id, key=key, value=value, note=note, risk=risk, confidence=confidence)
        )

    def collect(self, target: str) -> List[Signal]:  # pragma: no cover - interface
        raise NotImplementedError

    def run(self, target: str) -> List[Signal]:
        """Run :meth:`collect`, never raising: failures become a soft signal."""
        self._signals = []
        try:
            self.collect(target)
        except Exception as exc:  # defensive: a broken collector must not crash the run
            self.add(
                "collector_error",
                str(exc),
                note=f"Le collecteur « {self.id} » a échoué (ignoré).",
                risk=0.0,
                confidence=0.2,
            )
        return list(self._signals)
