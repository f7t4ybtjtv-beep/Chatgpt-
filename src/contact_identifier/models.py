"""Data models shared across the toolkit.

A *Signal* is one atomic piece of evidence a detector found about an
identifier (an email, phone number, username, domain...). A *Report* bundles
the signals for a single query plus an overall risk assessment.

Everything here is a plain dataclass so it serialises cleanly to JSON and is
easy to test without any network access.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Risk(str, Enum):
    """Qualitative risk level for a signal or a whole report."""

    INFO = "info"          # neutral, purely descriptive
    LOW = "low"            # mildly reassuring / minor concern
    MEDIUM = "medium"      # worth a second look
    HIGH = "high"          # strong indicator something is off

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 4}[self.value]


@dataclass
class Signal:
    """One observation about an identifier."""

    detector: str                 # which detector produced it, e.g. "email"
    label: str                    # short human label, e.g. "Disposable domain"
    value: Any = None             # the raw observed value
    risk: Risk = Risk.INFO
    detail: str = ""              # one-line explanation for a human
    source: str = "local"         # "local" (offline) or a network source name

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d


@dataclass
class Report:
    """The full result of identifying one contact."""

    query: str
    kind: str                                   # email | phone | username | domain | unknown
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: str = ""                           # filled in by the AI/heuristic layer
    risk: Risk = Risk.INFO                       # overall

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def score(self) -> Risk:
        """Derive an overall risk from the collected signals.

        Heuristic: take the highest individual risk, but bump a cluster of
        medium signals up to high.
        """
        if not self.signals:
            self.risk = Risk.INFO
            return self.risk

        highest = max(self.signals, key=lambda s: s.risk.weight).risk
        medium_plus = sum(1 for s in self.signals if s.risk.weight >= Risk.MEDIUM.weight)
        if highest == Risk.MEDIUM and medium_plus >= 2:
            highest = Risk.HIGH
        self.risk = highest
        return self.risk

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "kind": self.kind,
            "created_at": self.created_at,
            "risk": self.risk.value,
            "summary": self.summary,
            "signals": [s.to_dict() for s in self.signals],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
