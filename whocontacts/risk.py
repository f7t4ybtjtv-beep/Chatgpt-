"""Aggregate signals into a transparent suspicion score and verdict.

The score is a confidence-weighted blend of each signal's ``risk`` hint,
mapped onto 0..100 (0 = rien de suspect, 100 = très suspect). The function is
pure and deterministic, which makes the verdict explainable and testable: the
same signals always yield the same score, and :func:`top_reasons` shows exactly
which signals drove it.
"""

from __future__ import annotations

from typing import List, Tuple

from .collectors.base import Signal

# Minimum total weight of risk-bearing signals needed before we dare give a
# real verdict. Below this the honest answer is "not enough information".
_MIN_COVERAGE = 0.5


def score(signals: List[Signal]) -> int:
    """Return an integer suspicion score in ``[0, 100]`` (50 = neutral)."""
    num = 0.0
    den = 0.0
    for s in signals:
        if s.risk == 0.0:
            continue
        w = s.confidence
        num += s.risk * w
        den += w
    if den == 0:
        return 50  # no evidence either way -> neutral, not "clean"
    mean = num / den  # weighted mean in [-1, 1]
    return int(round((mean + 1.0) / 2.0 * 100))


def coverage(signals: List[Signal]) -> float:
    """Total confidence weight of risk-bearing signals (evidence we actually have)."""
    return sum(s.confidence for s in signals if s.risk != 0.0)


def verdict(sc: int, cov: float | None = None) -> Tuple[str, str]:
    """Map a score (and optional evidence coverage) to (label, emoji)."""
    if cov is not None and cov < _MIN_COVERAGE:
        return ("SIGNAL INSUFFISANT", "🔵")
    if sc >= 70:
        return ("TRÈS SUSPECT", "🔴")
    if sc >= 55:
        return ("SUSPECT", "🟠")
    if sc >= 45:
        return ("INCERTAIN", "🟡")
    if sc >= 30:
        return ("PLUTÔT FIABLE", "🟢")
    return ("FIABLE", "🟢")


def top_reasons(signals: List[Signal], n: int = 5) -> List[Signal]:
    """Return the *n* most decision-relevant signals (by |risk| * confidence)."""
    ranked = [s for s in signals if s.note]
    ranked.sort(key=lambda s: abs(s.risk) * s.confidence, reverse=True)
    return ranked[:n]
