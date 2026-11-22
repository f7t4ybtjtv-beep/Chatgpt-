"""The "AI" layer: turn a pile of signals into a plain-language verdict.

Two backends:

  * heuristic (default, offline, deterministic) — rule-based narrative. Always
    available, no API key, no network.
  * llm (opt-in) — sends ONLY the anonymised signal list (never the operator's
    own data) to an LLM for a richer, natural-language write-up. Supports
    Anthropic and OpenAI, selected by available API key.

The backend is chosen automatically: if an LLM key is present AND
CONTACT_ID_USE_LLM=1, the LLM is used; otherwise the heuristic runs.
"""

from __future__ import annotations

import os

from ..models import Report, Risk

_ADVICE = {
    Risk.HIGH: "Treat this contact as untrusted. Do not share personal or financial "
               "information, click links, or act on urgency. Verify through an "
               "independent, official channel before engaging.",
    Risk.MEDIUM: "Proceed carefully. Independently verify the sender's identity before "
                 "sharing anything sensitive or taking requested actions.",
    Risk.LOW: "Nothing strongly alarming, but stay alert — absence of red flags is not "
              "proof of identity.",
    Risk.INFO: "No notable risk signals surfaced from the available data.",
}


def summarize(report: Report) -> str:
    """Populate report.summary and return it."""
    report.score()
    use_llm = os.environ.get("CONTACT_ID_USE_LLM", "").strip() in {"1", "true", "yes"}
    if use_llm:
        text = _llm_summary(report)
        if text:
            report.summary = text
            return text
    report.summary = _heuristic_summary(report)
    return report.summary


# --------------------------------------------------------------------------- #
# Heuristic backend
# --------------------------------------------------------------------------- #
def _heuristic_summary(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"Identifier: {report.query}  (type: {report.kind})")
    lines.append(f"Overall risk: {report.risk.value.upper()}")
    lines.append("")

    notable = [s for s in report.signals if s.risk.weight >= Risk.MEDIUM.weight]
    context = [s for s in report.signals if s.risk.weight < Risk.MEDIUM.weight]

    if notable:
        lines.append("Flags worth attention:")
        for s in notable:
            lines.append(f"  [!] {s.label}: {s.detail}")
        lines.append("")
    if context:
        lines.append("Context:")
        for s in context:
            val = s.value if not isinstance(s.value, (list, dict)) else ""
            tail = f" ({val})" if val else ""
            lines.append(f"  - {s.label}{tail}")
        lines.append("")

    if report.errors:
        lines.append("Could not check:")
        for e in report.errors:
            lines.append(f"  - {e}")
        lines.append("")

    lines.append("What to do: " + _ADVICE[report.risk])
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# LLM backend (opt-in)
# --------------------------------------------------------------------------- #
def _signal_payload(report: Report) -> str:
    rows = [f"- [{s.risk.value}] {s.label}: {s.detail}" for s in report.signals]
    return (
        f"Identifier type: {report.kind}\n"
        f"Computed risk: {report.risk.value}\n"
        "Signals:\n" + "\n".join(rows)
    )


_SYSTEM = (
    "You are a cautious OSINT analyst helping someone decide whether an unknown "
    "person who contacted them is trustworthy. You are given only automated "
    "signals about an identifier (email/phone/username/domain). Write a short, "
    "calm assessment for a non-technical person: what the signals suggest, what "
    "is uncertain, and concrete safety advice. Never fabricate facts beyond the "
    "signals. Never claim certainty about a real person's identity."
)


def _llm_summary(report: Report) -> str | None:
    payload = _signal_payload(report)

    # Prefer Anthropic if its key is set.
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # type: ignore
            client = anthropic.Anthropic()
            model = os.environ.get("CONTACT_ID_LLM_MODEL", "claude-opus-4-8")
            msg = client.messages.create(
                model=model,
                max_tokens=500,
                system=_SYSTEM,
                messages=[{"role": "user", "content": payload}],
            )
            return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
        except Exception:
            return None

    if os.environ.get("OPENAI_API_KEY"):
        try:
            from openai import OpenAI  # type: ignore
            client = OpenAI()
            model = os.environ.get("CONTACT_ID_LLM_MODEL", "gpt-4o-mini")
            resp = client.chat.completions.create(
                model=model,
                max_tokens=500,
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": payload},
                ],
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception:
            return None

    return None
