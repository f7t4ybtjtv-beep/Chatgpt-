"""Orchestration: take a raw identifier, route it to the right detector(s),
and return a scored, summarised Report.
"""

from __future__ import annotations

from .models import Report
from .utils import detect_kind
from .detectors import email as email_detector
from .detectors import phone as phone_detector
from .detectors import username as username_detector
from .detectors import domain as domain_detector
from .ai import summarize


def identify(
    value: str,
    *,
    kind: str | None = None,
    default_region: str | None = None,
    summarize_report: bool = True,
) -> Report:
    """Identify a single contact identifier.

    Parameters
    ----------
    value:
        The raw identifier someone used to contact you (email, phone, handle,
        domain).
    kind:
        Force a type instead of auto-detecting ("email"|"phone"|"username"|"domain").
    default_region:
        ISO region (e.g. "US", "FR") used when a phone number has no country code.
    summarize_report:
        Run the AI/heuristic summary layer (default True).
    """
    value = (value or "").strip()
    resolved = kind or detect_kind(value)
    report = Report(query=value, kind=resolved)

    if not value:
        report.add_error("empty input")
    elif resolved == "email":
        email_detector.run(value, report)
    elif resolved == "phone":
        phone_detector.run(value, report, default_region=default_region)
    elif resolved == "username":
        username_detector.run(value, report)
    elif resolved == "domain":
        domain_detector.run(value, report)
    else:
        report.add_error(
            f"could not classify '{value}'. Pass kind= to force email/phone/username/domain."
        )

    if summarize_report:
        summarize(report)
    else:
        report.score()
    return report
