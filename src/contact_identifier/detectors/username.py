"""Username detector.

Checks whether a handle exists as a *public* profile on a set of common
platforms by requesting the public profile URL (like a lightweight, respectful
version of tools such as Sherlock/Maigret). Network is opt-in; with network
off it only reports the candidate profile URLs so a human can check manually.

Only public, unauthenticated pages are fetched. Nothing is scraped from behind
a login, and results are presence/absence only — not profile contents.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from ..models import Report, Signal, Risk
from ..utils import http_get, network_allowed

_DATA_DIR = Path(os.environ.get("CONTACT_ID_DATA_DIR", Path(__file__).resolve().parents[3] / "data"))


@lru_cache(maxsize=1)
def _platforms() -> list[dict]:
    try:
        raw = json.loads((_DATA_DIR / "platforms.json").read_text(encoding="utf-8"))
        return raw.get("platforms", [])
    except (OSError, json.JSONDecodeError):
        return []


def run(username: str, report: Report, *, max_checks: int | None = None) -> None:
    handle = username.strip().lstrip("@")
    platforms = _platforms()
    if max_checks:
        platforms = platforms[:max_checks]

    if not network_allowed():
        urls = [p["url"].replace("{u}", handle) for p in platforms]
        report.add(Signal("username", "Candidate profile URLs", urls, Risk.INFO,
                           "Network checks disabled. Open these to verify the handle manually "
                           "(set CONTACT_ID_ALLOW_NETWORK=1 to auto-check)."))
        return

    found: list[str] = []
    for p in platforms:
        url = p["url"].replace("{u}", handle)
        resp = http_get(url)
        if resp is None:
            continue
        if resp.status_code == 200:
            body = (resp.text or "")[:20000]
            absent = any(marker.lower() in body.lower() for marker in p.get("absence", []))
            if not absent:
                found.append(p["name"])
                report.add(Signal("username", f"Profile found: {p['name']}", url, Risk.INFO,
                                   f"A public {p['name']} profile responds for this handle.",
                                   source=p["name"]))

    if found:
        risk = Risk.LOW if len(found) >= 3 else Risk.INFO
        report.add(Signal("username", "Handle reuse", found, risk,
                           f"Same handle appears on {len(found)} platform(s): {', '.join(found)}. "
                           "Reused handles help corroborate identity but can also be impersonation."))
    else:
        report.add(Signal("username", "No public profiles matched", handle, Risk.INFO,
                           "None of the checked platforms returned a public profile for this handle."))
