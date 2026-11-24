"""Check whether a username exists on a curated set of **public** platforms.

This is a small, respectful version of the well-known "username enumeration"
technique: for each site we request the *public* profile URL and infer presence
from the HTTP status (and, for a few sites, an "absent" marker string). We only
report that a public profile *exists* and link to it — we never log in, scrape
private content, or follow the person around.

The site list is deliberately short (fast, low load). Extend ``SITES`` for more
coverage. A match tells you the handle is used publicly somewhere; it does not,
by itself, prove the two accounts are the same human.
"""

from __future__ import annotations

import time

from ..utils.http import HttpError, get
from .base import Collector

# name -> (url_template, absent_marker_or_None). status 200 + no marker = found.
SITES = {
    "GitHub": ("https://github.com/{u}", None),
    "GitLab": ("https://gitlab.com/{u}", None),
    "Reddit": ("https://www.reddit.com/user/{u}/about.json", None),
    "Instagram": ("https://www.instagram.com/{u}/", None),
    "X (Twitter)": ("https://nitter.net/{u}", None),
    "TikTok": ("https://www.tiktok.com/@{u}", None),
    "Telegram": ("https://t.me/{u}", "tgme_page_title"),
    "Pinterest": ("https://www.pinterest.com/{u}/", None),
    "Twitch": ("https://m.twitch.tv/{u}", None),
    "Keybase": ("https://keybase.io/{u}", None),
    "Steam": ("https://steamcommunity.com/id/{u}", None),
    "Medium": ("https://medium.com/@{u}", None),
    "Dev.to": ("https://dev.to/{u}", None),
    "Replit": ("https://replit.com/@{u}", None),
    "SoundCloud": ("https://soundcloud.com/{u}", None),
}


class UsernameCollector(Collector):
    id = "username"

    #: polite pause between requests (seconds)
    delay: float = 0.4

    def collect(self, target: str) -> None:
        user = target.strip().lstrip("@")
        self.add("username", user, note=f"Pseudo analysé : @{user}.")
        if not user or len(user) > 64:
            self.add("invalid", user, note="Pseudo invalide.", risk=0.1)
            return

        if not self.online:
            self.add("offline_mode", True, note="Mode hors-ligne : recherche de profils publics ignorée.", confidence=0.3)
            return

        found, checked = [], 0
        for name, (tmpl, marker) in SITES.items():
            url = tmpl.format(u=user)
            checked += 1
            try:
                resp = get(url, timeout=self.timeout, allow_redirects=True)
            except HttpError:
                continue
            finally:
                time.sleep(self.delay)

            present = resp.status == 200 and (marker is None or marker in resp.text)
            # Reddit returns JSON; an empty/suspended user still gives 200 with error payload.
            if name == "Reddit" and present and '"error"' in resp.text:
                present = False
            if present:
                found.append({"site": name, "url": tmpl.format(u=user).replace("/about.json", "")})

        self.add("checked_sites", checked, note=f"{checked} plateformes publiques testées.", confidence=0.5)
        if found:
            self.add(
                "profiles", found,
                note=f"Profil(s) public(s) trouvé(s) sur : {', '.join(f['site'] for f in found)}. "
                     "Comparez-les à la personne qui vous écrit pour vérifier la cohérence.",
                risk=-0.1, confidence=0.5,
            )
        else:
            self.add(
                "profiles", [],
                note="Aucun profil public trouvé sur les plateformes testées : pseudo rare, privé, ou tout récent.",
                risk=0.1, confidence=0.3,
            )
