"""Collect public signals about an e-mail address.

Offline:  syntax validity, disposable-domain check, role-account detection,
          plus-addressing, look-alike/obfuscation heuristics.
Online:   MX presence for the domain (deliverability), Gravatar presence
          (public avatar => the address is used by a real person), and an
          *optional* breach check if ``HIBP_API_KEY`` is set.

No private data is accessed. The Gravatar check hashes the address locally and
requests only the public avatar endpoint.
"""

from __future__ import annotations

import hashlib
import os
import re

from ..utils import disposable
from ..utils.http import HttpError, get
from .base import Collector

_ROLE_LOCALPARTS = {
    "admin", "administrator", "support", "contact", "info", "sales", "billing",
    "help", "service", "noreply", "no-reply", "donotreply", "postmaster",
    "webmaster", "abuse", "security", "team", "hello", "office", "mail",
}

# Big, reputable consumer mailbox providers (reassuring *context*, not proof).
_MAJOR_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.fr", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "orange.fr", "free.fr", "sfr.fr", "laposte.net", "wanadoo.fr", "gmx.com",
    "gmx.net", "aol.com", "zoho.com", "mail.com", "yandex.com",
}


class EmailCollector(Collector):
    id = "email"

    def collect(self, target: str) -> None:
        email = target.strip().lower()
        if "@" not in email:
            self.add("invalid", email, note="Ce n'est pas une adresse e-mail valide.", risk=0.1)
            return
        local, _, domain = email.rpartition("@")
        self.add("address", email, note="Adresse analysée.")
        self.add("domain", domain, note=f"Domaine de messagerie : {domain}.")

        # --- Offline heuristics -------------------------------------------
        if disposable.is_disposable(domain):
            self.add(
                "disposable_domain", True,
                note="Adresse jetable/temporaire : souvent utilisée pour rester anonyme.",
                risk=0.75, confidence=0.9,
            )
        elif domain in _MAJOR_PROVIDERS:
            self.add(
                "major_provider", domain,
                note="Fournisseur grand public connu (neutre : n'importe qui peut en créer une).",
                risk=-0.1, confidence=0.5,
            )

        if local in _ROLE_LOCALPARTS or local.split("+")[0] in _ROLE_LOCALPARTS:
            self.add(
                "role_account", local,
                note="Adresse « de rôle » (support@, contact@…) : probablement une organisation, pas une personne.",
                risk=-0.05, confidence=0.6,
            )

        if "+" in local:
            self.add(
                "plus_addressing", local,
                note="Sous-adressage « + » : l'expéditeur segmente/filtre ses contacts (neutre).",
                risk=0.0, confidence=0.4,
            )

        # Obfuscation: many digits or long random-looking localpart.
        digit_ratio = sum(c.isdigit() for c in local) / max(1, len(local))
        if len(local) >= 12 and digit_ratio >= 0.4:
            self.add(
                "random_localpart", local,
                note="Partie locale longue et très numérique : typique d'adresses créées en masse.",
                risk=0.35, confidence=0.5,
            )

        # Homoglyph / brand look-alike hint on the domain.
        if re.search(r"(paypa1|g00gle|micr0soft|amaz0n|app1e|secure-|-verify|account-)", domain):
            self.add(
                "lookalike_domain", domain,
                note="Le domaine imite une marque connue ou utilise des mots d'hameçonnage : forte suspicion.",
                risk=0.8, confidence=0.7,
            )

        # --- Online checks -------------------------------------------------
        if not self.online:
            self.add("offline_mode", True, note="Mode hors-ligne : vérifications réseau ignorées.", confidence=0.3)
            return

        self._check_gravatar(email)
        self._check_hibp(email)

    def _check_gravatar(self, email: str) -> None:
        digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
        md5 = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324 - Gravatar requires md5
        try:
            resp = get(f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=self.timeout)
        except HttpError:
            return
        if resp.status == 200:
            self.add(
                "gravatar", f"https://www.gravatar.com/avatar/{md5}",
                note="Avatar Gravatar public trouvé : l'adresse appartient à une personne réelle et active.",
                risk=-0.3, confidence=0.7,
            )
        self.add("fingerprint_sha256", digest[:16], note="Empreinte (non réversible) pour corrélation locale.", confidence=0.2)

    def _check_hibp(self, email: str) -> None:
        api_key = os.environ.get("HIBP_API_KEY")
        if not api_key:
            self.add(
                "breach_check", "skipped",
                note="Vérification de fuites (Have I Been Pwned) non effectuée : définissez HIBP_API_KEY pour l'activer.",
                confidence=0.2,
            )
            return
        try:
            resp = get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true",
                headers={"hibp-api-key": api_key},
                timeout=self.timeout,
            )
        except HttpError:
            return
        if resp.status == 404:
            self.add("breaches", 0, note="Aucune fuite connue pour cette adresse (elle existe mais n'a pas fuité).", risk=0.0, confidence=0.5)
        elif resp.status == 200:
            try:
                breaches = resp.json()
                n = len(breaches)
            except Exception:
                n = 1
            self.add(
                "breaches", n,
                note=f"Présente dans {n} fuite(s) connue(s) : l'adresse est réelle et ancienne (plutôt rassurant sur son existence).",
                risk=-0.15, confidence=0.6,
            )
