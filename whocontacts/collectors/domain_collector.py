"""Collect public signals about a domain (or the domain part of a URL/e-mail).

Online checks use only public infrastructure data:
- **RDAP** (the modern, HTTPS replacement for WHOIS) for registration/creation
  date and registrar — proxy-friendly, no port-43 WHOIS needed.
- **DNS A record** via the standard library (``socket``) to confirm the domain
  resolves; MX records if the optional :mod:`dnspython` package is present.

The strongest fraud signal here is **domain age**: scam/phishing domains are
usually days or weeks old. A freshly registered domain contacting you is a red
flag; a years-old one is reassuring context.
"""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

from ..utils import disposable
from ..utils.http import HttpError, get_json
from .base import Collector

_URL_RE = re.compile(r"^https?://([^/]+)", re.IGNORECASE)


def extract_domain(target: str) -> str:
    t = target.strip().lower()
    m = _URL_RE.match(t)
    if m:
        t = m.group(1)
    if "@" in t:
        t = t.rpartition("@")[2]
    t = t.split("/")[0].split(":")[0].strip().rstrip(".")
    return t


class DomainCollector(Collector):
    id = "domain"

    def collect(self, target: str) -> None:
        domain = extract_domain(target)
        if not domain or "." not in domain:
            self.add("invalid", target, note="Domaine non reconnaissable.", risk=0.1)
            return
        self.add("domain", domain, note=f"Domaine analysé : {domain}.")

        if disposable.is_disposable(domain):
            self.add("disposable", True, note="Domaine de messagerie jetable.", risk=0.7, confidence=0.9)

        # Brand homoglyphs: digits/letters swapped to imitate a known brand.
        if re.search(r"(paypa1|g00gle|micr0soft|amaz0n|app1e|faceb00k|netf1ix|y0utube|1nstagram)", domain):
            self.add(
                "lookalike_domain", domain,
                note="Le domaine imite une marque connue (caractères substitués) : forte suspicion d'hameçonnage.",
                risk=0.8, confidence=0.7,
            )
        # Phishing keywords glued with a hyphen (e.g. 'paypal-secure-login.com').
        # Hyphen-only to avoid flagging legitimate subdomains like account.google.com.
        _kw = r"(secure|verify|support|account|login|signin|confirm|update|billing|wallet|recovery)"
        if re.search(rf"(-{_kw}|{_kw}-)", domain):
            self.add(
                "phishing_pattern", domain,
                note="Mots d'hameçonnage accolés par tiret dans le nom de domaine.",
                risk=0.55, confidence=0.6,
            )

        if not self.online:
            self.add("offline_mode", True, note="Mode hors-ligne : DNS et RDAP ignorés.", confidence=0.3)
            return

        self._resolve(domain)
        self._mx(domain)
        self._rdap(domain)

    def _resolve(self, domain: str) -> None:
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = sorted({i[4][0] for i in infos})
            self.add("dns_a", ips, note=f"Le domaine résout vers {len(ips)} adresse(s) IP.", risk=-0.05, confidence=0.6)
        except OSError:
            self.add(
                "dns_a", None,
                note="Le domaine ne résout vers aucune IP : inexistant ou inactif (suspect pour un expéditeur).",
                risk=0.4, confidence=0.6,
            )

    def _mx(self, domain: str) -> None:
        try:
            import dns.resolver  # type: ignore
        except Exception:
            self.add("mx", "skipped", note="Installez « dnspython » pour vérifier les serveurs de mail (MX).", confidence=0.2)
            return
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=self.timeout)
            hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
            self.add("mx", hosts, note=f"{len(hosts)} serveur(s) de mail configuré(s) : le domaine peut émettre des e-mails.", confidence=0.6)
        except Exception:
            self.add("mx", [], note="Aucun serveur de mail (MX) : un e-mail prétendant venir de ce domaine est douteux.", risk=0.3, confidence=0.5)

    def _rdap(self, domain: str) -> None:
        try:
            data = get_json(f"https://rdap.org/domain/{domain}", timeout=self.timeout)
        except HttpError:
            self.add("rdap", "unavailable", note="Données d'enregistrement (RDAP/WHOIS) indisponibles pour ce TLD.", confidence=0.2)
            return

        registrar = None
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles") or []
            if "registrar" in roles:
                registrar = _vcard_name(ent)
                break
        if registrar:
            self.add("registrar", registrar, note=f"Bureau d'enregistrement : {registrar}.", confidence=0.6)

        created = _event_date(data, "registration")
        if created:
            age_days = (datetime.now(timezone.utc) - created).days
            self.add("created", created.date().isoformat(), note=f"Domaine enregistré le {created.date().isoformat()}.", confidence=0.8)
            if age_days < 30:
                self.add("age_days", age_days, note=f"Domaine très récent ({age_days} j) : signal fort d'arnaque/hameçonnage.", risk=0.8, confidence=0.85)
            elif age_days < 180:
                self.add("age_days", age_days, note=f"Domaine récent ({age_days} j) : prudence.", risk=0.4, confidence=0.7)
            elif age_days < 365:
                self.add("age_days", age_days, note=f"Domaine de moins d'un an ({age_days} j).", risk=0.15, confidence=0.6)
            else:
                years = age_days // 365
                self.add("age_days", age_days, note=f"Domaine ancien (~{years} an(s)) : plutôt rassurant.", risk=-0.4, confidence=0.75)
        else:
            self.add("created", None, note="Date de création inconnue (RDAP partiel).", confidence=0.2)


def _vcard_name(entity: dict):
    try:
        vcard = entity.get("vcardArray", [None, []])[1]
        for item in vcard:
            if item and item[0] == "fn":
                return item[3]
    except Exception:
        pass
    return entity.get("handle")


def _event_date(data: dict, action: str):
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == action:
            raw = ev.get("eventDate")
            if raw:
                try:
                    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
                except ValueError:
                    try:
                        return datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    except ValueError:
                        return None
    return None
