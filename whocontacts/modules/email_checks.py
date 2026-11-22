"""Analyse OSINT d'une adresse e-mail (sources publiques).

- Validité syntaxique et domaine
- Enregistrements MX (le domaine peut-il recevoir des mails ?)
- Fournisseur gratuit / jetable / domaine privé
- Présence Gravatar (compte lié à cette adresse)
- Exposition dans des fuites via HaveIBeenPwned (si clé API fournie)
"""
from __future__ import annotations

import hashlib
import os

from ..data import DISPOSABLE_EMAIL_DOMAINS, FREE_EMAIL_PROVIDERS
from ..findings import Report
from ..net import doh_query, http_get


def _gravatar_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def analyze(email: str) -> Report:
    r = Report(identifier=email, kind="email")
    local, _, domain = email.partition("@")
    domain = domain.lower()
    r.fact("local_part", local)
    r.fact("domain", domain)

    # Indice : pseudo réutilisable ailleurs.
    if local and all(c.isalnum() or c in "._-" for c in local):
        r.fact("username_guess", local)

    # Classement du domaine.
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        r.add("E-mail jetable / temporaire", domain, weight=40, source="liste locale")
    elif domain in FREE_EMAIL_PROVIDERS:
        r.add("Fournisseur gratuit grand public", domain, weight=5, source="liste locale")
    else:
        r.add("Domaine privé / professionnel", domain, weight=-5, source="liste locale")
        r.fact("domain_type", "privé/pro")

    # MX : le domaine peut-il recevoir des e-mails ?
    try:
        mx = doh_query(domain, "MX")
        if mx is None:
            r.errors.append("MX: résolveur DNS injoignable (vérification ignorée)")
        elif mx:
            hosts = sorted({m.split()[-1] for m in mx if m})
            r.fact("mx_records", hosts)
            r.add("Domaine configuré pour l'e-mail (MX présents)", ", ".join(hosts[:3]),
                  weight=-5, source="DoH")
            low = " ".join(hosts).lower()
            for prov, name in (("google", "Google Workspace"), ("outlook", "Microsoft 365"),
                               ("protonmail", "Proton"), ("zoho", "Zoho"),
                               ("ovh", "OVH"), ("gandi", "Gandi")):
                if prov in low:
                    r.fact("mail_host", name)
                    break
        else:
            r.add("Aucun MX : le domaine ne reçoit pas d'e-mail", domain,
                  weight=20, source="DoH")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"MX: {e}")

    # Gravatar : révèle un compte public lié à l'e-mail.
    try:
        h = _gravatar_hash(email)
        res = http_get(f"https://www.gravatar.com/avatar/{h}?d=404")
        if res.ok:
            r.fact("gravatar", f"https://www.gravatar.com/avatar/{h}")
            prof = http_get(f"https://www.gravatar.com/{h}.json")
            data = prof.json() if prof.ok else None
            if data and data.get("entry"):
                e0 = data["entry"][0]
                r.fact("gravatar_profile", e0.get("profileUrl"))
                if e0.get("displayName"):
                    r.fact("display_name", e0.get("displayName"))
                accounts = [a.get("url") for a in e0.get("accounts", []) if a.get("url")]
                if accounts:
                    r.fact("linked_accounts", accounts)
            r.add("Profil Gravatar public trouvé", "compte réel associé à l'adresse",
                  weight=-10, source="Gravatar")
        elif res.status == 404:
            r.add("Pas de Gravatar", "", weight=0, source="Gravatar")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"Gravatar: {e}")

    # HaveIBeenPwned (optionnel, clé requise).
    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        try:
            res = http_get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                headers={"hibp-api-key": hibp_key},
            )
            if res.ok:
                breaches = res.json() or []
                names = [b.get("Name") for b in breaches if b.get("Name")]
                r.fact("breaches", names)
                r.add("Adresse présente dans des fuites de données",
                      f"{len(names)} fuite(s): {', '.join(names[:5])}",
                      weight=-5, source="HIBP")
            elif res.status == 404:
                r.add("Aucune fuite connue (HIBP)", "", weight=0, source="HIBP")
        except Exception as e:  # pragma: no cover
            r.errors.append(f"HIBP: {e}")

    return r
