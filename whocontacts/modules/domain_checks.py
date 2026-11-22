"""Analyse d'un domaine (RDAP + DNS-over-HTTPS).

- RDAP : registrar, dates de création/expiration, âge, statuts
- DNS : A, NS, MX, TXT
- Heuristique : un domaine très récent est un signal de risque (arnaque/phishing).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..findings import Report
from ..net import doh_query, http_get


def _parse_date(s: str):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _rdap(domain: str):
    # rdap.org redirige vers le bon serveur RDAP du TLD.
    for base in ("https://rdap.org/domain/", "https://rdap.verisign.com/com/v1/domain/"):
        res = http_get(base + domain)
        if res.ok:
            data = res.json()
            if data:
                return data
    return None


def analyze(domain: str) -> Report:
    r = Report(identifier=domain, kind="domain")
    r.fact("domain", domain)

    # DNS.
    try:
        a = doh_query(domain, "A")
        if a is None:
            r.errors.append("DNS: résolveur injoignable (vérifications DNS ignorées)")
        else:
            r.fact("a_records", a)
            if not a:
                r.add("Aucune IP (enregistrement A) résolue", "domaine inactif ou inexistant",
                      weight=15, source="DoH")
            ns = doh_query(domain, "NS") or []
            r.fact("nameservers", ns)
            mx = doh_query(domain, "MX") or []
            if mx:
                r.fact("mx_records", sorted({m.split()[-1] for m in mx if m}))
            txt = doh_query(domain, "TXT") or []
            if txt:
                r.fact("txt_records", txt[:8])
                if any("v=spf1" in t.lower() for t in txt):
                    r.add("SPF configuré", "domaine qui envoie des mails légitimement",
                          weight=-5, source="DoH")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"DNS: {e}")

    # RDAP (WHOIS moderne).
    try:
        data = _rdap(domain)
        if data:
            # Registrar.
            for ent in data.get("entities", []) or []:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray")
                    name = None
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                name = item[3]
                    r.fact("registrar", name or ent.get("handle"))
            # Dates.
            created = expires = None
            for ev in data.get("events", []) or []:
                action = ev.get("eventAction")
                if action == "registration":
                    created = ev.get("eventDate")
                elif action == "expiration":
                    expires = ev.get("eventDate")
            if created:
                r.fact("created", created)
                dt = _parse_date(created)
                if dt:
                    age_days = (datetime.now(timezone.utc) - dt).days
                    r.fact("age_days", age_days)
                    if age_days < 30:
                        r.add("Domaine créé il y a moins de 30 jours",
                              f"{age_days} jours — signal de risque élevé (phishing/arnaque)",
                              weight=35, source="RDAP")
                    elif age_days < 180:
                        r.add("Domaine récent (< 6 mois)", f"{age_days} jours", weight=15, source="RDAP")
                    elif age_days > 365 * 3:
                        r.add("Domaine établi (> 3 ans)", f"{age_days} jours", weight=-10, source="RDAP")
            if expires:
                r.fact("expires", expires)
            statuses = data.get("status", [])
            if statuses:
                r.fact("status", statuses)
        else:
            r.add("Aucune donnée RDAP/WHOIS", "TLD sans RDAP public ou domaine libre",
                  weight=5, source="RDAP")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"RDAP: {e}")

    return r
