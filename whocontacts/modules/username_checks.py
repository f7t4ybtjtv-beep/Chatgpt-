"""Recherche de présence d'un pseudo sur des plateformes publiques.

Vérifie le statut HTTP d'une page de profil. 200 => présent, 404 => absent.
Les vérifications s'exécutent en parallèle (threads) pour la rapidité.
Usage défensif : identifier les profils publics d'un contact entrant, pas
surveiller un particulier. Voir ETHICS.md.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..data import USERNAME_SITES
from ..findings import Report
from ..net import http_get


def _check(site: str, url_tmpl: str, username: str):
    url = url_tmpl.format(u=username)
    res = http_get(url, headers={"Accept": "text/html"}, timeout=10)
    if res.status == 200:
        # Certains sites renvoient 200 avec une page "non trouvé" : heuristique légère.
        body = res.body[:4000].decode("utf-8", "replace").lower()
        negatives = ("page not found", "profile not found", "n'existe pas",
                     "sorry, this page", "user not found", "couldn't find this account")
        if any(n in body for n in negatives):
            return site, "absent", url
        return site, "présent", url
    if res.status in (301, 302, 303, 307, 308):
        return site, "redirigé", url
    if res.status == 404:
        return site, "absent", url
    if res.status == 429:
        return site, "limité (réessayer)", url
    if res.status == 0:
        return site, f"erreur ({res.error[:40]})", url
    return site, f"indéterminé ({res.status})", url


def analyze(username: str, max_workers: int = 8) -> Report:
    r = Report(identifier=username, kind="username")
    r.fact("username", username)
    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_check, s, u, username): s for s, u in USERNAME_SITES.items()}
        for fut in as_completed(futs):
            try:
                site, status, url = fut.result()
            except Exception as e:  # pragma: no cover
                r.errors.append(f"{futs[fut]}: {e}")
                continue
            if status == "présent":
                found.append({"site": site, "url": url})
    found.sort(key=lambda x: x["site"].lower())
    r.fact("profiles_found", found)
    r.fact("profiles_count", len(found))
    if found:
        r.add(f"{len(found)} profil(s) public(s) trouvé(s)",
              ", ".join(p["site"] for p in found), weight=-5, source="username")
    else:
        r.add("Aucun profil public trouvé sur les sites testés",
              "pseudo rare, privé, ou inexistant", weight=5, source="username")
    return r
