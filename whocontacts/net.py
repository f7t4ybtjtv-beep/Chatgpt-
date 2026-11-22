"""Helpers réseau — tout passe par HTTPS (DoH, RDAP, APIs publiques).

Aucune dépendance externe : urllib stdlib uniquement. Respecte un User-Agent
générique et des timeouts courts. Honore les variables d'environnement proxy
(HTTPS_PROXY) automatiquement via urllib.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

USER_AGENT = "whocontacts-osint/0.1 (+https://github.com/; defensive-use)"
DEFAULT_TIMEOUT = 12


class HttpResult:
    __slots__ = ("status", "body", "error", "url")

    def __init__(self, status: int = 0, body: bytes = b"", error: str = "", url: str = ""):
        self.status = status
        self.body = body
        self.error = error
        self.url = url

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Optional[Any]:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return None


def http_get(
    url: str,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 1,
) -> HttpResult:
    """GET robuste. Renvoie un HttpResult, ne lève jamais d'exception."""
    hdr = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdr.update(headers)
    last_err = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdr, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return HttpResult(resp.status, resp.read(), "", url)
        except urllib.error.HTTPError as e:
            # Un code HTTP (403, 404, 429...) est une réponse valide à interpréter.
            body = b""
            try:
                body = e.read()
            except Exception:
                pass
            return HttpResult(e.code, body, "", url)
        except urllib.error.URLError as e:
            last_err = str(getattr(e, "reason", e))
        except Exception as e:  # pragma: no cover - garde-fou
            last_err = str(e)
        if attempt < retries:
            time.sleep(0.6 * (attempt + 1))
    return HttpResult(0, b"", last_err, url)


# --- DNS over HTTPS -----------------------------------------------------------

_DOH_ENDPOINTS = [
    "https://dns.google/resolve?name={name}&type={rtype}",
    "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
]

_RTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "PTR": 12}


def doh_query(name: str, rtype: str = "A"):
    """Résolution DNS via DNS-over-HTTPS.

    Renvoie une liste de réponses (éventuellement vide = résolu mais aucun
    enregistrement), ou None si aucun résolveur n'a pu être joint (échec réseau),
    afin de ne pas confondre « pas de MX » et « DNS injoignable ».
    """
    name = name.strip(".")
    reached = False
    for tmpl in _DOH_ENDPOINTS:
        url = tmpl.format(name=urllib.parse.quote(name), rtype=rtype)
        res = http_get(url, headers={"Accept": "application/dns-json"})
        data = res.json()
        if not res.ok or not isinstance(data, dict):
            continue  # endpoint injoignable, on tente le suivant
        reached = True
        answers = data.get("Answer") or []
        want = _RTYPE.get(rtype)
        out = []
        for a in answers:
            if want is None or a.get("type") == want:
                val = (a.get("data") or "").strip()
                if val:
                    out.append(val.rstrip("."))
        # Réponse (même NXDOMAIN) obtenue : résultat fiable.
        return out
    return None if not reached else []
