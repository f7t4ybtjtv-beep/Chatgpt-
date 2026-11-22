"""Analyse d'une adresse IP (RDAP réseau + reverse DNS)."""
from __future__ import annotations

import ipaddress

from ..findings import Report
from ..net import doh_query, http_get


def _ptr_name(ip: str) -> str:
    obj = ipaddress.ip_address(ip)
    if obj.version == 4:
        return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    # IPv6 : nibbles inversés.
    full = obj.exploded.replace(":", "")
    return ".".join(reversed(full)) + ".ip6.arpa"


def analyze(ip: str) -> Report:
    r = Report(identifier=ip, kind="ip")
    obj = ipaddress.ip_address(ip)
    r.fact("version", f"IPv{obj.version}")

    if obj.is_private:
        r.add("IP privée (réseau local)", "non routable sur Internet", weight=0, source="local")
        r.fact("scope", "privée")
        return r
    if obj.is_loopback or obj.is_reserved or obj.is_multicast:
        r.add("IP spéciale (loopback/réservée/multicast)", "", weight=0, source="local")
        return r

    # Reverse DNS.
    try:
        ptr = doh_query(_ptr_name(ip), "PTR")
        if ptr:
            r.fact("reverse_dns", ptr)
            host = ptr[0].lower()
            hints = {
                "amazonaws": "Amazon AWS", "googleusercontent": "Google Cloud",
                "azure": "Microsoft Azure", "ovh": "OVH", "digitalocean": "DigitalOcean",
                "hetzner": "Hetzner", "scaleway": "Scaleway", "linode": "Linode",
                "vpn": "VPN possible", "tor": "Nœud Tor possible", "proxy": "Proxy possible",
            }
            for frag, label in hints.items():
                if frag in host:
                    r.add(f"Hébergement/relais détecté : {label}", host, weight=10, source="PTR")
                    break
    except Exception as e:  # pragma: no cover
        r.errors.append(f"PTR: {e}")

    # RDAP IP.
    try:
        res = http_get("https://rdap.org/ip/" + ip)
        data = res.json() if res.ok else None
        if data:
            r.fact("network_name", data.get("name"))
            r.fact("network_range", f"{data.get('startAddress')} - {data.get('endAddress')}")
            r.fact("country", data.get("country"))
            for ent in data.get("entities", []) or []:
                vcard = ent.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            r.fact("org", item[3])
                            break
                if "abuse" in ent.get("roles", []):
                    r.fact("abuse_contact", ent.get("handle"))
            r.add("Propriétaire du réseau identifié", str(data.get("name")),
                  weight=0, source="RDAP")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"RDAP: {e}")

    return r
