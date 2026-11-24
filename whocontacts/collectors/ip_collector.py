"""Collecte des signaux publics sur une adresse IP (IPv4 ou IPv6).

On reçoit de plus en plus de contacts via une IP brute : un lien qui pointe sur
une IP plutôt qu'un domaine, une « adresse serveur » dans un message, une IP
extraite d'un en-tête d'e-mail. Ce collecteur évalue le risque d'une IP.

Hors-ligne (déterministe, sans réseau) :
- validation IPv4/IPv6 (y compris la forme ``[entre crochets]`` et ``:port``) ;
- classification des plages à usage spécial : privée / bouclage / lien-local /
  multicast / réservée, et surtout les plages **de documentation** (RFC 5737 /
  RFC 3849) qu'un vrai contact n'utiliserait jamais.

En ligne (si ``online=True``) :
- DNS inverse (PTR) via la bibliothèque standard — aucune clé d'API ;
- détection d'un hébergeur / VPS / cloud dans l'enregistrement PTR (un contact
  non sollicité venant d'un datacenter plutôt que d'un FAI résidentiel est un
  signal fréquent de bot, scanner ou VPN) ;
- RDAP (données publiques de registre) pour le réseau propriétaire.
"""

from __future__ import annotations

import ipaddress
import socket

from ..utils.http import HttpError, get_json
from .base import Collector

# Sous-chaînes fréquentes dans le PTR des hébergeurs / cloud / VPN. Ce n'est pas
# une liste de blocage : juste un indice que le trafic vient d'une
# infrastructure plutôt que d'une connexion résidentielle.
_HOSTING_HINTS = (
    "amazonaws", "aws", "ec2", "googleusercontent", "google", "azure",
    "microsoft", "digitalocean", "linode", "vultr", "ovh", "hetzner",
    "scaleway", "contabo", "leaseweb", "oracle", "cloud", "hosting",
    "server", "vps", "datacenter", "colo", "m247", "choopa", "quadranet",
)

_DOC_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")


def parse_ip(target: str):
    """Retourne un objet ip_address ou ``None`` si *target* n'est pas une IP."""
    candidate = target.strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


class IPCollector(Collector):
    id = "ip"

    def collect(self, target: str) -> None:
        ip = parse_ip(target)
        if ip is None:
            self.add("invalid", target, note="Adresse IP non valide.", risk=0.1, confidence=0.3)
            return

        self.add("ip", str(ip), note=f"Adresse IPv{ip.version} valide analysée.", confidence=0.6)

        if self._classify(ip):
            return  # plage à usage spécial : pas de recherche réseau utile

        self.add(
            "public", str(ip),
            note="Adresse publique routable. Activez le mode en ligne pour le DNS inverse et le RDAP.",
            risk=-0.05, confidence=0.4,
        )

        if not self.online:
            self.add("offline_mode", True, note="Mode hors-ligne : DNS inverse et RDAP ignorés.", confidence=0.3)
            return

        self._reverse_dns(ip)
        self._rdap(ip)

    # -- hors-ligne -------------------------------------------------------- #
    def _classify(self, ip) -> bool:
        """Classe les plages à usage spécial. Retourne True si une s'applique.

        L'ordre compte : les plages de documentation sont testées en premier
        car Python les considère aussi comme ``is_private``.
        """
        if any(ip in ipaddress.ip_network(n) for n in _DOC_NETS):
            self.add(
                "documentation", str(ip),
                note="Plage réservée à la documentation (RFC 5737 / RFC 3849) : un vrai "
                     "contact ne l'utilise jamais, adresse quasi certainement falsifiée.",
                risk=0.6, confidence=0.8,
            )
            return True
        if ip.is_loopback:
            self.add("loopback", str(ip),
                     note="Adresse de bouclage (localhost) : ne peut pas être la source réelle "
                          "d'un contact externe — usage suspect ou trompeur.",
                     risk=0.35, confidence=0.7)
            return True
        if ip.is_private:
            self.add("private", str(ip),
                     note="Plage privée (RFC 1918 / ULA), non routable sur Internet : ne peut pas "
                          "émettre un contact externe — signe classique d'en-tête falsifié.",
                     risk=0.35, confidence=0.7)
            return True
        if ip.is_link_local:
            self.add("link_local", str(ip),
                     note="Adresse lien-local, valable seulement sur le segment réseau local.",
                     risk=0.3, confidence=0.6)
            return True
        if ip.is_multicast:
            self.add("multicast", str(ip),
                     note="Adresse multicast : pas un hôte unique pouvant vous contacter.",
                     risk=0.3, confidence=0.6)
            return True
        if ip.is_reserved or ip.is_unspecified:
            self.add("reserved", str(ip),
                     note="Plage réservée ou non spécifiée : pas un hôte public normal.",
                     risk=0.3, confidence=0.6)
            return True
        return False

    # -- en ligne ---------------------------------------------------------- #
    def _reverse_dns(self, ip) -> None:
        try:
            host, _, _ = socket.gethostbyaddr(str(ip))
        except Exception:
            self.add("ptr", None,
                     note="Aucun DNS inverse (PTR). Fréquent pour le résidentiel, mais aussi "
                          "pour les infrastructures jetables.",
                     risk=0.05, confidence=0.3)
            return

        lowered = host.lower()
        if any(h in lowered for h in _HOSTING_HINTS):
            self.add("hosting", host,
                     note=f"Le DNS inverse (« {host} ») correspond à un hébergeur/VPS/cloud. Un "
                          "contact non sollicité venant d'un datacenter (plutôt que d'un FAI "
                          "résidentiel) est un signal fréquent de bot, scanner ou VPN.",
                     risk=0.4, confidence=0.6)
        else:
            self.add("ptr", host, note=f"Le DNS inverse pointe vers « {host} ».", confidence=0.5)

    def _rdap(self, ip) -> None:
        try:
            data = get_json(f"https://rdap.org/ip/{ip}", timeout=self.timeout)
        except HttpError:
            self.add("rdap", "unavailable",
                     note="Données de registre (RDAP) indisponibles pour cette IP.", confidence=0.2)
            return
        name = data.get("name") or ""
        country = data.get("country") or ""
        handle = data.get("handle") or ""
        bits = [b for b in (name, handle, country) if b]
        if bits:
            self.add("network", ", ".join(bits),
                     note="Réseau propriétaire / enregistrement issu des données publiques RDAP.",
                     confidence=0.6)
