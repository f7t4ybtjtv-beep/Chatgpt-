"""IP-address detector.

People increasingly get contacted from, or asked to connect to, a raw IP
address (a link that points at an IP instead of a domain, a "server" address in
a message, an entry from a mail header). This detector risk-assesses an IPv4 or
IPv6 address.

Offline (default, deterministic, no network):
  * validates and classifies the address (public vs private/loopback/reserved)
  * flags addresses that cannot plausibly originate a legitimate external
    contact (private / documentation / reserved ranges used as a lure)

Network (opt-in, set CONTACT_ID_ALLOW_NETWORK=1):
  * reverse DNS (PTR) lookup via the standard library — no API key, no
    third-party service, no leaking of the operator's own data
  * detects hosting / VPS / cloud providers in the PTR record (traffic from a
    datacenter rather than a residential ISP is a common bot / scanner / VPN
    signal)
  * optional RDAP lookup (public registry data) for the owning network, when
    the `requests` dependency is available
"""

from __future__ import annotations

import ipaddress
import socket

from ..models import Report, Signal, Risk
from ..utils import network_allowed, http_get

# Substrings that commonly appear in the reverse-DNS names of hosting / cloud /
# VPN providers. Not a blocklist — a heuristic hint that traffic is coming from
# infrastructure rather than a residential connection.
_HOSTING_HINTS = (
    "amazonaws", "aws", "ec2", "googleusercontent", "google", "azure",
    "microsoft", "digitalocean", "linode", "vultr", "ovh", "hetzner",
    "scaleway", "contabo", "leaseweb", "oracle", "cloud", "hosting",
    "server", "vps", "datacenter", "colo", "m247", "choopa", "quadranet",
)


def run(value: str, report: Report) -> None:
    raw = value.strip()
    # Strip a bracketed IPv6 literal (e.g. "[2001:db8::1]") and any :port.
    candidate = raw
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        report.add_error(f"ip: '{raw}' is not a valid IPv4/IPv6 address")
        return

    report.add(Signal("ip", "IP version", f"IPv{ip.version}", Risk.INFO,
                       f"Parsed as a valid IPv{ip.version} address."))

    _classify(ip, report)

    if ip.is_global and network_allowed():
        _reverse_dns(ip, report)
        _rdap(ip, report)


def _classify(ip, report: Report) -> None:
    """Offline special-use classification.

    Order matters: the documentation ranges are checked first because Python's
    ``is_private`` also reports them as private, and they carry a stronger
    signal (a real contact would never use a documentation-only address).
    """
    # Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
    # 2001:db8::/32) are reserved for examples; seeing one 'in the wild' is fake.
    if _is_documentation(ip):
        report.add(Signal("ip", "Documentation-only address", str(ip), Risk.MEDIUM,
                           "Reserved for documentation/examples (RFC 5737 / RFC 3849). A real "
                           "contact would never use it — almost certainly fabricated."))
        return
    if ip.is_loopback:
        report.add(Signal("ip", "Loopback address", str(ip), Risk.LOW,
                           "Refers to the local machine (localhost). It cannot be the real "
                           "source of an external contact — treat its use as suspicious or "
                           "mislabelled."))
        return
    if ip.is_private:
        report.add(Signal("ip", "Private / internal address", str(ip), Risk.LOW,
                           "A private LAN range (RFC 1918 / ULA). Not routable on the public "
                           "internet, so it cannot originate an external contact — a classic "
                           "sign of a spoofed header or a misleading link."))
        return
    if ip.is_link_local:
        report.add(Signal("ip", "Link-local address", str(ip), Risk.LOW,
                           "Only valid on the local network segment; cannot be a genuine "
                           "external sender."))
        return
    if ip.is_multicast:
        report.add(Signal("ip", "Multicast address", str(ip), Risk.LOW,
                           "A multicast group address, not a single host that could contact you."))
        return
    if ip.is_reserved or ip.is_unspecified:
        report.add(Signal("ip", "Reserved / unspecified address", str(ip), Risk.LOW,
                           "Falls in a reserved or unspecified range — not a normal public host."))
        return
    report.add(Signal("ip", "Public address", str(ip), Risk.INFO,
                       "A globally routable public IP. Enable network lookups "
                       "(CONTACT_ID_ALLOW_NETWORK=1) for reverse-DNS and registry details."))


def _is_documentation(ip) -> bool:
    doc_nets = (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
    )
    for net in doc_nets:
        try:
            if ip in ipaddress.ip_network(net):
                return True
        except (ValueError, TypeError):
            continue
    return False


def _reverse_dns(ip, report: Report) -> None:
    """PTR lookup using only the standard library."""
    try:
        host, _, _ = socket.gethostbyaddr(str(ip))
    except Exception:
        report.add(Signal("ip", "No reverse DNS", str(ip), Risk.INFO,
                           "No PTR record. Common for home/residential addresses and also for "
                           "throwaway infrastructure.", source="dns"))
        return

    lowered = host.lower()
    hit = next((h for h in _HOSTING_HINTS if h in lowered), None)
    if hit:
        report.add(Signal("ip", "Hosting / datacenter origin", host, Risk.MEDIUM,
                           f"Reverse DNS ('{host}') matches a hosting/VPS/cloud provider. "
                           "Unsolicited contact from datacenter infrastructure (rather than a "
                           "residential ISP) is a frequent bot, scanner, or VPN signal.",
                           source="dns"))
    else:
        report.add(Signal("ip", "Reverse DNS", host, Risk.INFO,
                           f"PTR record resolves to '{host}'.", source="dns"))


def _rdap(ip, report: Report) -> None:
    """Optional public RDAP lookup for the owning network (no API key)."""
    resp = http_get(f"https://rdap.org/ip/{ip}")
    if resp is None or resp.status_code != 200:
        return
    try:
        data = resp.json()
    except Exception:
        return
    name = data.get("name") or ""
    country = data.get("country") or ""
    handle = data.get("handle") or ""
    bits = [b for b in (name, handle, country) if b]
    if bits:
        report.add(Signal("ip", "Registered network", ", ".join(bits), Risk.INFO,
                           "Owning network / registry record from public RDAP data.",
                           source="rdap"))
