"""Analyse d'un numéro de téléphone (format E.164, pays, type de ligne).

Hors-ligne par défaut. Enrichissement optionnel via NumVerify (NUMVERIFY_API_KEY).
Si la lib `phonenumbers` est installée, elle est utilisée en priorité.
"""
from __future__ import annotations

import os

from ..data import PHONE_PREFIXES
from ..findings import Report
from ..net import http_get


def _match_prefix(e164: str):
    """Trouve l'indicatif pays le plus long qui correspond."""
    digits = e164.lstrip("+")
    for length in (4, 3, 2, 1):
        pref = digits[:length]
        if pref in PHONE_PREFIXES:
            return pref, PHONE_PREFIXES[pref]
    return None, (None, None)


def analyze(phone: str) -> Report:
    r = Report(identifier=phone, kind="phone")
    cleaned = "".join(c for c in phone if c.isdigit() or c == "+")
    r.fact("cleaned", cleaned)

    # Tentative avec phonenumbers si disponible (bien plus précis).
    try:
        import phonenumbers  # type: ignore
        from phonenumbers import carrier, geocoder, number_type, PhoneNumberType

        parsed = phonenumbers.parse(cleaned if cleaned.startswith("+") else "+" + cleaned, None)
        valid = phonenumbers.is_valid_number(parsed)
        r.fact("valid", valid)
        r.fact("e164", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
        r.fact("region", geocoder.description_for_number(parsed, "fr") or None)
        r.fact("carrier", carrier.name_for_number(parsed, "fr") or None)
        tmap = {
            PhoneNumberType.MOBILE: "mobile",
            PhoneNumberType.FIXED_LINE: "fixe",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixe/mobile",
            PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.TOLL_FREE: "numéro gratuit",
            PhoneNumberType.PREMIUM_RATE: "numéro surtaxé",
        }
        lt = tmap.get(number_type(parsed), "inconnu")
        r.fact("line_type", lt)
        if not valid:
            r.add("Numéro invalide", "format incorrect pour le pays", weight=25, source="phonenumbers")
        if lt == "VoIP":
            r.add("Ligne VoIP", "souvent utilisée pour l'anonymat / spam", weight=20, source="phonenumbers")
        if lt == "numéro surtaxé":
            r.add("Numéro surtaxé", "prudence (arnaque possible)", weight=30, source="phonenumbers")
    except ImportError:
        # Repli hors-ligne : indicatif pays seulement.
        if not cleaned.startswith("+"):
            r.add("Pas d'indicatif international (+)", "pays indéterminable de façon fiable",
                  weight=5, source="local")
        e164 = cleaned if cleaned.startswith("+") else "+" + cleaned
        r.fact("e164", e164)
        pref, (iso, name) = _match_prefix(e164)
        if iso:
            r.fact("country_prefix", "+" + pref)
            r.fact("country", f"{name} ({iso})")
            r.add("Pays identifié par l'indicatif", f"{name} ({iso})", weight=0, source="local")
        else:
            r.add("Indicatif pays non reconnu", "", weight=5, source="local")
        r.add("Installez `phonenumbers` pour l'opérateur et le type de ligne", "",
              weight=0, source="local")
    except Exception as e:  # pragma: no cover
        r.errors.append(f"phone: {e}")

    # NumVerify (optionnel).
    key = os.environ.get("NUMVERIFY_API_KEY")
    if key:
        try:
            num = cleaned.lstrip("+")
            res = http_get(f"https://apilayer.net/api/validate?access_key={key}&number={num}")
            data = res.json()
            if data and data.get("valid") is not None:
                r.fact("numverify_carrier", data.get("carrier") or None)
                r.fact("numverify_line_type", data.get("line_type") or None)
                r.fact("numverify_country", data.get("country_name") or None)
                r.fact("numverify_location", data.get("location") or None)
        except Exception as e:  # pragma: no cover
            r.errors.append(f"numverify: {e}")

    return r
