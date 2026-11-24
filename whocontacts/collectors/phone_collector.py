"""Collect public signals about a phone number.

Everything here is **offline** and privacy-preserving: it parses the number,
infers country, and (if the optional :mod:`phonenumbers` library is installed)
reports carrier and line type. It never dials, texts, or queries a lookup
service, so it leaks nothing about who is asking.
"""

from __future__ import annotations

import re

from .base import Collector

# Minimal country-code map for stdlib-only fallback (dial code -> country).
# Not exhaustive; phonenumbers covers the rest when available.
_DIAL_CODES = {
    "1": "Amérique du Nord (US/Canada)",
    "33": "France",
    "32": "Belgique",
    "41": "Suisse",
    "44": "Royaume-Uni",
    "49": "Allemagne",
    "34": "Espagne",
    "39": "Italie",
    "212": "Maroc",
    "213": "Algérie",
    "216": "Tunisie",
    "221": "Sénégal",
    "225": "Côte d'Ivoire",
    "237": "Cameroun",
    "7": "Russie/Kazakhstan",
    "86": "Chine",
    "91": "Inde",
    "234": "Nigéria",
}


class PhoneCollector(Collector):
    id = "phone"

    def collect(self, target: str) -> None:
        raw = target.strip()
        digits = re.sub(r"[^\d]", "", raw)
        has_plus = raw.strip().startswith("+") or raw.strip().startswith("00")
        self.add("input", raw, note="Numéro analysé (aucun appel ni SMS n'est émis).")

        if not (6 <= len(digits) <= 15):
            self.add("invalid", raw, note="Longueur inhabituelle pour un numéro de téléphone.", risk=0.2)
            return

        try:
            import phonenumbers  # type: ignore
            from phonenumbers import carrier, geocoder, number_type, PhoneNumberType  # type: ignore

            self._with_lib(raw, phonenumbers, carrier, geocoder, number_type, PhoneNumberType)
        except Exception:
            self._without_lib(digits, has_plus)

    # -- rich path -----------------------------------------------------------
    def _with_lib(self, raw, phonenumbers, carrier, geocoder, number_type, PhoneNumberType) -> None:
        try:
            num = phonenumbers.parse(raw, None if raw.startswith("+") else "FR")
        except Exception:
            self.add("unparseable", raw, note="Numéro non analysable. Ajoutez l'indicatif international (+33…).", risk=0.1)
            return

        valid = phonenumbers.is_valid_number(num)
        self.add(
            "valid", valid,
            note="Numéro valide et attribuable." if valid else "Numéro non valide selon les plans de numérotation.",
            risk=0.0 if valid else 0.4, confidence=0.9,
        )
        region = geocoder.description_for_number(num, "fr") or geocoder.description_for_number(num, "en")
        if region:
            self.add("region", region, note=f"Zone géographique probable : {region}.", confidence=0.7)
        car = carrier.name_for_number(num, "fr") or carrier.name_for_number(num, "en")
        if car:
            self.add("carrier", car, note=f"Opérateur : {car}.", confidence=0.6)

        t = number_type(num)
        kind = {
            PhoneNumberType.MOBILE: ("mobile", "Ligne mobile.", 0.0),
            PhoneNumberType.FIXED_LINE: ("fixe", "Ligne fixe.", -0.05),
            PhoneNumberType.FIXED_LINE_OR_MOBILE: ("fixe/mobile", "Ligne fixe ou mobile.", 0.0),
            PhoneNumberType.VOIP: ("voip", "Ligne VoIP (Internet) : facile à créer anonymement, prudence.", 0.4),
            PhoneNumberType.TOLL_FREE: ("gratuit", "Numéro gratuit (type 0800).", 0.0),
            PhoneNumberType.PREMIUM_RATE: ("surtaxé", "Numéro surtaxé : méfiance (arnaques au rappel).", 0.6),
        }.get(t, ("inconnu", "Type de ligne indéterminé.", 0.0))
        self.add("line_type", kind[0], note=kind[1], risk=kind[2], confidence=0.7)

    # -- stdlib fallback -----------------------------------------------------
    def _without_lib(self, digits: str, has_plus: bool) -> None:
        self.add(
            "library_missing", True,
            note="Installez « phonenumbers » pour l'opérateur et le type de ligne. Analyse de base effectuée.",
            confidence=0.3,
        )
        country = None
        if has_plus:
            norm = digits
            for length in (3, 2, 1):  # longest dial code first
                code = norm[:length]
                if code in _DIAL_CODES:
                    country = _DIAL_CODES[code]
                    self.add("country", country, note=f"Indicatif +{code} → {country}.", confidence=0.6)
                    break
        if not country:
            self.add(
                "country", "inconnu",
                note="Indicatif international absent : impossible de situer le numéro de façon fiable.",
                risk=0.15, confidence=0.4,
            )
        self.add("digits", len(digits), note=f"{len(digits)} chiffres.", confidence=0.5)
