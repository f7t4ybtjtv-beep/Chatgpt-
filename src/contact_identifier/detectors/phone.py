"""Phone number detector.

Uses the offline `phonenumbers` library (Google libphonenumber port) for
validity, region, carrier and line-type metadata — no network required.
Adds simple scam/robocall heuristics on top.
"""

from __future__ import annotations

from ..models import Report, Signal, Risk

# Line-type names that are frequently abused by spam / scam / spoofing.
_RISKY_LINE_TYPES = {"VOIP", "TOLL_FREE", "PREMIUM_RATE"}


def run(number: str, report: Report, default_region: str | None = None) -> None:
    try:
        import phonenumbers  # type: ignore
        from phonenumbers import carrier, geocoder, number_type, PhoneNumberType
    except ImportError:
        report.add_error("phone: 'phonenumbers' not installed — cannot parse number")
        return

    try:
        parsed = phonenumbers.parse(number, default_region)
    except phonenumbers.NumberParseException as exc:
        report.add_error(f"phone: could not parse ({exc})")
        return

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

    if not valid:
        report.add(Signal("phone", "Not a valid number", e164,
                           Risk.MEDIUM if possible else Risk.HIGH,
                           "Fails validation for its country — may be spoofed or mistyped."))
    else:
        report.add(Signal("phone", "Valid number", e164, Risk.INFO,
                           "Parses as a valid number."))

    region = geocoder.description_for_number(parsed, "en")
    if region:
        report.add(Signal("phone", "Region", region, Risk.INFO,
                           f"Country/region associated with the number: {region}."))

    car = carrier.name_for_number(parsed, "en")
    if car:
        report.add(Signal("phone", "Carrier", car, Risk.INFO,
                           f"Original carrier (may differ after porting): {car}."))

    type_map = {
        PhoneNumberType.MOBILE: "MOBILE",
        PhoneNumberType.FIXED_LINE: "FIXED_LINE",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
        PhoneNumberType.VOIP: "VOIP",
        PhoneNumberType.TOLL_FREE: "TOLL_FREE",
        PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
        PhoneNumberType.SHARED_COST: "SHARED_COST",
        PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
        PhoneNumberType.PAGER: "PAGER",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "VOICEMAIL",
        PhoneNumberType.UNKNOWN: "UNKNOWN",
    }
    ltype = type_map.get(number_type(parsed), "UNKNOWN")
    if ltype in _RISKY_LINE_TYPES:
        report.add(Signal("phone", f"Line type: {ltype}", ltype, Risk.MEDIUM,
                           "VOIP / toll-free / premium-rate lines are disproportionately "
                           "used for scams and spoofing. Treat an unsolicited call with care."))
    else:
        report.add(Signal("phone", f"Line type: {ltype}", ltype, Risk.INFO,
                           f"Detected line type: {ltype}."))
