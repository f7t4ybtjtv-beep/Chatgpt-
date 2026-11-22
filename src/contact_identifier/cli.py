"""Command-line interface.

Examples
--------
    contact-id someone@example.com
    contact-id "+1 202-555-0142" --region US
    contact-id johndoe --kind username
    contact-id example.com --json
    echo -e "a@b.com\\nbob" | contact-id --stdin
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import identify
from .models import Risk

_COLORS = {
    Risk.INFO: "\033[90m",    # grey
    Risk.LOW: "\033[32m",     # green
    Risk.MEDIUM: "\033[33m",  # yellow
    Risk.HIGH: "\033[31m",    # red
}
_RESET = "\033[0m"


def _render(report, color: bool) -> str:
    if report.summary:
        body = report.summary
    else:
        body = f"{report.query} [{report.kind}] -> {report.risk.value}"
    if color and sys.stdout.isatty():
        c = _COLORS.get(report.risk, "")
        banner = f"{c}=== {report.risk.value.upper()} ==={_RESET}"
        return f"{banner}\n{body}"
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="contact-id",
        description="OSINT toolkit: identify and risk-assess who is contacting you "
                    "(email / phone / username / domain). Public data only. "
                    "Use responsibly and lawfully — see the README ethics notice.",
    )
    parser.add_argument("identifiers", nargs="*", help="one or more identifiers to check")
    parser.add_argument("--kind", choices=["email", "phone", "username", "domain"],
                        help="force the identifier type instead of auto-detecting")
    parser.add_argument("--region", help="default ISO region for phone numbers without a + code (e.g. US, FR)")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument("--no-summary", action="store_true", help="skip the AI/heuristic summary")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--stdin", action="store_true", help="read identifiers from stdin, one per line")
    parser.add_argument("--version", action="version", version=f"contact-identifier {__version__}")
    args = parser.parse_args(argv)

    targets: list[str] = list(args.identifiers)
    if args.stdin or not targets:
        if not sys.stdin.isatty():
            targets.extend(line.strip() for line in sys.stdin if line.strip())
    if not targets:
        parser.print_help()
        return 2

    reports = [
        identify(t, kind=args.kind, default_region=args.region,
                 summarize_report=not args.no_summary)
        for t in targets
    ]

    if args.json:
        import json
        payload = [r.to_dict() for r in reports]
        print(json.dumps(payload if len(payload) > 1 else payload[0], indent=2, ensure_ascii=False))
    else:
        for i, r in enumerate(reports):
            if i:
                print("\n" + "-" * 60 + "\n")
            print(_render(r, color=not args.no_color))

    # Exit code reflects the worst risk found (handy for scripting/automation).
    worst = max((r.risk.weight for r in reports), default=0)
    return 0 if worst < Risk.HIGH.weight else 1


if __name__ == "__main__":
    raise SystemExit(main())
