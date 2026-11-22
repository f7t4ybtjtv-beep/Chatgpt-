"""Interface en ligne de commande de whocontacts."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import investigate
from .report import render_json, render_markdown, render_terminal

BANNER = r"""
 whocontacts  ·  OSINT défensif — « qui me contacte ? »
 Sources publiques uniquement. Usage éthique : voir ETHICS.md
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="whocontacts",
        description="Identifier un contact entrant (e-mail, téléphone, pseudo, domaine, IP) "
                    "à partir de sources ouvertes, avec synthèse IA.",
        epilog="Exemples:\n"
               "  whocontacts john.doe@example.com\n"
               "  whocontacts +33612345678\n"
               "  whocontacts suspectuser --format json\n"
               "  whocontacts exemple-arnaque.com --no-ai -o rapport.md --format markdown",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("identifier", nargs="?", help="e-mail, numéro, pseudo, domaine, IP ou URL")
    p.add_argument("-f", "--format", choices=["terminal", "json", "markdown"],
                   default="terminal", help="format de sortie (défaut: terminal)")
    p.add_argument("-o", "--output", help="écrire le résultat dans un fichier")
    p.add_argument("--no-ai", action="store_true", help="désactiver la synthèse IA")
    p.add_argument("--no-color", action="store_true", help="sortie sans couleurs ANSI")
    p.add_argument("--version", action="version", version=f"whocontacts {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.identifier:
        print(BANNER)
        parser.print_help()
        return 0

    result = investigate(args.identifier, with_ai=not args.no_ai)
    report, ai = result["report"], result["ai"]

    if args.format == "json":
        text = render_json(report, ai)
    elif args.format == "markdown":
        text = render_markdown(report, ai)
    else:
        use_color = sys.stdout.isatty() and not args.no_color and not args.output
        text = render_terminal(report, ai, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Rapport écrit dans {args.output}")
    else:
        print(text)

    # Code de sortie selon le niveau de risque (utile en script).
    return 2 if report["risk_score"] >= 70 else 0


if __name__ == "__main__":
    raise SystemExit(main())
