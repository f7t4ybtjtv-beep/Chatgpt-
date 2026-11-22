"""Command-line interface: ``whocontacts <identifiant> [options]``."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .identify import identify
from .report import render_json, render_text

_CONSENT = (
    "Usage défensif uniquement : n'analysez un identifiant que si vous avez un\n"
    "motif légitime (la personne/organisation vous a contacté·e) et dans le respect\n"
    "du droit applicable. Voir ETHICS.md. L'auteur de l'outil décline toute\n"
    "responsabilité en cas d'usage abusif."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="whocontacts",
        description="Identifier qui vous contacte à partir de sources ouvertes (OSINT défensif + IA).",
        epilog=_CONSENT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="E-mail, numéro, domaine, URL ou pseudo à vérifier.")
    p.add_argument("--json", action="store_true", help="Sortie JSON (pour intégration).")
    p.add_argument("--offline", action="store_true", help="Aucune requête réseau (analyse hors-ligne).")
    p.add_argument("--no-ai", action="store_true", help="Désactiver la synthèse IA (règles uniquement).")
    p.add_argument(
        "--kind",
        choices=["email", "phone", "domain", "url", "username"],
        help="Forcer le type d'identifiant (sinon détection automatique).",
    )
    p.add_argument("--timeout", type=float, default=8.0, help="Délai réseau par requête (s). Défaut : 8.")
    p.add_argument("--version", action="version", version=f"whocontacts {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target:
        parser.print_help()
        return 2

    rep = identify(
        args.target,
        online=not args.offline,
        timeout=args.timeout,
        use_ai=not args.no_ai,
        kind=args.kind,
    )

    if args.json:
        print(render_json(rep))
    else:
        print(render_text(rep))

    # Exit code encodes the verdict for scripting: 0 fiable, 1 incertain, 2 suspect.
    if rep.score >= 55:
        return 2
    if rep.score >= 45:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
