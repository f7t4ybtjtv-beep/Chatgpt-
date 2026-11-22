#!/usr/bin/env python3
"""Démo rapide de WhoContacts, entièrement hors-ligne (aucune requête réseau).

    python3 examples/demo.py

Montre comment appeler la bibliothèque et lire un rapport.
"""

from __future__ import annotations

import os
import sys

# Allow running directly (`python3 examples/demo.py`) without installing.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whocontacts import identify  # noqa: E402
from whocontacts.report import render_text

EXEMPLES = [
    "x7f392aa@mailinator.com",   # adresse jetable -> suspect
    "secure-paypa1-login.com",   # imitation de marque -> suspect
    "contact@gmail.com",         # fournisseur grand public -> neutre
    "+33 6 12 34 56 78",         # numéro FR -> signal insuffisant hors-ligne
]


def main() -> None:
    for cible in EXEMPLES:
        rep = identify(cible, online=False, use_ai=False)
        print(render_text(rep))
        print("\n" + "=" * 62 + "\n")


if __name__ == "__main__":
    main()
