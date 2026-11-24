"""WhoContacts — OSINT défensif + IA pour identifier qui vous contacte.

Outil open source qui, à partir d'un identifiant reçu (e-mail, numéro, domaine,
URL ou pseudo), collecte des signaux **publics** et en tire une estimation de
fiabilité, avec une synthèse en langage clair (IA optionnelle).

Lisez ``ETHICS.md`` : cet outil est **défensif** et ne doit pas servir à
traquer ou harceler autrui.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .identify import Report, identify  # noqa: E402

__all__ = ["identify", "Report", "__version__"]
