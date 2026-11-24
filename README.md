# WhoContacts 🔎

**Outils OSINT open source, avec IA, pour identifier qui vous contacte.**

Vous recevez un e‑mail, un appel, un message d'un·e inconnu·e ? WhoContacts
collecte des **signaux publics** (OSINT) sur l'identifiant utilisé et vous donne
en quelques secondes une **estimation de fiabilité** + une **synthèse en
français clair** : *qui est‑ce probablement, quels sont les signaux d'alerte, et
que faire*.

C'est un outil **défensif et anti‑arnaque** — pas un outil de traque. Lisez
[`ETHICS.md`](ETHICS.md) avant toute utilisation.

```text
┌──────────────────────────────────────────────────────────┐
│ WhoContacts — qui vous contacte ?                        │
├──────────────────────────────────────────────────────────┤
│ Cible   : x7f392aa@mailinator.com                       │
│ Type    : email                                         │
│ Score   :  88/100  [█████████████████████░░░]           │
│ Verdict : 🔴 TRÈS SUSPECT                                │
└──────────────────────────────────────────────────────────┘
⚠ Adresse jetable/temporaire : souvent utilisée pour rester anonyme.
Recommandation : prudence. Ne cliquez sur aucun lien, ne communiquez
aucune donnée personnelle ou bancaire…
```

## Ce qu'il sait analyser

| Vous avez…        | Il regarde (sources publiques)                                             |
|-------------------|---------------------------------------------------------------------------|
| **E‑mail**        | validité, domaine jetable, adresse « de rôle », imitation de marque, MX, Gravatar, fuites (option) |
| **Numéro**        | pays/indicatif, opérateur, type de ligne (mobile/VoIP/surtaxé)            |
| **Domaine / URL** | DNS, serveurs mail (MX), **âge du domaine** (RDAP/WHOIS), motifs d'hameçonnage |
| **IP** (IPv4/IPv6) | classification des plages (privée/bouclage/réservée, **documentation « falsifiée »**), **DNS inverse** + détection d'hébergeur/VPS/cloud, réseau propriétaire (RDAP) |
| **Pseudo**        | présence de profils **publics** sur une sélection de plateformes          |

Chaque conclusion est **traçable** : le verdict n'est qu'une agrégation de
signaux concrets, tous affichés. L'IA ne fait que *rédiger* la synthèse — elle
ne change jamais le score.

## Installation

Le cœur fonctionne **sans aucune dépendance** (bibliothèque standard Python 3.9+) :

```bash
git clone https://github.com/f7t4ybtjtv-beep/Chatgpt-.git
cd Chatgpt-
python3 -m whocontacts "exemple@domaine.com"
```

Pour des résultats plus riches (opérateur téléphonique, MX, synthèse par Claude) :

```bash
pip install -r requirements-optional.txt
# ou :  pip install -e ".[full,ai]"
```

| Dépendance (optionnelle) | Apporte                              |
|--------------------------|--------------------------------------|
| `phonenumbers`           | opérateur + type de ligne du numéro  |
| `dnspython`              | enregistrements MX des domaines      |
| `anthropic` + `ANTHROPIC_API_KEY` | synthèse rédigée par Claude |

Sans clé API, la synthèse est produite par un **moteur de règles déterministe** :
l'outil reste 100 % utilisable hors‑ligne.

## Utilisation

```bash
# Détection automatique du type d'identifiant
whocontacts "+33 6 12 34 56 78"
whocontacts "https://secure-paypa1-login.com"
whocontacts "203.0.113.9"
whocontacts "@un_pseudo"

# Options utiles
whocontacts "a@b.com" --offline     # aucune requête réseau
whocontacts "a@b.com" --no-ai       # règles seules, pas d'appel IA
whocontacts "a@b.com" --json        # sortie machine (intégration)
whocontacts "a@b.com" --kind domain # forcer le type
```

Le **code de sortie** encode le verdict (pratique en script) :
`0` fiable/insuffisant · `1` incertain · `2` suspect.

### En bibliothèque Python

```python
from whocontacts import identify

rep = identify("suspicious@mailinator.com", online=True, use_ai=False)
print(rep.score, rep.verdict)      # 88 'TRÈS SUSPECT'
for s in rep.signals:
    print(s.source, s.key, s.note)
print(rep.to_dict())               # dict JSON-sérialisable
```

## Comment lire le score

| Score  | Verdict             | Lecture                                             |
|--------|---------------------|-----------------------------------------------------|
| 70–100 | 🔴 TRÈS SUSPECT     | Plusieurs signaux d'arnaque. Ne communiquez rien.   |
| 55–69  | 🟠 SUSPECT          | Prudence marquée, vérifiez par un autre canal.      |
| 45–54  | 🟡 INCERTAIN        | Ambigu, demandez confirmation.                      |
| 30–44  | 🟢 PLUTÔT FIABLE    | Rien d'alarmant, gardez l'esprit critique.          |
| 0–29   | 🟢 FIABLE           | Signaux rassurants.                                 |
| —      | 🔵 SIGNAL INSUFFISANT | Trop peu d'indices publics pour conclure.         |

> ⚠️ **Ce sont des indices probabilistes, pas des preuves.** Un score bas ne
> prouve pas la bonne foi ; un score haut ne prouve pas une fraude. Ne prenez
> jamais de décision irréversible sur la seule foi de l'outil.

## Architecture

```
whocontacts/
├─ detect.py        # type d'identifiant (email/phone/domain/url/ip/username)
├─ collectors/      # un collecteur par type → émet des Signaux publics
│  ├─ base.py       #   Signal (source, valeur, note, risque, confiance)
│  ├─ email_collector.py
│  ├─ phone_collector.py
│  ├─ domain_collector.py
│  └─ username_collector.py
├─ risk.py          # agrégation transparente → score + verdict
├─ ai.py            # synthèse Claude (optionnelle) ou règles déterministes
├─ identify.py      # orchestrateur → Report
├─ report.py        # rendu texte / JSON
└─ cli.py           # interface ligne de commande
```

Ajouter une plateforme à la recherche de pseudo ? Complétez `SITES` dans
`collectors/username_collector.py`. Ajouter un collecteur ? Héritez de
`Collector`, implémentez `collect()`, émettez des `Signal`.

## Respect de la vie privée

- N'envoie **jamais** d'information sur *vous* aux services interrogés
  (User‑Agent générique, pas d'e‑mail/nom/machine dans les requêtes).
- Collecteurs réseau volontairement **lents et limités** (respect des CGU).
- La synthèse IA est **opt‑in** : activée seulement si vous fournissez une clé.

## Tests

```bash
pip install pytest
pytest -q          # 27 tests, exécutables hors‑ligne
```

## Avertissement

Projet fourni « en l'état », sans garantie ([`LICENSE`](LICENSE) MIT). Usage
strictement **défensif et légal** : voir [`ETHICS.md`](ETHICS.md). Vous êtes
responsable de la conformité (RGPD, etc.) de votre usage.
