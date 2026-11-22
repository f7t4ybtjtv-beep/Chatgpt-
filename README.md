# whocontacts 🕵️ — « Qui me contacte ? »

**Boîte à outils OSINT open source, assistée par IA, pour identifier un contact entrant** à
partir de **sources publiques uniquement**. Vous recevez un e-mail, un appel, un message
d'un inconnu ? `whocontacts` rassemble ce qui est publiquement connu sur cet identifiant
(e-mail, numéro, pseudo, domaine, IP) et une IA en tire un **verdict de confiance** clair,
avec des recommandations.

> ⚠️ **Usage défensif.** Cet outil sert à vous protéger de contacts inconnus (spam, phishing,
> arnaque, usurpation). Il n'a pas vocation à surveiller ou traquer des particuliers.
> Lisez **[ETHICS.md](ETHICS.md)** avant toute utilisation.

---

## ✨ Ce que ça fait

| Entrée | Analyses effectuées | Sources |
|--------|--------------------|---------|
| **E-mail** | validité, type de domaine (gratuit / pro / **jetable**), enregistrements MX, profil **Gravatar**, comptes liés, fuites de données | DNS-over-HTTPS, Gravatar, HIBP* |
| **Téléphone** | format E.164, pays, opérateur, type de ligne (mobile / VoIP / **surtaxé**) | `phonenumbers`*, NumVerify* |
| **Pseudo** | présence sur ~20 plateformes publiques (GitHub, Reddit, Instagram, TikTok…) | statut HTTP des pages de profil |
| **Domaine / URL** | registrar, **âge du domaine** (un domaine récent = risque), DNS, SPF | RDAP, DNS-over-HTTPS |
| **Adresse IP** | propriétaire du réseau, pays, hébergeur / VPN / proxy, contact abuse, reverse DNS | RDAP, DNS-over-HTTPS |

Puis une **couche IA** synthétise tous les signaux : nature probable du contact
(personne réelle, entreprise, spam, arnaque…), niveau de confiance, signaux d'alerte et
actions recommandées.

\* _Fonctionnalités optionnelles activées par une clé API ou une dépendance — voir plus bas.
Tout le reste fonctionne sans aucune clé, en Python standard._

---

## 🚀 Installation

Aucune dépendance obligatoire (Python ≥ 3.9) :

```bash
git clone <ce-dépôt>
cd whocontacts
python3 -m whocontacts --help
```

Enrichissements optionnels :

```bash
pip install -r requirements.txt   # phonenumbers (opérateur/type de ligne) + anthropic (IA Claude)
# ou, en tant que paquet :
pip install -e .
whocontacts john.doe@example.com
```

---

## 🧑‍💻 Utilisation

```bash
# E-mail
whocontacts john.doe@example.com

# Téléphone (indicatif international recommandé)
whocontacts +33612345678

# Pseudo (recherche multi-plateformes)
whocontacts suspectuser99

# Domaine ou URL reçue par message
whocontacts https://offre-cadeau-gratuite.xyz

# Adresse IP
whocontacts 203.0.113.45

# Formats et options
whocontacts cible --format json                 # JSON structuré
whocontacts cible --format markdown -o rapport.md
whocontacts cible --no-ai                        # désactive la synthèse IA
whocontacts cible --no-color                     # sans couleurs ANSI
```

Le **code de sortie** vaut `2` si le risque est élevé (≥ 70/100), `0` sinon — pratique en script.

### En bibliothèque Python

```python
from whocontacts.core import investigate

result = investigate("arnaque@mailinator.com")
print(result["report"]["risk_score"], result["ai"]["likely_nature"])
```

---

## 🤖 La couche IA

- **Avec Claude** : définissez `ANTHROPIC_API_KEY` et installez `anthropic`. L'IA reçoit les
  faits bruts (jamais de données inventées), distingue faits et hypothèses, et refuse de
  déduire une identité civile réelle. Modèle configurable via `WHOCONTACTS_MODEL`.
- **Sans clé** : un moteur **déterministe par règles** produit le même type de verdict à
  partir du score et des signaux. Aucune donnée ne quitte votre machine dans ce mode.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export WHOCONTACTS_MODEL=claude-3-5-sonnet-latest   # optionnel
whocontacts inconnu@domaine-suspect.com
```

---

## 🔑 Clés API optionnelles

| Variable | Service | Apporte |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | Claude (Anthropic) | synthèse IA en langage naturel |
| `HIBP_API_KEY` | Have I Been Pwned | exposition d'un e-mail dans des fuites |
| `NUMVERIFY_API_KEY` | NumVerify | opérateur / type de ligne d'un numéro |

Sans ces clés, les modules concernés sont simplement ignorés (dégradation propre).

---

## 🧩 Architecture

```
whocontacts/
├── classify.py          # détecte le type d'identifiant
├── core.py              # orchestrateur
├── net.py              # HTTP + DNS-over-HTTPS (stdlib)
├── data.py             # listes (domaines jetables, indicatifs, plateformes…)
├── findings.py         # structures Report / Signal + scoring
├── modules/            # un analyseur par type
│   ├── email_checks.py
│   ├── phone_checks.py
│   ├── domain_checks.py
│   ├── ip_checks.py
│   └── username_checks.py
├── ai/analyzer.py      # synthèse Claude + repli par règles
├── report.py           # rendu terminal / JSON / markdown
└── cli.py              # interface CLI
```

**Étendre** : ajoutez des plateformes dans `data.USERNAME_SITES`, des domaines jetables dans
`DISPOSABLE_EMAIL_DOMAINS`, des indicatifs dans `PHONE_PREFIXES`, ou un nouveau module dans
`modules/` branché depuis `core.investigate`.

---

## ✅ Tests

```bash
python3 -m pytest tests/ -q       # logique hors-réseau (détection, scoring, règles)
```

---

## ⚖️ Licence & éthique

[MIT](LICENSE). En utilisant `whocontacts`, vous acceptez les règles de
**[ETHICS.md](ETHICS.md)** : sources publiques uniquement, finalité défensive, respect de la
vie privée et des lois applicables (RGPD, etc.). Les résultats sont **indicatifs** et ne
constituent jamais une preuve d'identité.
