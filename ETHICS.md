# Charte d'utilisation éthique — whocontacts

`whocontacts` est un outil **OSINT défensif**. Il interroge uniquement des **sources
ouvertes et publiques** et ne contourne aucune protection, authentification ou paramètre de
confidentialité.

## ✅ Usages prévus

- Vérifier un **contact entrant inconnu** (e-mail, appel, message) avant de répondre.
- Détecter le **phishing, le spam, l'usurpation d'identité et les arnaques**.
- Évaluer la **réputation d'un domaine ou d'une IP** qui vous sollicite.
- Protéger vos proches, votre famille ou votre organisation.

## 🚫 Usages interdits

- **Traquer, harceler ou surveiller** une personne, un·e ex, un particulier.
- **Ciblage de masse**, collecte ou revente de données personnelles.
- **Doxxing** : agréger et publier des informations pour nuire.
- Toute tentative de **dé-anonymiser** une personne contre sa volonté.
- Toute finalité **illégale** ou contraire au règlement d'un service tiers.

## 📏 Principes

1. **Sources publiques seulement.** Aucun scraping derrière authentification, aucun
   contournement de `robots.txt` abusif, aucune collecte de données privées.
2. **Faits ≠ identité.** Les résultats sont des **indices**, jamais une preuve d'identité
   civile. Un score de risque n'est pas un verdict de culpabilité.
3. **Minimisation.** N'interrogez que ce dont vous avez besoin, ne conservez pas les
   résultats plus longtemps que nécessaire.
4. **Respect du droit.** Vous êtes responsable du respect des lois applicables (RGPD en
   Europe, protection de la vie privée, droit local). En cas de doute, abstenez-vous.
5. **Proportionnalité.** L'intensité de la recherche doit rester proportionnée au risque
   réel que représente le contact.

## 🔒 Confidentialité technique

- En l'absence de clé API, **aucune donnée ne quitte votre machine** au-delà des requêtes
  publiques strictement nécessaires (DNS-over-HTTPS, RDAP, pages de profil publiques).
- La couche IA n'envoie des données à Claude **que si** vous avez configuré
  `ANTHROPIC_API_KEY`. Sinon, un moteur local par règles est utilisé.

En utilisant cet outil, vous confirmez agir dans un cadre **légitime et défensif**.
