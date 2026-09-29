# Cahier des charges v3 : netcheck devient un outil d'audit et de maintenance

Suite du projet `lab-reseau-frr` + `netcheck` (v1 : `SPEC_netcheck.md`, v2 : `SPEC_v2.md`). Toutes les contraintes précédentes restent valables, sauf mention contraire ci-dessous. Version cible : **netcheck 0.3.0**.

## 1. Objectifs

| # | Objectif | Critère de réussite |
|---|---|---|
| O1 | **Audit de sécurité** : règles de durcissement, reliées à des références vérifiables | `check --rules netcheck/rules/security.yml` produit un rapport d'audit ; le lab durci est conforme |
| O2 | **État attendu** : vérifier que le réseau est *tel qu'il doit être*, pas seulement ce qui a changé | `netcheck assert --intent intent.yml` en direct et hors ligne (snapshot) |
| O3 | **Changements attendus** dans `guard` | Un changement déclaré comme prévu n'est plus une alerte ; un changement prévu mais non observé est signalé |
| O4 | **Retour arrière automatique** | `guard --rollback annule.sh` lance l'annulation si le verdict est ÉCHEC, puis prouve le retour à l'état initial |
| O5 | **Surveillance planifiée et alertes** | `netcheck monitor` exécutable par un planificateur ; alerte envoyée uniquement quand le statut change |
| O6 | **Troisième constructeur** : Arista cEOS | `snapshot`, `diff`, `check` et `assert` fonctionnent sur un lab FRR + cEOS |

## 2. Ordre des phases et justification

| Phase | Contenu | Pourquoi à cette place |
|---|---|---|
| A | Règles de sécurité (audit seul) | Faible risque, réutilise le moteur de règles existant, résultat visible tout de suite |
| B | Durcissement du lab | Sépare « l'outil détecte » de « on corrige » : le rapport avant/après sert de démonstration |
| C | État attendu (`assert`) | Brique centrale : C, D et E s'appuient dessus |
| D | `guard` : changements attendus + retour arrière | Utilise le format de l'état attendu ; D2 dépend de D1 pour savoir si l'annulation a réussi |
| E | Surveillance planifiée + alertes | Assemble diff, conformité et état attendu dans une seule commande |
| F | Driver Arista cEOS | Le plus risqué (image, RAM, interopérabilité) : en dernier, avec un point d'arrêt obligatoire, quand tout le reste est stable |
| G | Documentation, version 0.3.0, vérification finale | Clôture |

## 3. Contraintes

| # | Contrainte |
|---|---|
| C1-C12 | Toutes les contraintes de `SPEC_netcheck.md` et `SPEC_v2.md` restent valables : lecture seule et liste blanche, pas de `sudo`, commentaires en français courts par bloc, petits commits, **jamais de `git push` sans me demander**, vérifier au lieu de deviner. |
| C9 (modifiée) | `lab.clab.yml`, `configs/`, `automation/` et `test_lab.sh` ne changent **que pendant la phase B**, après validation de la liste exacte des modifications. `test_lab.sh` 28/28 et `tests/integration.sh` 30/30 doivent rester verts après chaque phase. |
| C13 | netcheck reste en lecture seule. Les seules exécutions de scripts restent dans `guard` (changement et, nouveau, annulation), toujours fournis par l'utilisateur, affichés et confirmés avant exécution. Toute nouvelle commande logique ajoutée à la liste blanche doit être une commande d'affichage, justifiée et montrée avant ajout. |
| C14 | **Références de sécurité vérifiables** : chaque référence citée (ANSSI, CIS, RFC, documentation constructeur) doit avoir un titre exact et une URL vérifiée. Si aucune source fiable n'est trouvée pour une règle, laisser le champ vide plutôt qu'inventer. |
| C15 | Secrets (URL de webhook, jetons) uniquement par variables d'environnement, jamais dans le dépôt ni dans les logs. Aucun appel réseau réel dans les tests unitaires (serveur local ou mock). |
| C16 | Jamais d'utilisation sur un équipement réel. Les nouvelles fonctions (rollback, monitor) sont documentées avec l'avertissement d'autorisation écrite. |
| C17 | Compatibilité ascendante : un snapshot, un inventaire ou un fichier de règles v2 fonctionne sans modification en v3. Test à l'appui pour chaque format qui évolue. |
| C18 | Les deux ou trois labs ne tournent jamais en même temps (RAM). Mesurer la RAM avant tout nouveau lab. |
| C19 | La CI doit rester verte après chaque phase ; les nouveaux tests unitaires y tournent. |

## 4. Phase A : règles de sécurité (O1, audit seul)

- Nouveau fichier `netcheck/rules/security.yml`, distinct de `default.yml` (qui reste conforme sur le lab, inchangé).
- Nouveau champ optionnel de règle `references:` (liste de `{title, url}`), affiché dans les trois sorties (terminal, JSON, HTML). Absent = aucune référence. Validé au chargement.
- Nouveau champ optionnel `category:` (ex. `acces`, `journalisation`, `bgp`, `ospf`, `gestion`), utilisé pour regrouper le rapport HTML.
- Règles FRR à étudier (au moins 8, chacune avec `drivers: [frr]` si elle lit le texte) :
  - authentification OSPF sur les liens entre routeurs ;
  - mot de passe (TCP-MD5 ou TCP-AO) sur les sessions eBGP ;
  - `maximum-prefix` sur chaque voisin eBGP ;
  - `service password-encryption` ou absence de tout mot de passe en clair ;
  - bannière d'avertissement présente ;
  - journalisation avec horodatage ;
  - filtrage des annonces eBGP entrantes des préfixes privés ou « bogons » ;
  - GTSM (`ttl-security`) ou équivalent sur les sessions eBGP directes.
- Au moins 2 règles SR Linux de sécurité, vérifiées sur la syntaxe réelle.
- Nouveaux `kind` uniquement si `line_present` / `line_absent` ne suffisent pas (ex. règle par voisin BGP). Montre la liste des kinds nécessaires avant de coder.
- **Vérifie d'abord ce que FRR 10.2.1 et SR Linux 26.7.2 supportent vraiment** (commande acceptée, prise en compte dans le conteneur, notamment TCP-MD5 qui dépend du noyau). Une règle impossible à satisfaire dans le lab ne doit pas être écrite comme une bonne pratique applicable : signale-la.
- Résultat attendu de cette phase : un rapport d'audit **non conforme** sur le lab actuel, qui liste honnêtement ses faiblesses. C'est normal : on ne corrige rien en phase A.

**Critère de fin** : tests unitaires conforme / non conforme pour chaque règle et pour `references`, `check --rules security.yml` lancé sur les deux labs (l'un après l'autre), rapport HTML d'audit généré. Commit, arrêt.

## 5. Phase B : durcissement du lab (démonstration avant/après)

- **Avant toute modification**, montre-moi la liste exacte des lignes à ajouter dans `configs/` et `configs-multivendor/`, règle par règle. J'arbitre.
- Applique uniquement ce qui est validé ; les deux labs doivent continuer à converger (OSPF Full, eBGP Established, ping pc1 → pc2).
- Garde le rapport d'audit **avant** (phase A) et produis le rapport **après** : c'est la démonstration du projet. Les deux vont dans `docs/audit/` (ce sont des rapports sur un lab public, sans secret réel).
- Mots de passe de lab (OSPF, BGP) : valeurs de lab clairement identifiées comme telles, jamais réutilisables ailleurs, documentées.

**Critère de fin** : `security.yml` conforme sur les deux labs (ou non-conformités restantes expliquées et acceptées par moi), `test_lab.sh` 28/28, `tests/integration.sh` 30/30, `test_lab_multivendor.sh` et `tests/integration_multivendor.sh` verts. Commit, arrêt.

## 6. Phase C : état attendu (O2)

- Nouvelle commande `netcheck assert --intent <fichier.yml> [--snapshot <nom>] [-i inventaire] [--json] [--html]`.
- Format YAML, chargé avec `yaml.safe_load` et validé comme les règles. Types d'assertions minimum :

| type | Exemple |
|---|---|
| `bgp_session` | r3 → 172.16.34.2 Established, au moins 2 préfixes reçus |
| `ospf_neighbors` | r1 a exactement 2 voisins Full |
| `route_present` | r1 connaît 192.168.2.0/24, protocole attendu, next-hop ou interface attendus (optionnels) |
| `route_absent` | r4 ne connaît pas 10.1.12.0/30 (preuve que le filtrage fonctionne) |
| `interface_up` | r4 eth1 opérationnelle |
| `path` | le chemin logique de r1 vers 192.168.2.0/24 passe par r3 puis r4 (calculé à partir des next-hops des snapshots, sans commande supplémentaire) |

- Assertions évaluées uniquement sur le modèle normalisé (jamais du texte de config) : elles doivent marcher pour tous les drivers.
- Résultat par assertion : `OK`, `ÉCHEC` ou `NON ÉVALUABLE` (routeur injoignable, donnée non collectée par ce driver). Codes retour : 0 tout OK, 2 au moins un ÉCHEC, 3 erreur d'usage.
- Fichiers fournis : `intents/lab.yml` et `intents/lab-multivendor.yml`, vrais sur les labs durcis.

**Critère de fin** : tests unitaires par type d'assertion (vrai, faux, non évaluable), `assert` vert en direct et hors ligne sur les deux labs, et **rouge** quand on coupe le lien r4 ↔ r5 (scénario ajouté aux scripts d'intégration). Commit, arrêt.

## 7. Phase D : `guard`, changements attendus et retour arrière (O3, O4)

### D1 — changements attendus
- `guard --expect <fichier.yml>` : liste de changements prévus, décrits par critères sur les constats (équipement, catégorie, motif sur le message) ou par une section d'état attendu après changement (réutilise le format de la phase C).
- Un constat qui correspond à un changement prévu devient **PRÉVU** : affiché, mais sans effet sur le verdict.
- Un changement prévu **non observé** devient un constat ATTENTION (« changement attendu absent »).
- `diff` accepte aussi `--expect`, pour rejouer une analyse hors ligne.

### D2 — retour arrière
- `guard --rollback <annule.sh> [--rollback-on echec|attention]` (défaut : `echec`).
- Les deux scripts (changement et annulation) sont affichés et confirmés **ensemble** au début, avant toute action.
- Si le seuil est atteint : exécution de l'annulation, attente de convergence, troisième snapshot, puis diff **avant ↔ après annulation**. Le résultat final indique clairement : changement réussi / changement échoué et annulé avec succès / changement échoué **et annulation échouée** (code retour distinct, message très visible).
- Tout est journalisé dans un fichier `reports/guard_<horodatage>.json` (hors Git).

**Critère de fin** : tests unitaires de la logique (sans lab), puis scénarios d'intégration sur le lab : changement prévu = OK ; changement cassant + rollback = retour à l'état initial prouvé par un diff OK. Commit, arrêt.

## 8. Phase E : surveillance planifiée et alertes (O5)

- Nouvelle commande `netcheck monitor --baseline <snapshot> [--intent f.yml] [--rules f.yml] [-i inventaire] [--state-file f.json]`, **à exécution unique** (pas de démon) : snapshot, diff contre la référence, assertions, conformité, puis statut global.
- Le planificateur est externe (cron ou timer systemd utilisateur dans WSL) : documente les deux, sans `sudo` et sans modifier le système à ma place. Donne-moi les commandes à taper.
- Alertes via webhook générique (JSON POST), URL dans `NETCHECK_WEBHOOK_URL`. Formats compatibles au moins avec Discord et un webhook générique ; indique ce qui change pour Slack/Teams.
- **Anti-bruit** : alerte uniquement quand le statut change (OK → ÉCHEC, ÉCHEC → OK), grâce au fichier d'état. Un message de retour à la normale est envoyé.
- Le message d'alerte ne contient ni configuration ni secret : statut, équipements concernés, résumé des constats, chemin du rapport local.
- Timeout réseau court, échec d'envoi journalisé sans faire planter la commande.

**Critère de fin** : tests unitaires avec serveur HTTP local (aucun appel externe), scénario d'intégration : panne → une seule alerte, deuxième exécution sans changement → aucune alerte, réparation → message de retour à la normale. Commit, arrêt.

## 9. Phase F : driver Arista cEOS (O6), avec point d'arrêt obligatoire

- **Étape manuelle de ma part** : l'image cEOS se télécharge avec un compte gratuit sur arista.com puis s'importe dans Docker. Donne-moi la procédure exacte (version, commande d'import, vérification), vérifiée dans la documentation officielle containerlab et Arista. Tu ne crées aucun compte et n'accèdes à aucun site à ma place.
- Nouveau lab `lab-cEOS.clab.yml` (nom et réseau de management distincts, ex. `172.20.22.0/24`) : même topologie, un routeur remplacé par cEOS (propose lequel, en justifiant). Les autres labs ne changent pas.

**⚠️ Point de validation obligatoire** avant tout code de driver :
1. l'image démarre sur ma machine ;
2. RAM mesurée du lab complet ;
3. OSPF (et BGP si le routeur choisi en fait) monte avec FRR, pc1 joint pc2 ;
4. type d'appareil Netmiko, format des sorties JSON et identifiants par défaut vérifiés en direct.

Puis **arrête-toi et fais-moi un rapport**. Si un point échoue, propose une alternative argumentée.

- Ensuite : `drivers/eos.py` enregistré dans le registre, fixtures réelles (nominal + dégradé), `is_loopback`, règles `drivers: [eos]` (au moins 2, dont une de sécurité), `intents/lab-ceos.yml`, `test_lab_ceos.sh`, `tests/integration_ceos.sh`.
- Mesure honnête de ce qui a changé hors de `drivers/` pour ce troisième constructeur : c'est le vrai test de l'architecture.

**Critère de fin** : snapshot, diff, check et assert fonctionnent sur le lab cEOS ; rien de cassé ailleurs. Commit, arrêt.

## 10. Phase G : documentation, version et vérification finale

- README : sections audit de sécurité (avec le rapport avant/après), `assert`, `guard --expect --rollback`, `monitor` (planification et webhook), lab cEOS (mesures, différences entre constructeurs).
- `netcheck/README.md` : nouveaux formats (intent, expect), mise à jour du guide « ajouter un driver » avec le retour d'expérience du troisième constructeur.
- Version **0.3.0**.
- **Vérification finale séquentielle** (un seul lab à la fois) : pytest, ruff, shellcheck ; lab FRR (test_lab.sh, integration.sh) ; lab mixte (test_lab_multivendor.sh, integration_multivendor.sh) ; lab cEOS (test_lab_ceos.sh, integration_ceos.sh). Rapport chiffré final.

## 11. Méthode de travail

1. Lis ce document, les deux cahiers des charges précédents, les deux README et `git log`. Propose un plan détaillé **avant de coder** et attends ma validation.
2. Une phase à la fois (A → G), un commit par phase (ou sous-phase), validation entre chaque. **Arrêts obligatoires** : avant de modifier les configurations (phase B) et après le point de validation cEOS (phase F).
3. À chaque fin de phase : résumé, tests passés, `git status` propre et **explication pédagogique** du point technique principal.
4. Au-delà de 10 avertissements ou modifications de masse, montre la liste avant de corriger.
5. Signale toute ambiguïté, toute valeur qui ressemble à un exemple non remplacé et toute affirmation que tu n'as pas pu vérifier.
