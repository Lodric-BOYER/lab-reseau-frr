# Cahier des charges v4 : netcheck prêt pour l'entreprise

Suite du projet `lab-reseau-frr` + `netcheck` (v1 : `SPEC_netcheck.md`, v2 : `SPEC_v2.md`, v3 : `SPEC_v3.md`). Toutes les contraintes précédentes restent valables, sauf mention contraire. Version cible : **netcheck 0.4.0**.

Fil directeur : netcheck ne cherche pas à remplacer Batfish, NetBox, NAPALM ou une supervision existante. Il garde sa niche (lecture seule, verdicts prouvés, simplicité) et **se branche** sur ce qu'une entreprise utilise déjà.

## 1. Objectifs

| # | Objectif | Critère de réussite |
|---|---|---|
| O1 | **Socle v4** : règles de configuration déplacées dans les drivers, configuration structurée, peer groups, audit de fichiers hors ligne | `compliance.py` ne contient plus aucune syntaxe constructeur ; `check --config-dir` audite des fichiers sans équipement |
| O2 | **Modèle étendu** : IPv6, VRF, sections collectées | Diff, assert et check fonctionnent en IPv6 et par VRF ; un driver partiel donne NON ÉVALUABLE, jamais un faux OK |
| O3 | **Accès d'entreprise** : inventaire NetBox, coffre de secrets (Vault), clés SSH, vérification des clés d'hôte, bastion, comptes de service en lecture seule | Le lab est interrogé depuis un inventaire NetBox, avec des identifiants venus de Vault, à travers un bastion, avec un compte qui ne peut rien configurer |
| O4 | **Nouveaux constructeurs** : FortiGate, Cisco IOS (IOL), Juniper (vJunos), Cisco NX-OS si faisable, et un driver générique NAPALM | Chaque driver faisable passe snapshot, diff, check et assert sur son lab ; chaque driver infaisable est documenté avec la raison mesurée |
| O5 | **Conformité référencée** : correspondance avec les référentiels ANSSI et CIS, matrice de couverture, export PDF | Un rapport d'audit PDF qui cite pour chaque règle le contrôle de référentiel couvert |
| O6 | **Passage à l'échelle et historique** | 500 équipements simulés relevés dans un temps mesuré et borné ; historique des exécutions consultable |
| O7 | **Sorties pour la supervision** : Slack, Teams, e-mail, Prometheus + Grafana, SIEM | Une même panne remonte dans chacune des sorties configurées, sans secret ni configuration |
| O8 | **Simulation avant d'agir** (Batfish) | `netcheck simulate` dit si une configuration candidate respecte l'intent **avant** tout changement ; `guard --simulate` refuse un changement simulé en échec |
| O9 | **Processus de changement** : tickets ServiceNow / Jira, pré-contrôle en pipeline CI | Un `guard` lié à un ticket y joint son rapport ; une merge request qui casse l'intent est bloquée par le pipeline |
| O10 | **Confiance dans l'outil** : image Docker, versions signées, SBOM, audit des dépendances, journal d'audit infalsifiable | Une version publiée est vérifiable (signature, SBOM) et toute altération du journal d'audit est détectée |

## 2. Ordre des phases et justification

| Phase | Contenu | Objectif | Pourquoi à cette place |
|---|---|---|---|
| A | Socle : règles dans les drivers, configuration structurée, peer groups, `check --config-dir` | O1 | Dette identifiée en v3 ; prérequis de tous les nouveaux constructeurs et des référentiels |
| B | Modèle étendu : IPv6, VRF, sections collectées ; lab double pile + une VRF | O2 | Les nouveaux drivers doivent être écrits une seule fois, sur le modèle final |
| C | Accès d'entreprise : NetBox, Vault, clés SSH, clés d'hôte, bastion, comptes en lecture seule | O3 | Les labs des phases suivantes s'appuient dessus |
| D | Nouveaux constructeurs + driver NAPALM (**point d'arrêt de faisabilité obligatoire**) | O4 | Le plus risqué (images, licences, KVM, RAM) ; sur un socle stable |
| E | Conformité référencée, matrice de couverture, PDF | O5 | A besoin de tous les constructeurs |
| F | Passage à l'échelle, historique SQLite | O6 | Avant les sorties de supervision, qui lisent l'historique |
| G | Slack, Teams, e-mail, Prometheus, Grafana, SIEM | O7 | Branche monitor et l'historique sur l'existant |
| H | Simulation Batfish (**point d'arrêt de faisabilité obligatoire**) | O8 | A besoin de `--config-dir` (A) et des constructeurs (D) |
| I | Tickets ServiceNow / Jira, pipeline de pré-contrôle | O9 | Assemble `check --config-dir`, `simulate` et `guard` |
| J | Image Docker, signatures, SBOM, audit des dépendances, journal infalsifiable | O10 | Emballe la version finale |
| K | Documentation, version 0.4.0, vérification finale | — | Clôture |

## 3. Contraintes

| # | Contrainte |
|---|---|
| C1-C19 | Toutes les contraintes de `SPEC_netcheck.md`, `SPEC_v2.md` et `SPEC_v3.md` restent valables : lecture seule, liste blanche, pas de `sudo`, commentaires en français courts par bloc, petits commits, **jamais de `git push` sans me demander**, vérifier au lieu de deviner, références vérifiées (C14), secrets hors dépôt (C15), jamais d'équipement réel (C16), compatibilité ascendante (C17), un seul lab à la fois (C18), CI verte (C19). |
| C9 (rappel) | Les configurations des labs existants (`configs/`, `configs-multivendor/`, `configs-ceos/`) ne changent **que pendant la phase B**, après validation de la liste exacte des modifications. Les nouveaux labs ont leurs propres dossiers. |
| C20 | **Lecture seule par construction pour tout nouveau transport.** API REST : liste blanche des chemins exacts, méthode GET uniquement. NAPALM : liste blanche des getters `get_*` explicitement autorisés ; `cli`, `load_*`, `compare_config`, `commit_config`, `rollback`, `discard_config` interdits, test à l'appui. Batfish : analyse hors ligne de fichiers uniquement. |
| C21 | **Images et licences constructeurs** : jamais commitées ni redistribuées. Comptes (Cisco, Juniper, Fortinet, ServiceNow, Atlassian) créés **par moi**, avec mes données personnelles, jamais un compte ou une instance d'Advans. Tu me donnes la procédure vérifiée ; tu n'accèdes à aucun site à ma place. |
| C22 | **Écritures vers des systèmes externes** (tickets, Slack, Teams, e-mail, syslog) : uniquement sur option explicite, testées d'abord contre un serveur local ou un mock, puis sur mes instances personnelles **après mon accord**. Jamais d'écriture vers un équipement réseau. |
| C23 | **Contenu sous licence** (benchmarks CIS, guides constructeurs) : jamais reproduit. On cite l'identifiant du contrôle, son titre et la source, rien de plus. |
| C24 | **RAM** : mesure avant chaque nouveau composant lourd (NetBox, Batfish, VM constructeur, Grafana). Un seul composant lourd à la fois si la RAM libre passe sous 4 Go. Rapport chiffré à chaque fois. |
| C25 | **KVM** : les images constructeurs basées sur des VM (vrnetlab) exigent `/dev/kvm` dans WSL2. Tu vérifies sa présence et les droits ; tout réglage système (groupe `kvm`, `.wslconfig`) est fait **par moi**, avec les commandes que tu me donnes. |
| C26 | **Dépendances lourdes optionnelles** : NAPALM, pybatfish, WeasyPrint, hvac, pynetbox… sont des extras (`pip install netcheck[napalm]`, `[batfish]`, `[pdf]`, `[vault]`, `[netbox]`). Le cœur s'installe et fonctionne sans elles, avec un message clair si une option manque. |
| C27 | **Points d'arrêt obligatoires** : avant toute modification des configurations (B) ; après l'étude de faisabilité des constructeurs (D0) ; après l'étude de faisabilité Batfish (H0) ; avant la première écriture vers une instance externe réelle (I). |

## 4. Phase A : socle v4 (O1)

- **Règles dans les drivers.** Chaque driver fournit ses évaluateurs de configuration (interface du type `config_checks()` ou un module `drivers/<nom>_rules.py`). `compliance.py` ne garde que le moteur : chargement, validation, `drivers:`, « non applicable », références, sorties. Mesure à l'appui : plus aucune syntaxe FRR, SR Linux ou EOS dans `compliance.py`.
- **Configuration structurée.** Analyse hiérarchique de la configuration (blocs, indentation, accolades SR Linux) au lieu d'expressions régulières ligne par ligne. Évalue `ciscoconfparse2` pour les syntaxes de type IOS (FRR, EOS, Cisco) : licence, maintenance, version ; propose avant d'ajouter la dépendance.
- **Peer groups** : un voisin BGP défini par un peer group hérite de ses paramètres (mot de passe, GTSM, limite, politiques). Les règles BGP évaluent la valeur **effective**. Tests avec et sans peer group, FRR et EOS.
- **`netcheck check --config-dir <dossier> [--driver frr|eos|…]`** : audit de fichiers de configuration sans aucun équipement (un fichier par équipement, driver déduit de l'inventaire ou donné). Les règles qui lisent le modèle (état) sont « non applicables » dans ce mode, et le rapport le dit.
- Compatibilité : `default.yml` et `security.yml` v3 fonctionnent **sans modification** et donnent les mêmes résultats sur les trois labs (comparaison automatique avant/après refonte).

**Critère de fin** : mêmes verdicts qu'en v0.3.0 sur les trois labs, nouveaux tests peer groups et `--config-dir`, mesure du nombre de lignes retirées de `compliance.py`. Commit, arrêt.

## 5. Phase B : modèle étendu (O2)

- **IPv6** : adresses IPv6 sur les interfaces, table de routage IPv6, voisins OSPFv3, BGP `ipv6 unicast`. Diff, assert (`path` en IPv6 compris) et check fonctionnent en IPv6.
- **VRF** : champ `vrf` sur interfaces, routes et sessions BGP (défaut : `default`). Assertions et diff par VRF ; `path` reste dans la VRF de départ.
- **Sections collectées** : chaque `DeviceState` indique quelles sections ont été réellement collectées (interfaces, routes v4/v6, OSPF, OSPFv3, BGP, config). Une assertion ou un comparateur qui a besoin d'une section absente rend **NON ÉVALUABLE**, jamais OK. Indispensable pour les drivers partiels (NAPALM, FortiGate).
- **Lab** : **avant toute modification, montre-moi la liste exacte** des lignes ajoutées aux trois labs pour la double pile IPv4/IPv6 (adressage `2001:db8::/32`, documentation, RFC 3849) et pour **une** VRF de démonstration (proposer laquelle, sur quel routeur, et pourquoi). J'arbitre.
- Compatibilité : un snapshot v0.3.0 se charge (IPv6 et VRF absents = section non collectée), test à l'appui.

**Critère de fin** : les trois labs convergent en double pile, intents IPv6 verts, scénario de coupure rouge en IPv6, tous les anciens tests verts. Commit, arrêt.

## 6. Phase C : accès d'entreprise (O3)

- **Sources d'inventaire** : `inventory.py` accepte plusieurs sources : YAML (existant), CSV, et **NetBox** (API REST, jeton en lecture seule via `NETCHECK_NETBOX_TOKEN`, filtres par site, rôle, tag ; plateforme NetBox → driver par une table de correspondance explicite). NetBox tourne dans le lab avec `netbox-docker` (mesure la RAM avant). Un script de chargement remplit NetBox avec le lab.
- **Fournisseurs de secrets** : variables d'environnement (existant), fichier 0600 lu comme du texte, **HashiCorp Vault** (KV v2 ; serveur de développement en conteneur pour le lab ; authentification par jeton ou AppRole venant de l'environnement). Ordre de priorité documenté. Aucun secret dans les sorties, journaux ou exceptions (test qui échoue si une valeur de test apparaît).
- **Clés SSH** : authentification par clé (chemin de clé dans l'inventaire, phrase de passe éventuelle depuis le fournisseur de secrets).
- **Clés d'hôte** : vérification stricte par défaut avec un fichier `known_hosts` dédié. Les conteneurs du lab changent de clé à chaque déploiement : un mode explicite `--host-keys accept-new` (premier contact) est autorisé et documenté comme réservé au lab ; `--host-keys ignore` n'existe pas.
- **Bastion** : connexion à travers un hôte de rebond SSH (ProxyJump) déclaré dans l'inventaire. Le lab ajoute un conteneur bastion ; preuve que la connexion passe par lui (adresse source vue sur le routeur).
- **Comptes de service en lecture seule** : configuration de démonstration d'un compte `netcheck-ro` par constructeur (EOS : rôle limité aux commandes `show` ; SR Linux : rôle en lecture ; FRR : à étudier, signaler si impossible). **La preuve négative** (le compte ne peut pas configurer) est faite par les **scripts de test du lab**, jamais par netcheck, qui reste en lecture seule.

**Critère de fin** : snapshot des trois labs avec inventaire NetBox + secrets Vault + bastion + clés vérifiées, tests unitaires par source et par fournisseur, preuves négatives des comptes en lecture seule. Commit, arrêt.

## 7. Phase D : nouveaux constructeurs (O4)

### D0 : étude de faisabilité, puis ⚠️ **arrêt obligatoire**

Pour chaque constructeur, vérifie dans la documentation officielle (containerlab, constructeur) et donne-moi un tableau :

| Constructeur | Image et moyen de l'obtenir | Licence / compte | KVM requis | RAM annoncée | Transport (SSH, API) | Verdict |
|---|---|---|---|---|---|---|
| FortiGate (VM, licence d'évaluation) | | | | | API REST en priorité | |
| Cisco IOS (IOL, via Cisco Modeling Labs Free) | | | | | SSH | |
| Juniper (vJunos-router ou vJunos-switch) | | | | | SSH, NETCONF en lecture | |
| Cisco NX-OS (Nexus 9000v) | | | | | SSH, NX-API | |

Vérifie `/dev/kvm` dans WSL2 et la RAM libre. Propose un ordre et les labs (nom, réseau de management distinct, routeur remplacé, justification). Donne-moi les procédures de téléchargement exactes. Un constructeur infaisable sur ma machine (RAM, licence) est **documenté, pas forcé**. Puis arrête-toi.

### D1 à D4 : un driver par constructeur validé

Pour chacun, comme pour EOS en v3 : point de validation (image démarre, RAM mesurée, interopérabilité OSPF/BGP avec FRR prouvée des deux côtés avec preuves négatives, accès en lecture seule vérifié en direct), puis driver, fixtures réelles nominales et dégradées, `is_loopback`, masquage des secrets propres au constructeur (testé sur les vraies lignes), règles `drivers: [...]` dont au moins deux de sécurité, intent, `test_lab_<x>.sh`, `tests/integration_<x>.sh`, mesure de ce qui a changé hors de `drivers/`.

- **FortiGate** : API REST en GET uniquement, liste blanche des chemins exacts, jeton d'un profil administrateur **en lecture seule**, vérification TLS (certificat du lab épinglé, jamais `verify=False`). Le collecteur gagne un transport HTTP **sans affaiblir** la liste blanche (contrôle avant connexion et avant chaque requête, comme pour SSH).
- **Cisco IOS, Juniper, NX-OS** : SSH, sorties structurées quand elles existent (`| json`, `| display json`), sinon analyse texte testée sur fixtures réelles.

### D5 : driver générique NAPALM

- Driver `napalm` (plateforme précisée dans l'inventaire) pour les plateformes sans driver natif. Liste blanche des getters (C20). Ce qu'il ne fournit pas (OSPF notamment) est déclaré non collecté (phase B) : NON ÉVALUABLE, jamais OK.
- **Validation croisée** : sur au moins un équipement qui a aussi un driver natif (IOL ou EOS), comparer les deux modèles produits et documenter chaque écart.
- Nornir : évalue et dis-moi s'il apporte quelque chose de plus que le collecteur parallèle actuel ; ne l'intègre que si c'est justifié.

**Critère de fin** : chaque constructeur faisable passe snapshot, diff, check et assert ; tous les anciens labs verts ; tableau final des constructeurs (faisable, livré, infaisable avec la raison). Commit par constructeur, arrêt.

## 8. Phase E : conformité référencée (O5)

- Champ de règle `controls:` : liste de `{framework, id, title, url}` (ex. un guide ANSSI, un CIS Benchmark par plateforme). Titres et URL vérifiés (C14) ; texte des benchmarks jamais reproduit (C23).
- **Matrice de couverture** : pour un référentiel donné, quels contrôles sont couverts par une règle, lesquels ne le sont pas (et pourquoi : non vérifiable par la configuration, hors périmètre). `netcheck check --framework <nom>` filtre et produit cette matrice.
- **Export PDF** du rapport d'audit (extra `[pdf]`, à partir du HTML existant) : page de garde, synthèse par gravité et par catégorie, détail, matrice, secrets masqués.
- Au moins une règle de sécurité par nouveau constructeur reliée à un contrôle de référentiel.

**Critère de fin** : PDF d'audit produit sur au moins deux labs, matrice relue par moi. Commit, arrêt.

## 9. Phase F : passage à l'échelle et historique (O6)

- **Équipements simulés** : un outil de test (`tests/tools/`) qui lance N faux équipements SSH dans un seul processus (ports distincts), répondant avec les fixtures réelles, avec une proportion configurable d'équipements lents ou injoignables.
- **Collecteur** : nombre de connexions simultanées borné (`--max-workers`), délai par équipement, réessais avec attente croissante, progression affichée, aucun équipement lent ne bloque les autres.
- **Mesures** sur 50, 200 et 500 équipements simulés : durée, RAM, taille des snapshots. Compression des snapshots si utile (mesure avant de décider).
- **Historique** : base SQLite locale (`reports/`, hors Git) des exécutions (commande, date, verdict, constats résumés et masqués), alimentée par diff, check, assert, guard et monitor. Commande `netcheck history [--device] [--since]` ; rétention configurable.

**Critère de fin** : 500 équipements simulés relevés dans une durée mesurée et documentée, historique consultable, aucune régression. Commit, arrêt.

## 10. Phase G : sorties pour la supervision (O7)

- **Slack** (webhook entrant) et **Teams** (webhook Workflows) : mêmes garanties que Discord en v3 (https, pas de redirection, délai, URL secrète jamais affichée, liste blanche du contenu, mentions neutralisées).
- **E-mail** : SMTP avec STARTTLS obligatoire, identifiants depuis le fournisseur de secrets, test contre un serveur SMTP local.
- **Prometheus** : `monitor` écrit des métriques au format texte pour le collecteur de fichiers de `node_exporter` (statut global, statut par composant, nombre de constats par gravité, durée de collecte, horodatage). Tableau de bord **Grafana** fourni en JSON. Lab Prometheus + Grafana + node_exporter en conteneurs (RAM mesurée).
- **SIEM** : événements JSON (un par ligne, champs documentés, inspirés d'un schéma connu comme ECS) vers un fichier et/ou syslog (RFC 5424, TCP avec TLS). Test avec un récepteur syslog local. Exemple de règle d'ingestion documenté pour au moins un SIEM, sans le déployer s'il est trop lourd.

**Critère de fin** : une panne du lab apparaît dans chaque sortie configurée (mocks et serveurs locaux), puis le retour à la normale ; aucun secret ni configuration dans aucune sortie (tests). Commit, arrêt.

## 11. Phase H : simulation Batfish (O8)

### H0 : faisabilité, puis ⚠️ **arrêt obligatoire**
- Batfish en conteneur (mesure RAM), `pybatfish` en extra `[batfish]`. Charge les configurations des labs et rapporte précisément ce que Batfish analyse ou non (statut d'analyse par fichier, avertissements), **constructeur par constructeur** (FRR, EOS, SR Linux, Cisco, Juniper, FortiGate). Puis arrête-toi.

### H1 : `netcheck simulate`
- `netcheck simulate --configs <dossier> --intent <f.yml> [--baseline-configs <dossier>]` : traduit les assertions de l'intent en questions Batfish (sessions BGP, routes, chemins) et rend OK / ÉCHEC / NON ÉVALUABLE, avec le même format de rapport que `assert`. Une assertion que Batfish ne sait pas évaluer est NON ÉVALUABLE, jamais OK.
- Mode différentiel : avec `--baseline-configs`, liste ce que la configuration candidate change (joignabilité, routes).
- **`guard --simulate <dossier>`** : simulation avant la confirmation ; si elle est en ÉCHEC, guard refuse de lancer le changement (code 3) sauf option explicite documentée comme dangereuse.
- Validation : sur le lab, un changement dont la simulation annonce un ÉCHEC est effectivement en ÉCHEC une fois appliqué (et inversement) ; tout désaccord entre simulation et réalité est documenté.

**Critère de fin** : simulation cohérente avec la réalité sur les scénarios d'intégration existants, désaccords documentés. Commit, arrêt.

## 12. Phase I : processus de changement (O9)

- **Tickets** : `guard --ticket <id> --ticketing servicenow|jira` ajoute au ticket un commentaire (verdict, résumé masqué) et le rapport en pièce jointe. Jetons via le fournisseur de secrets. `--dry-run` montre ce qui serait envoyé. Tests contre un mock local d'abord.
- ⚠️ **Avant le premier envoi réel**, arrête-toi : je crée moi-même une instance personnelle (ServiceNow Personal Developer Instance, Jira Cloud gratuit) et je te donne le feu vert.
- **Pipeline de pré-contrôle** : exemples `.gitlab-ci.yml` et workflow GitHub Actions qui, sur une merge request modifiant des configurations, lancent `check --config-dir` puis `simulate`, publient le rapport en artefact et échouent si le verdict est ÉCHEC. Démonstration dans le dépôt : une branche de test qui casse l'intent est bloquée (sans fusionner quoi que ce soit dans `main` sans mon accord).

**Critère de fin** : ticket enrichi sur mock puis sur mon instance (après accord), pipeline rouge sur la branche cassante et vert sur une branche saine. Commit, arrêt.

## 13. Phase J : confiance dans l'outil (O10)

- **Image Docker** : construction multi-étapes, image de base épinglée par empreinte, utilisateur non root, système de fichiers en lecture seule possible, sans secret. Documentation d'usage (montage de l'inventaire, des secrets, des rapports).
- **Audit des dépendances** : `pip-audit` dans la CI ; mises à jour automatiques proposées (Dependabot) ; versions des actions toujours épinglées.
- **SBOM** au format CycloneDX pour le paquet et l'image.
- **Signatures** : attestations de provenance GitHub ou signature Sigstore (cosign, sans clé) du paquet et de l'image, avec la commande de vérification documentée. Rien n'est publié sur PyPI ou un registre public sans mon accord.
- **Journal d'audit infalsifiable** : guard, monitor et simulate écrivent un journal JSON en chaîne (chaque entrée contient l'empreinte de la précédente ; HMAC optionnel avec une clé du fournisseur de secrets). `netcheck audit-log verify` détecte toute entrée modifiée, supprimée ou réordonnée (tests à l'appui).
- **`SECURITY.md`** et **modèle de menaces** court (actifs, attaquants, protections, limites).

**Critère de fin** : image construite et vérifiée, SBOM et signature vérifiables, altération du journal détectée, CI verte avec `pip-audit`. Commit, arrêt.

## 14. Phase K : documentation, version et vérification finale

- README et `netcheck/README.md` : chaque nouveauté, avec l'avertissement d'autorisation écrite pour tout ce qui touche des équipements ou des systèmes externes.
- Guide « déployer netcheck en entreprise » : inventaire, secrets, bastion, compte en lecture seule, planification, sorties, pipeline, limites.
- Tableau final des constructeurs et de ce que chaque driver collecte.
- CHANGELOG 0.4.0, version **0.4.0**, tag annoté **en local**.
- **Vérification finale séquentielle** (un lab ou composant lourd à la fois) : pytest, ruff, shellcheck, pip-audit ; tous les labs (anciens et nouveaux) en démarrage à froid ; scénarios NetBox + Vault + bastion ; simulation ; sorties ; balayage du dépôt (aucune image, aucun secret réel, aucune URL réelle, aucune adresse autre que noreply). Rapport chiffré final.

## 15. Méthode de travail

1. Lis ce document, les trois cahiers des charges précédents, les deux README, le CHANGELOG et `git log`. Propose un plan détaillé **avant de coder** et attends ma validation.
2. Une phase à la fois (A → K), un commit par phase ou sous-phase, validation entre chaque. Respecte les **points d'arrêt obligatoires** (C27).
3. À chaque fin de phase : résumé, compteurs de tests, `git status` propre, RAM mesurée si un composant a été ajouté, **explication pédagogique** du point technique principal.
4. Au-delà de 10 avertissements ou modifications de masse, montre la liste avant de corriger.
5. Signale toute ambiguïté, toute valeur qui ressemble à un exemple non remplacé, toute affirmation non vérifiée, et tout ce qui est infaisable sur ma machine plutôt que de le contourner.
