# Cahier des charges v2 : intégration continue + multi-constructeur (Nokia SR Linux)

Suite du projet `lab-reseau-frr` + `netcheck` (voir `SPEC_netcheck.md` pour la v1, dont toutes les contraintes restent valables).

## 1. Objectifs

| # | Objectif | Critère de réussite |
|---|---|---|
| O1 | **Intégration continue** : les tests unitaires tournent automatiquement sur GitHub à chaque push | Workflow vert sur GitHub, badge dans le README |
| O2 | **Installation propre** : une vraie commande `netcheck` | `pip install -e .` puis `netcheck --help` fonctionnent ; `python -m netcheck` marche toujours |
| O3 | **Loopback reconnu par le modèle** (`is_loopback`), et non plus par une heuristique de nom | Champ rempli par chaque driver et utilisé par la règle `interface_description_required` |
| O4 | **Lab multi-constructeurs** : r5 remplacé par un routeur **Nokia SR Linux** dans une deuxième topologie | OSPF entre r4 (FRR) et r5 (SR Linux) en Full, et pc1 ↔ pc2 joignables de bout en bout |
| O5 | **Driver SR Linux** dans netcheck | `snapshot`, `diff` et `check` fonctionnent sur un lab mixte FRR + SR Linux |

## 2. Contraintes

| # | Contrainte |
|---|---|
| C1-C8 | Toutes les contraintes de `SPEC_netcheck.md` §2 restent valables : lecture seule et liste blanche, pas de `sudo`, commentaires en français courts par bloc, petits commits, **jamais de `git push` sans me demander**. |
| C9 | **Le lab FRR existant ne change pas** : `lab.clab.yml`, `configs/`, `automation/` et `test_lab.sh` (28/28) restent identiques et fonctionnels. Le lab multi-constructeurs est un **ajout**, pas une modification. |
| C10 | Les deux labs ne tournent **jamais en même temps** (RAM). Utilise un réseau de management distinct pour le lab multi-constructeurs (ex. `172.20.21.0/24`), pour éviter toute confusion d'inventaire. |
| C11 | Identifiants SR Linux par défaut de containerlab (`admin`/`NokiaSrl1!`) acceptés **pour le lab uniquement**, documentés comme tels, jamais écrits en dur dans le code Python (inventaire + variables d'environnement). |
| C12 | Tout ce qui concerne SR Linux (syntaxe, sorties JSON, noms d'interfaces, type d'appareil Netmiko) doit être **vérifié sur l'équipement réel ou dans la documentation officielle**, jamais deviné. En cas de doute, dis-le. |

## 3. Phase A : intégration continue et installation (O1, O2)

- `pyproject.toml` à la racine : métadonnées, dépendances (reprises de `netcheck/requirements*.txt`), point d'entrée `netcheck = "netcheck.cli:main"` (ou équivalent). Les `requirements*.txt` restent, cohérents avec le `pyproject.toml`.
- `.github/workflows/tests.yml` : déclenché à chaque push et pull request ; matrice avec au moins **deux versions de Python** (3.11 et la plus récente disponible sur `actions/setup-python`) ; installe le projet et lance `pytest`. **Les tests d'intégration sur le lab ne tournent pas en CI** : documente pourquoi.
- Ajoute aussi une vérification `shellcheck` des scripts `.sh` et un lint Python léger (ex. `ruff check`, avec des règles raisonnables). Corrige ce qu'ils remontent, sans changer le comportement.
- Badge de statut du workflow en haut du README.
- Mets à jour le README (installation via `pip install -e .`).

**Critère de fin** : workflow vert **localement** (reproduis ses étapes dans un venv neuf), `netcheck --help` OK, `pytest` et `test_lab.sh` toujours verts. La CI GitHub sera vérifiée après mon push.

## 4. Phase B : `is_loopback` dans le modèle (O3)

- Ajoute `is_loopback: bool | None = None` à `Interface` (`None` = inconnu).
- Driver FRR : `True` si le JSON indique `"type": "Loopback"`. Vérifie sur les fixtures.
- `interface_description_required` : utilise `is_loopback` quand il est connu, et garde l'heuristique de nom actuelle **uniquement en repli** quand il vaut `None`.
- **Compatibilité** : un snapshot créé avant cette version (sans le champ) doit toujours se charger, avec `None`. Ajoute un test.
- Tests unitaires mis à jour ; les 6 tests de `interface_description_required` restent verts, plus de nouveaux cas (`is_loopback=True` avec un nom quelconque, `is_loopback=False` avec un nom en `lo…`).

## 5. Phase C : lab multi-constructeurs, avec validation avant d'aller plus loin (O4)

- `lab-multivendor.clab.yml` : même topologie et même adressage que le lab FRR, mais **r5 = Nokia SR Linux** (image officielle gratuite `ghcr.io/nokia/srlinux`, version fixée explicitement, kind containerlab adapté). Nom de lab distinct, réseau de management distinct (C10).
- Configuration de r5 dans `configs-multivendor/` (format de configuration de démarrage accepté par containerlab pour SR Linux) : interfaces vers r4 et vers pc2, OSPF area 0 en point-to-point vers r4, LAN et loopback en passif, redistribution ou annonce cohérente avec le reste du lab.
- `test_lab_multivendor.sh` sur le modèle de `test_lab.sh` : OSPF r4 ↔ r5 Full, BGP r3 ↔ r4 inchangé, route de r1 vers 192.168.2.0/24, ping et chemin pc1 → pc2.

**⚠️ Point de validation obligatoire.** Avant d'écrire le moindre code de driver, prouve que :
1. l'image SR Linux se télécharge et démarre sur ma machine ;
2. la RAM totale du lab reste raisonnable (donne le chiffre mesuré) ;
3. l'adjacence OSPF FRR ↔ SR Linux monte en Full et que pc1 joint pc2.

Puis **arrête-toi et fais-moi un rapport**. Si l'un des trois échoue, propose une alternative argumentée (autre version de SR Linux, BGP au lieu d'OSPF sur ce lien, etc.) au lieu d'insister.

## 6. Phase D : driver SR Linux (O5)

- `netcheck/drivers/srlinux.py` implémente le contrat de `drivers/base.py`. **Aucune modification de `collector.py`** n'est permise, sauf si elle est indispensable et justifiée (c'est le test de l'architecture).
- Méthode de collecte : Netmiko (type d'appareil SR Linux, sorties JSON via la CLI) **ou** l'API JSON-RPC de SR Linux. Compare les deux, explique ton choix, et garde la **liste blanche des commandes logiques** dans tous les cas.
- Normalisation vers le **même modèle** que FRR : interfaces (avec `is_loopback`), routes sélectionnées, voisins OSPF, sessions et préfixes BGP (vides sur r5 s'il n'y a pas de BGP), configuration.
- Inventaire : un champ `driver` par équipement (`frr` par défaut, `srlinux`), et un inventaire dédié au lab multi-constructeurs. Ajoute une option CLI `--inventory` si elle n'existe pas.
- Fixtures capturées sur le **vrai** SR Linux, cas nominal et cas dégradé (OSPF coupé), avec tests unitaires du driver comme pour FRR.
- **Conformité** : les règles écrites pour la syntaxe FRR n'ont pas de sens sur la configuration SR Linux. Ajoute un champ optionnel `drivers: [frr]` aux règles. Une règle ne s'applique qu'aux équipements des drivers listés, et le rapport affiche « non applicable » plutôt qu'une fausse violation. Ajoute au moins 2 règles propres à SR Linux, respectées par le lab.

## 7. Phase E : intégration, documentation, vérification finale

- `tests/integration_multivendor.sh` : S1 (aucun changement → OK), coupure du lien r4 ↔ r5 (→ ÉCHEC : voisin OSPF perdu **vu des deux côtés, FRR et SR Linux**, et routes vers 192.168.2.0/24 perdues), et `check` conforme sur le lab mixte.
- README : section « Lab multi-constructeurs », avec topologie, démarrage, RAM mesurée et différences notables FRR / SR Linux. `netcheck/README.md` : le driver SR Linux comme exemple concret de « comment ajouter un driver », avec ce qui a dû changer (idéalement : rien en dehors de `drivers/` et de l'inventaire).
- **Vérification finale** : `pytest`, `tests/integration.sh` (lab FRR), `tests/integration_multivendor.sh`, `test_lab.sh` 28/28 et `test_lab_multivendor.sh` verts, puis un rapport avec les chiffres.

## 8. Méthode de travail

1. Lis ce document, `SPEC_netcheck.md`, le README et `git log`. Propose un plan **avant de coder** et attends ma validation.
2. Une phase à la fois (A → B → C → D → E), avec un commit par phase et une validation entre chaque. **Phase C : arrêt obligatoire après le point de validation.**
3. À chaque fin de phase : résumé, tests passés et **explication pédagogique** du point technique principal.
4. Signale toute ambiguïté, et toute valeur qui ressemble à un exemple non remplacé.
