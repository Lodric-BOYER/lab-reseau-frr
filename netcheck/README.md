# netcheck

Outil en ligne de commande qui **valide les changements réseau** (état avant/après) et
**audite la conformité** des configurations. Développé et testé sur le lab FRR de ce dépôt
(voir le [README principal](../README.md#netcheck--validation-de-changement-et-conformité)
pour l'usage), mais conçu pour s'étendre à d'autres constructeurs.

> ⚠️ Outil strictement en lecture seule (liste blanche de commandes, voir plus bas). À
> n'utiliser sur un réseau réel qu'avec une autorisation écrite — même en lecture seule, un
> scan de découverte non autorisé peut être illégal.

## Architecture

```
netcheck/
├── cli.py                 # argparse : snapshot, list, diff, check, guard
├── inventory.py           # lit automation/inventory.yml (ou -i/--inventory) ; identifiants
│                           # NETCHECK_USER/PASS → LAB_USER/PASS → inventaire (dans cet ordre)
├── collector.py           # session SSH générique + liste blanche des commandes (C1) +
│                           # registre de drivers (DRIVER_REGISTRY) + attente de convergence
├── management.py          # filtre les interfaces de management (et ce qui en dépend),
│                           # partagé par diff.py et compliance.py
├── model.py                # dataclasses normalisées : Interface, Route, OspfNeighbor,
│                           # BgpPeer, BgpPrefix, DeviceState
├── drivers/
│   ├── base.py             # interface commune d'un constructeur (voir plus bas)
│   ├── frr.py               # driver FRRouting
│   └── srlinux.py           # driver Nokia SR Linux (lab multi-constructeurs, Phase D1)
├── snapshot.py             # sauvegarde/chargement JSON (snapshots/<nom>/*.json + meta.json)
├── diff.py                  # compare deux DeviceState -> Finding (CRITIQUE/ATTENTION/INFO)
├── compliance.py           # charge des règles YAML (yaml.safe_load), les applique -> Violation
├── report.py                # sorties terminal (rich), JSON, HTML (Jinja2, autoescape)
├── templates/               # report.html.j2 (diff), compliance.html.j2 (check)
└── rules/default.yml        # règles de conformité par défaut
tests/
├── fixtures/                # sorties JSON réelles capturées sur le lab (pas inventées)
├── test_*.py                 # tests unitaires (pytest)
└── integration.sh            # scénarios de bout en bout sur le lab déployé
```

**Flux d'une commande `snapshot`** : `cli.py` charge l'inventaire (`inventory.py`), collecte
en parallèle chaque équipement (`collector.collect_all`, qui résout le driver de chaque
routeur d'après son champ `driver` -- voir "Registre de drivers" plus bas -- avant de
déléguer la traduction et l'analyse des commandes), et écrit le résultat (`snapshot.py`).

**Flux d'une commande `diff`** : `cli.py` charge deux snapshots, compare chaque type de
donnée séparément (`diff.py`), classe les constats par gravité, produit un rapport
(`report.py`).

**Flux d'une commande `check`** : `cli.py` charge les règles YAML (`compliance.py`, validées
avant tout usage), collecte en direct ou charge un snapshot, applique chaque règle à chaque
équipement concerné, produit un rapport.

## Sécurité

- **C1 (lecture seule)** : `collector.ALLOWED_COMMANDS` est la seule liste de commandes qui
  peuvent être envoyées à un équipement. Vérifiée deux fois : sur tout `REQUIRED_COMMANDS`
  du driver avant même la connexion SSH, puis à nouveau avant l'envoi de chaque commande
  individuelle. Un driver ne peut donc jamais faire passer une commande de configuration.
- **Règles YAML** : chargées avec `yaml.safe_load` exclusivement (jamais `yaml.load`). Un
  fichier de règles peut venir d'une revue de code ou d'un partage réseau — ce n'est pas un
  canal de confiance. Voir `compliance.load_rules`.
- **Rapports HTML** : Jinja2 avec `autoescape=True` explicite, aucune valeur marquée `|safe`.
  Le filtrage (gravité/équipement) ne fait que montrer/cacher des lignes déjà rendues et
  échappées côté serveur — jamais de réinjection de texte en JavaScript. Aucune ressource
  externe (CSS/JS intégrés). Voir `tests/test_report.py` pour les preuves (payload XSS
  vérifié échappé, absence d'`innerHTML`, absence de `http://`/`https://`/`src=`).
- **`guard`** est la seule commande qui exécute quelque chose de modifiant — et c'est le
  script fourni par l'utilisateur (`--change`) qui le fait, jamais netcheck lui-même.

## Registre de drivers et lab multi-constructeurs (Phase D1)

`collector.DRIVER_REGISTRY` associe un nom de driver (`"frr"`, `"srlinux"`) à sa classe.
Chaque routeur de l'inventaire peut porter un champ `driver:` -- absent, il vaut `"frr"`
(comportement historique, lab mono-constructeur inchangé). Un nom qui ne correspond à aucun
driver enregistré lève une `ValueError` explicite (nom du routeur, nom demandé, drivers
disponibles) avant toute tentative de connexion, plutôt qu'un échec SSH incompréhensible plus
loin. `collector.collect()`/`collect_all()`/`wait_for_convergence()` acceptent toujours un
`driver` explicite (comportement historique, utilisé par les tests) ; omis, chacun résout son
propre driver via le registre.

`automation/inventory-multivendor.yml` est l'inventaire du lab multi-constructeurs
([lab-multivendor.clab.yml](../lab-multivendor.clab.yml)) : r1-r4 identiques à
`inventory.yml`, r5 avec `driver: srlinux` et ses propres identifiants (C11 : uniquement dans
ce fichier et les variables d'environnement, jamais en dur ailleurs, y compris dans les
tests). Le sélectionner : `netcheck <sous-commande> ... -i automation/inventory-multivendor.yml`
(l'option `-i`/`--inventory` existe sur `snapshot`, `diff`, `check` et `guard` ; le drapeau se
place après la sous-commande, comme tout argument `argparse`).

## Ajouter un driver constructeur (ex. Cisco IOS, FortiGate)

Rien en dehors de `drivers/` ne doit connaître la syntaxe d'un constructeur particulier :
`collector.py`, `diff.py`, `compliance.py` et `report.py` ne travaillent que sur le modèle
normalisé (`model.py`). Pour ajouter un driver :

1. Créer `drivers/<constructeur>.py` avec une classe héritant de `drivers.base.Driver`.
2. Définir `REQUIRED_COMMANDS` : les commandes **logiques** de ce driver, prises dans
   `collector.ALLOWED_COMMANDS` (toutes ne sont pas obligatoires — un pare-feu n'a pas
   d'OSPF, par exemple : `parse()` renvoie alors des listes vides pour ce qu'il ne collecte
   pas).
3. Implémenter `translate(commande_logique) -> commande_cli_réelle`. Pour FRR, ça préfixe
   par `vtysh -c`.
4. Implémenter `parse(raw, name, host) -> DeviceState`, en gérant les variations de format
   entre versions du même OS (voir `FrrDriver._parse_ospf`, qui lit `nbrState` ou `state`
   selon la version de FRR — découvert en testant sur le vrai lab, pas deviné).
5. Optionnel : surcharger `clean_output()` pour retirer un bruit propre au constructeur
   avant analyse.
6. Construire des fixtures **réelles** (`tests/fixtures/<driver>/`) en interrogeant un
   vrai équipement — jamais des JSON inventés à la main, ils cachent presque toujours un
   champ absent ou mal nommé (voir `tests/fixtures/r1/bgp_summary.json` : `{}`, sans
   aucune clé `peers`, quand aucun BGP n'est configuré — un cas qu'on ne devine pas ; ou,
   côté SR Linux, `tests/fixtures/r5/route.json` : une route apprise dynamiquement référence
   un `next-hop-group` qui s'est avéré indirect -- résolu en deux temps via deux tableaux de
   la même réponse JSON, une architecture réelle découverte en creusant en direct, pas
   devinée non plus, documentée dans `drivers/srlinux.py`).
7. Ajouter la classe au registre `collector.DRIVER_REGISTRY`, sous le nom que portera le champ
   `driver:` de l'inventaire.

## Reconnaissance du loopback (`is_loopback`)

`model.Interface.is_loopback` (`bool | None`, `None` = inconnu) porte l'information plutôt
qu'un attribut de nom. Chaque driver le renseigne à partir de ce que son équipement expose
réellement — pour FRR, le champ JSON `"type"` (`"Loopback"` vs `"Ethernet"`), toujours
présent, donc jamais `None` pour ce driver ; pour SR Linux, le nom d'interface comparé au
motif YANG exact (`lo0`, `lo1`... jusqu'à `lo255`), affiché par l'équipement lui-même dans un
message d'erreur de validation -- jamais None non plus, mais jamais deviné. La règle
`interface_description_required`
utilise `is_loopback` quand il est connu, et ne retombe sur l'heuristique de nom (`lo` exact,
ou préfixe `loopback`) que s'il vaut `None` — un driver qui n'expose pas cette info, ou un
snapshot écrit avant l'ajout du champ (`DeviceState.from_dict` le charge alors à `None` sans
planter, voir `tests/test_model.py`).
