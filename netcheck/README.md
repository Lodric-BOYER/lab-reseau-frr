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
├── cli.py                 # argparse : snapshot, list, diff, check, guard, assert, monitor
├── assertions.py          # `assert` : 6 types d'état attendu, évalués sur le modèle (Phase C)
├── expect.py              # `--expect` : changements prévus, garde-fous anti-masquage (Phase D1)
├── guard.py               # `guard` : retour arrière, codes 0-6, journal, délais (Phase D2)
├── monitor.py             # `monitor` : statut global, état observed/notified, verrou, alertes (Phase E)
├── webhook.py             # envoi de webhook : https, sans redirection, 5 s, un réessai, URL jamais affichée
├── secrets.py             # masquage des secrets dans tous les rapports et journaux
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
│   ├── srlinux.py           # driver Nokia SR Linux (lab multi-constructeurs, Phase D1)
│   └── eos.py               # driver Arista EOS / cEOS (Phase F) : enable(), liste blanche exacte
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
équipement concerné, produit un rapport. Trois états possibles par (règle, équipement), Phase
D2 : conforme (aucun `Violation`), non-conforme (`Violation`), ou **non applicable**
(`NotApplicable` -- le champ optionnel `drivers:` de la règle ne couvre pas le driver de cet
équipement). "Non applicable" n'est ni conforme ni une violation : il apparaît dans les 3
sorties (terminal, JSON, HTML) mais n'entre jamais dans `verdict()` ni le code retour.

### Audit hors ligne : `check --config-dir` (Phase A5)

```
netcheck check --config-dir configs                                   # lab FRR (inventaire par défaut)
netcheck check --config-dir configs --config-dir configs-multivendor \
               -i automation/inventory-multivendor.yml               # lab mixte : r5 lu en SR Linux
netcheck check --config-dir configs --config-dir configs-ceos \
               -i automation/inventory-ceos.yml                      # lab cEOS : r4 lu en EOS
netcheck check --config-dir fichiers/ --driver eos                    # sans inventaire : un driver pour tous
```

Audit de fichiers de configuration, **sans aucun équipement** (lecture seule, aucun transport). Deux
dispositions, mélangeables : `dossier/<équipement>.<extension>` ou `dossier/<équipement>/<fichier>` (si le
sous-dossier a plusieurs fichiers, celui que le driver nomme : `frr.conf`, `startup-config`, `config.cli`).
Le nom de l'équipement est celui du fichier ou du sous-dossier ; son driver vient de l'inventaire (`-i`) ou de
`--driver`. `--config-dir` se répète : un équipement d'un dossier ultérieur remplace celui d'un dossier
précédent, et le rapport le dit. Ce sont les mêmes règles et le même moteur que le direct : sur les trois labs,
les fichiers de démarrage du dépôt donnent le même verdict que l'audit en direct (test à l'appui).

- **Rien n'est ignoré en silence.** Une entrée qui n'est pas une configuration (`daemons`, fichier caché,
  `.md`, `.yml`, `.json`) est listée comme *information* ; une entrée qui ressemble à une configuration mais
  n'a pas pu être lue (équipement inconnu de l'inventaire sans `--driver`, plusieurs fichiers sans nom
  attendu, fichier vide, trop gros, illisible en UTF-8) est **NON AUDITÉE** : comme une ligne non lue, elle
  empêche le verdict « conforme » (ANALYSE INCOMPLÈTE, code 1 au minimum). Aucun fichier lu : code 3.
- **Les règles qui lisent l'état collecté sont non évaluables hors ligne** (`Check.needs` contient
  `interfaces` : `lan-en-ospf-passif`, `interface-avec-description`). Elles sont « non applicables » avec
  leur propre cause, **ÉTAT REQUIS (hors ligne)**, comptée à part dans la synthèse des trois sorties : ce n'est
  ni une règle hors sujet ni un trou d'un driver. Les règles de `security.yml` ne lisent que la configuration :
  aucune n'est perdue.
- Le rapport (terminal, JSON `source`, HTML) donne, pour chaque équipement, son driver et son fichier.

## Sécurité

- **C1 (lecture seule), à deux niveaux.** (1) `collector.ALLOWED_COMMANDS` est la liste des
  commandes *logiques* qui peuvent être demandées à un équipement ; vérifiée deux fois : sur tout
  `REQUIRED_COMMANDS` du driver avant même la connexion SSH, puis à nouveau avant l'envoi de
  chaque commande individuelle. (2) Depuis la Phase F, un driver peut déclarer `ALLOWED_CLI` : la
  liste des commandes CLI *réelles*, en **correspondance exacte** de la chaîne complète (le driver
  EOS : six chaînes, suffixe `| json` compris). Le niveau 1 ne voit pas ce que `translate()`
  fabrique ; le niveau 2 porte sur ce qui part réellement. Un driver ne peut donc jamais faire
  passer une commande de configuration, une redirection ou un second pipe.
- **`monitor` ne modifie rien** : il n'importe ni `guard` ni `subprocess` (vérifié par un test
  statique) et n'écrit que son état, son verrou et ses rapports locaux. **`guard`** est la seule
  commande qui exécute quelque chose de modifiant -- et c'est le script de l'utilisateur.
- **Secrets** : `secrets.mask_secrets` masque, dans tout ce qui est publié (rapports terminal,
  JSON et HTML, journaux de `guard`, alertes de `monitor`), la valeur de chaque secret reconnu --
  règle générique « mot-clé, type facultatif, valeur », mot-clé conservé. Les snapshots, eux, sont
  bruts et restent hors Git. **L'URL d'un webhook est un secret** : jamais affichée ni journalisée.
- **Règles YAML** : chargées avec `yaml.safe_load` exclusivement (jamais `yaml.load`). Un
  fichier de règles peut venir d'une revue de code ou d'un partage réseau — ce n'est pas un
  canal de confiance. Voir `compliance.load_rules`.
- **Rapports HTML** : Jinja2 avec `autoescape=True` explicite, aucune valeur marquée `|safe`.
  Le filtrage (gravité/équipement) ne fait que montrer/cacher des lignes déjà rendues et
  échappées côté serveur — jamais de réinjection de texte en JavaScript. Aucune ressource
  externe (CSS/JS intégrés). Voir `tests/test_report.py` pour les preuves (payload XSS
  vérifié échappé, absence d'`innerHTML`, absence de `http://`/`https://`/`src=`).

## Formats de fichiers : intent (`assert`) et expect (`--expect`)

Les deux sont du YAML chargé par `yaml.safe_load` exclusivement, et **validés en entier avant la
moindre action** (code retour 3 sinon, jamais découvert après l'exécution d'un script de
changement). Exemples réels : `intents/lab.yml`, `intents/lab-multivendor.yml`,
`intents/lab-ceos.yml`, `tests/expect/*.yml`.

### Intent : l'état attendu (`netcheck assert --intent f.yml [--snapshot s]`)

```yaml
assertions:
  - id: bgp-r3-vers-r4              # obligatoire, unique
    description: "..."              # obligatoire
    device: r3                      # obligatoire (point de départ pour `path`)
    type: bgp_session               # obligatoire : un des six types ci-dessous
    neighbor: 172.16.34.2           # + paramètres propres au type
```

| `type` | Paramètres | Vérifie |
|---|---|---|
| `bgp_session` | `neighbor` ; `state` (défaut `Established`), `min_prefixes_received` | la session existe, dans l'état voulu, avec assez de préfixes |
| `ospf_neighbors` | `count` ; `state` (défaut `Full`) | **exactement** `count` voisins dans cet état |
| `route_present` | `prefix` ; `protocol`, `next_hop`, `interface` | route **sélectionnée** au préfixe EXACT (pas de LPM), avec les attributs donnés |
| `route_absent` | `prefix` | aucune route sélectionnée à ce préfixe EXACT |
| `interface_up` | `interface` | interface présente, administrativement et opérationnellement active |
| `path` | `prefix`, `via` (suite d'équipements après `device`) ; `mode: all\|any` (défaut `all`) | le chemin logique calculé de saut en saut |

Résultat par assertion : **OK**, **ÉCHEC** ou **NON ÉVALUABLE** (jamais un OK silencieux). Code
retour : 0 tout OK, 2 au moins un ÉCHEC, 3 usage ; NON ÉVALUABLE ne change pas le code (mais
`monitor` le traite comme ATTENTION). Évalué **uniquement sur le modèle normalisé** : les mêmes
assertions fonctionnent sur FRR, SR Linux et EOS.

`path` : à chaque saut, route sélectionnée la **plus spécifique** (longest prefix match), puis
saut suivant résolu par l'adresse du next-hop (table adresse -> équipement, interfaces de
management exclues) ; arrêt quand le préfixe est directement connecté. Un **trou noir** (aucune
route, ou route de rejet Null0 / `dropRoute`) est un fait observable : **ÉCHEC** avec « trou
noir », jamais NON ÉVALUABLE. NON ÉVALUABLE est réservé aux limites de la méthode : boucle,
profondeur maximale (16 sauts), next-hop inconnu, adresse portée par deux équipements, équipement
injoignable. En ECMP, `mode: all` exige que toutes les branches soient conformes, `any` qu'une
seule le soit ; l'échec montre le chemin calculé (« attendu r1 r3 r4 r5, obtenu … »).

### Expect : ce que l'intervention est censée changer (`diff|guard --expect f.yml`)

```yaml
findings:                  # critères sur les constats du diff
  - id: r1-bascule-next-hop        # obligatoire, unique
    description: "..."             # obligatoire
    device: r1                     # obligatoire : un nom précis (jamais « all », jamais une liste)
    category: next_hop             # obligatoire : une catégorie réelle de diff.FINDING_CATEGORIES
    pattern: "10\\.1\\.23\\.0/30"  # facultatif : regex (re.search) sur le message du constat
    severity: attention            # facultatif : info | attention | critique (défaut attention)
    count: 5                       # facultatif : nombre EXACT de constats attendus
after:                     # assertions au format intent, évaluées sur l'état APRÈS le changement
  - {id: ..., description: ..., device: r1, type: ospf_neighbors, count: 2}
```

Un constat couvert par un critère est affiché **PRÉVU** : il garde sa gravité d'origine mais
n'entre plus dans le verdict. Inversement, un changement prévu **mais non observé**
(`expected_change_missing`), un nombre de constats différent de `count` (`expected_count_mismatch`)
et une assertion `after` en ÉCHEC ou NON ÉVALUABLE (`expected_state`) deviennent des constats
**ATTENTION**. Garde-fous anti-masquage : `device` et `category` obligatoires ; un motif qui
accepte tout (`.*`, `.+`, `.`, `^`, `[\s\S]*`) est refusé ; `severity` est un **plafond** (sans
lui, un critère ne couvre jamais un constat CRITIQUE) ; une clé inconnue est refusée ; les
assertions `after` sont validées au chargement. Les effets de bord non listés (par exemple un
second routeur dont le chemin change) restent donc **non prévus** et continuent de compter.

## Registre de drivers et lab multi-constructeurs (Phase D1)

`collector.DRIVER_REGISTRY` associe un nom de driver (`"frr"`, `"srlinux"`, `"eos"`) à sa classe.
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
(l'option `-i`/`--inventory` existe sur `snapshot`, `diff`, `check`, `guard`, `assert` et
`monitor` ; le drapeau se place après la sous-commande, comme tout argument `argparse`). Même
principe pour le lab Arista cEOS : `automation/inventory-ceos.yml` (r4 = `driver: eos`, Netmiko
`arista_eos`, identifiants par défaut de l'image `admin` / `admin`, lab uniquement).

## Ajouter un driver constructeur (ex. Cisco IOS, FortiGate)

**Ce que dit le modèle** : `diff.py`, `report.py` et l'essentiel de `compliance.py` ne
travaillent que sur le modèle normalisé (`model.py`) -- eux n'ont jamais besoin de changer.

**Ce qui doit vraiment changer, honnêtement, à l'ajout d'un driver (SR Linux en Phase D1/D2, puis
Arista EOS en Phase F : le troisième constructeur est le vrai test de l'architecture)** : pas
seulement un fichier dans `drivers/`. Liste complète, sans rien cacher :

1. `drivers/<constructeur>.py` : une classe héritant de `drivers.base.Driver`
   (`REQUIRED_COMMANDS`, `translate()`, `parse()`, `clean_output()` optionnel ; et, si
   l'équipement l'exige, `NEEDS_ENABLE` et `ALLOWED_CLI` -- voir le point 8) -- voir
   `drivers/srlinux.py` et `drivers/eos.py`.
2. `collector.DRIVER_REGISTRY` : la classe doit y être ajoutée sous le nom que portera le
   champ `driver:` de l'inventaire (Phase D1) -- c'est ce registre qui résout automatiquement
   le bon driver par routeur.
3. `model.DeviceState.driver` (`str`, défaut `"frr"`) : renseigné par `collector.collect()`
   d'après le champ `driver` du routeur (pas par le driver lui-même) -- c'est ce que
   `compliance.py` lit pour savoir quelles règles s'appliquent à quel équipement.
4. L'inventaire (`automation/inventory-<lab>.yml`) : un champ `driver:` par routeur du
   nouveau constructeur, plus ses propres identifiants (voir le point 5).
5. Identifiants par driver (Phase D2) : si le nouveau constructeur a ses propres identifiants
   par défaut, `inventory.py` les résout via `NETCHECK_<DRIVER>_USER/PASS` en priorité sur le
   générique `NETCHECK_USER/PASS` -- sans ça, positionner ce dernier pour cibler un autre
   driver écraserait silencieusement les identifiants du nouveau constructeur.
6. `compliance.py` : toute règle de `rules/*.yml` qui lit le TEXTE de la running-config est
   écrite pour la syntaxe d'UN seul constructeur et doit porter `drivers: [<ce constructeur>]`
   (Phase D2) -- sans ça, elle produit de fausses non-conformités sur tout autre driver. Une
   règle qui ne lit que le modèle normalisé (`interface_description_required`) reste
   universelle, sans ce champ.
7. Fixtures **réelles** (`tests/fixtures/<driver>/`) en interrogeant un vrai équipement --
   jamais des JSON inventés à la main, ils cachent presque toujours un champ absent ou mal
   nommé (voir `tests/fixtures/r1/bgp_summary.json` : `{}`, sans aucune clé `peers`, quand
   aucun BGP n'est configuré -- un cas qu'on ne devine pas ; ou, côté SR Linux,
   `tests/fixtures/r5/route.json` : une route apprise dynamiquement référence un
   `next-hop-group` qui s'est avéré indirect -- résolu en deux temps via deux tableaux de la
   même réponse JSON, une architecture réelle découverte en creusant en direct, pas devinée
   non plus, documentée dans `drivers/srlinux.py` ; ou, côté EOS, `tests/fixtures/ceos/` : un
   nominal et cinq états dégradés capturés par les six commandes du driver).
8. **Double liste blanche** (Phase F). La liste *logique* du collecteur ne voit pas ce que
   `translate()` fabrique. Un driver déclare donc `ALLOWED_CLI` : les commandes CLI *réelles*, en
   **correspondance exacte** de la chaîne complète (EOS : `show ip route | json`, pas un
   préfixe, pas une regex). Le collecteur la contrôle avant la connexion puis avant chaque envoi.
   Écrire **un test par détournement possible** : redirection (`>`), ajout (`>>`), `tee`, second
   pipe, variantes d'espacement et de casse, `;`, retour ligne -- et un driver piégé doit être
   refusé *avant* que `ConnectHandler` soit appelé. `NEEDS_ENABLE` : si la session s'ouvre en mode
   utilisateur (EOS : `r4>`), le collecteur appelle la méthode Netmiko `enable()` -- jamais
   `send_command("enable")`.
9. **Masquage des secrets** (`secrets.py`) *avant* qu'une configuration du nouveau constructeur
   entre dans un rapport. Un motif écrit pour `md5 X` prenait le `7` d'EOS pour la valeur et
   laissait fuir le hash entier (constaté sur les trois formes réelles : `md5 7`, `password 7`,
   `secret sha512`). La règle est donc générique -- **mot-clé, type facultatif (`0|5|7|8a|9|
   sha512|…`), valeur ; tout est masqué sauf le mot-clé** -- avec des tests sur les lignes
   **réelles** de l'équipement, un test qui échoue si une valeur de hash survit, la non-régression
   des autres constructeurs, et des garde-fous contre le sur-masquage (une phrase française
   contenant « secret » ou « md5 » ne doit pas être mangée). Un hash « type 7 » n'est pas un
   chiffrement : il est réversible.
10. **Normalisation du JSON** : relever les particularités sur l'équipement, ne pas les deviner.
    Pour EOS : ASN en chaîne (`"65001"` -> entier) ; `adjacencyState: "full"` en minuscules ->
    `"Full/-"` ; tout sous `vrfs.default` ; `peerState: "Idle"` + `peerStateIdleReason: "MaxPath"`
    -> `Idle(MaxPath)` ; route statique Null0 = `dropRoute`, `vias: []` mais `directlyConnected:
    true` (trompeur) -> même signature de trou noir que FRR (`NextHop` sans ip ni interface), donc
    `assert path` fonctionne sans changement ; `interfaceStatus: "disabled"` = admin down ;
    `is_loopback` d'après `hardware`, jamais d'après le nom ; interface de management (`Management0`)
    à lister dans `management_interfaces` de l'inventaire.
11. **Des tests d'intégration qui attendent un état STABLE.** « OSPF Full » (ou `health.py` vert)
    précède la fin du recalcul des routes : une référence prise à cet instant est fausse dès sa
    naissance, et un `monitor` lancé trop tôt dit la vérité sur un état transitoire. Avant de
    prendre une référence, relever deux fois à 4 s d'intervalle jusqu'à un diff vide ; avant de
    conclure à un retour à la normale, attendre le retour à la référence. Découvert en Phase F :
    deux scénarios de la Phase E n'avaient réussi que par chance de timing.
12. **Règles et intents** : les évaluateurs de règles qui lisent le texte de la configuration
    vivent encore dans `compliance.py` (un jeu `eos_*` de +147 lignes en Phase F) ; les règles
    YAML correspondantes portent `drivers: [<constructeur>]` et un jeu d'assertions
    `intents/lab-<x>.yml` fournit l'état attendu.

**Mesure honnête du troisième constructeur (Arista EOS, Phase F)** :

| Fichier | Changement |
|---|---|
| `drivers/eos.py` | **nouveau**, 192 lignes : tout le dialecte EOS |
| `drivers/base.py` | +19 : `NEEDS_ENABLE`, `ALLOWED_CLI`, `check_cli` (sans effet pour FRR / SR Linux) |
| `collector.py` | +12 : registre, `enable()`, contrôle exact de la commande CLI |
| `compliance.py` | **+147** : la syntaxe d'un constructeur vit encore ici (voir « pistes v4 ») |
| `secrets.py` | +35 / −11 : règle générique (faille réelle trouvée) |
| `rules/security.yml` | +77 : cinq règles EOS |
| `model.py`, `diff.py`, `assertions.py`, `management.py`, `report.py`, `guard.py`, `monitor.py`, `cli.py` | **0 ligne** |

## Reconnaissance du loopback (`is_loopback`)

`model.Interface.is_loopback` (`bool | None`, `None` = inconnu) porte l'information plutôt
qu'un attribut de nom. Chaque driver le renseigne à partir de ce que son équipement expose
réellement — pour FRR, le champ JSON `"type"` (`"Loopback"` vs `"Ethernet"`), toujours
présent, donc jamais `None` pour ce driver ; pour SR Linux, le nom d'interface comparé au
motif YANG exact (`lo0`, `lo1`... jusqu'à `lo255`), affiché par l'équipement lui-même dans un
message d'erreur de validation -- jamais None non plus, mais jamais deviné ; pour Arista EOS, le
champ JSON `"hardware"` (`"loopback"` vs `"ethernet"`), et `None` s'il est absent. La règle
`interface_description_required`
utilise `is_loopback` quand il est connu, et ne retombe sur l'heuristique de nom (`lo` exact,
ou préfixe `loopback`) que s'il vaut `None` — un driver qui n'expose pas cette info, ou un
snapshot écrit avant l'ajout du champ (`DeviceState.from_dict` le charge alors à `None` sans
planter, voir `tests/test_model.py`).
