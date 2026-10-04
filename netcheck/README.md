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
├── confparse.py            # analyse structurelle d'une configuration (indentation, accolades, `set`) ;
│                           # aucune ligne ignorée en silence (Phase A v4, étape A2)
├── configdir.py            # lecture de fichiers de configuration hors ligne : `check --config-dir` (A5)
├── ruletypes.py            # Rule, Violation, NotApplicable, ConfigWarning, Check : types partagés entre
│                           # le moteur et les drivers
├── drivers/
│   ├── base.py             # interface commune d'un constructeur (voir plus bas)
│   ├── registry.py          # DRIVER_REGISTRY (collector.DRIVER_REGISTRY en est le même objet)
│   ├── frr.py               # driver FRRouting ...
│   ├── frr_rules.py         # ... et ses évaluateurs de règles de configuration
│   ├── srlinux.py           # driver Nokia SR Linux (lab multi-constructeurs, Phase D1) ...
│   ├── srlinux_rules.py     # ... et ses évaluateurs
│   ├── eos.py               # driver Arista EOS / cEOS (Phase F) : enable(), liste blanche exacte ...
│   ├── eos_rules.py         # ... et ses évaluateurs
│   └── bgp_neighbors.py     # vue « voisin BGP effectif » (peer groups, plages dynamiques), FRR et EOS
├── snapshot.py             # sauvegarde/chargement JSON (snapshots/<nom>/*.json + meta.json)
├── diff.py                  # compare deux DeviceState -> Finding (CRITIQUE/ATTENTION/INFO)
├── compliance.py           # le MOTEUR : charge les règles YAML (yaml.safe_load), résout l'évaluateur chez
│                           # le driver de chaque équipement, verdict ; plus aucune syntaxe de constructeur
├── report.py                # sorties terminal (rich), JSON, HTML (Jinja2, autoescape)
├── templates/               # report.html.j2 (diff), compliance.html.j2 (check)
└── rules/default.yml        # règles de conformité par défaut
tests/
├── fixtures/                # sorties et configurations réelles capturées sur les labs (pas inventées)
├── golden/                  # gel de la conformité : réponses sur des configurations réelles + mutations
├── tools/golden.py          # enregistre, compare, ajoute et met à jour le gel (jamais en bloc)
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
avant tout usage), collecte en direct, charge un snapshot ou lit des fichiers (`--config-dir`), puis
`compliance.evaluate_config()` applique chaque règle à chaque équipement concerné : le moteur résout
l'évaluateur du `kind` de la règle chez le **driver** de l'équipement, qui analyse lui-même la
configuration (`Driver.parse_config`). Trois états possibles par (règle, équipement) : conforme (aucun
`Violation`), non-conforme (`Violation`), ou **non applicable** (`NotApplicable`, trois causes, voir plus
bas). "Non applicable" n'est ni conforme ni une violation : il apparaît dans les 3 sorties (terminal, JSON,
HTML) mais n'entre jamais dans `verdict()` ni le code retour.

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
  empêche le verdict « conforme » (ANALYSE INCOMPLÈTE, code 1 au minimum). **Aucun fichier audité** (tous
  rejetés, ou aucun candidat) : code 3, jamais 1 : un pipeline ne peut pas passer avec un audit qui n'a rien lu.
- **Un fichier de notes n'est jamais « conforme ».** Un fichier n'est audité que si au moins la moitié de ses
  lignes de premier niveau commencent par un mot-clé racine connu du driver (`Driver.ROOT_KEYWORDS` :
  `hostname`, `interface`, `router`… ; `network-instance`, `system`… pour SR Linux) : sinon il est NON AUDITÉ.
  Sans cette signature, des notes lues avec `--driver eos` donnaient « conforme, code 0 » (aucune ligne
  douteuse pour l'analyse, rien à reprocher aux évaluateurs). Dans un fichier audité, une ligne de premier
  niveau dont le premier mot n'est pas connu du driver est lue mais listée en **information (lue, ambiguë)**,
  dans les trois sorties ; sans effet sur le verdict, et sans effet en direct (la configuration vient de
  l'équipement). Limite : quelques lignes de prose noyées dans une vraie configuration restent auditées, et
  signalées. Un fichier remplacé par un dossier ultérieur n'est jamais lu.
- **Les règles qui lisent l'état collecté sont non évaluables hors ligne** (`Check.needs` contient
  `interfaces` : `lan-en-ospf-passif`, `interface-avec-description`). Elles sont « non applicables » avec
  leur propre cause, **ÉTAT REQUIS (hors ligne)**, comptée à part dans la synthèse des trois sorties : ce n'est
  ni une règle hors sujet ni un trou d'un driver. Les règles de `security.yml` ne lisent que la configuration :
  aucune n'est perdue.
- Le rapport (terminal, JSON `source`, HTML) donne, pour chaque équipement, son driver et son fichier.

### Configuration structurée et règles dans les drivers (Phase A, v4)

**Pourquoi.** En v0.3.0, `compliance.py` lisait le TEXTE des configurations par expressions régulières
(836 lignes, trois syntaxes de constructeur mêlées). Résultat, mesuré : un bloc sans `exit` faisait
disparaître une interface du rapport, `no ip ospf passive` était lu comme `ip ospf passive`, un
`password` en double espace passait pour une absence de mot de passe. Depuis la Phase A, chaque driver
**analyse** sa configuration en arbre et ses règles lisent l'arbre : `compliance.py` n'est plus que le moteur
(un test statique, `tests/test_compliance_neutrality.py`, échoue si une syntaxe de constructeur y revient).

**`confparse.py`** (bibliothèque standard, neutre vis-à-vis des constructeurs) : trois syntaxes, un seul
résultat (`ParsedConfig`) : `parse_indented` (FRR, EOS), `parse_braces` (SR Linux, « info from running »),
`parse_set` (SR Linux, lignes `set / …`). Tous donnent la même **vue plate** (un chemin de mots par ligne
feuille, `ParsedConfig.select(...)`) : une règle SR Linux s'écrit une fois pour les deux syntaxes.
**Exigence : aucune ligne n'est ignorée en silence.** Chaque ligne de la source tombe dans exactement une
classe (blanc, commentaire, noeud, fermeture, brut, non conservée : la somme des classes égale le nombre de
lignes, testé), et tout ce qui est douteux produit un `ParseWarning` (texte tronqué et **secrets masqués**).

**Ce que le rapport dit d'une ligne douteuse** (jamais « conforme » sur une configuration qu'on n'a pas
entièrement lue ; trois sorties, JSON `status`) :

| Libellé | Cas | Effet |
|---|---|---|
| **ANALYSE INCOMPLÈTE** | une ligne n'a pas pu être lue (**NON LUE**), sans violation | code 1 au minimum |
| **STRUCTURE INCERTAINE** | ligne lue et évaluée, mais sa place est incertaine (accolade fermante manquante) | code 1 au minimum ; les violations s'affichent quand même |
| **NON AUDITÉ** | hors ligne, un fichier qui ressemble à une configuration n'a pas pu être lu | code 1 au minimum, compté à part |
| information | ligne lue mais ambiguë, ou entrée de dossier qui n'est pas une configuration | aucun |
| NON CONFORME | une violation réelle (jamais pour une ligne non lue : ce serait affirmer une violation non prouvée) | code 1 ou 2 |

**L'interface d'un driver pour ses règles** (`drivers/base.py`) :

```python
class MonDriver(Driver):
    CONFIG_CHECKS = {            # kind de règle YAML -> évaluateur
        "mon_kind": Check(fn, needs=frozenset({"config"})),   # + "interfaces" si fn lit le modèle collecté
    }
    CONFIG_FILENAMES = ("mon.conf",)      # nom reconnu par `check --config-dir`
    def parse_config(self, texte): ...    # -> ParsedConfig (confparse) ; ne lève jamais
```

`fn(rule, device, config) -> list[Violation]` lit `config` (l'arbre), jamais le texte. Les kinds neutres
(`line_present`, `line_absent` : l'expression régulière est dans la règle YAML ;
`interface_description_required` : lit le modèle) restent dans le moteur. Une règle qui cite dans `drivers:`
un driver qui n'implémente pas son kind est **refusée au chargement**. `compliance.check_one(règle,
équipement)` évalue une règle sur un équipement par le chemin complet (utile aux tests).

**Trois causes de « non applicable »**, comptées à part dans la synthèse :
« hors sujet » (la règle ne liste pas le driver : un choix), « **non implémenté par le driver X** » (la règle
le concerne mais il ne sait pas l'évaluer : un trou de couverture) et « **ÉTAT REQUIS (hors ligne)** » (hors
ligne seulement : la règle lit le modèle collecté, que des fichiers ne contiennent pas).

**Vue « voisin BGP effectif »** (`drivers/bgp_neighbors.py`, FRR et EOS). Un peer group porte des réglages
que ses membres héritent ; lire `neighbor PG remote-as N` comme un voisin donnait une fausse violation sur un
groupe sans membre, et un faux « conforme » silencieux sur les membres (qui n'ont pas de `remote-as`). Un
groupe n'est donc jamais évalué pour lui-même ; un membre est eBGP si son `remote-as`, ou celui de son groupe,
désigne un autre AS (ou `external`, FRR seulement : EOS refuse `external|internal`) ; un réglage posé sur le
membre **masque** celui du groupe ; une plage `bgp listen range … peer-group …` est un voisin eBGP virtuel qui
hérite de son groupe. Un constat nomme le membre avec son groupe (`192.0.2.5 (peer group PG-OPEN)`). Treize
configurations relevées en direct sur r3 et r4 (`tests/fixtures/peergroups/`) fixent le comportement.
Limites : peer groups SR Linux hors périmètre (pas de BGP sur r5) ; voisins sans numéro (`neighbor <iface>
interface …`) non lus.

**Le gel de la conformité** (`tests/golden/`). Les réponses de la v0.3.0 sur des configurations réelles, toutes
leurs mutations (une ligne retirée à la fois) et des sondes nommées : le moteur doit répondre pareil, constat
par constat. Un écart voulu n'entre jamais en bloc : il est présenté (cas, ancienne réponse, nouvelle
réponse, justification), validé, puis `tests/tools/golden.py replace` ne met à jour que ces entrées
(tracées dans `meta.revisions`) ; `add` ajoute un cas nouveau sans jamais écraser (`--current-code` pour une
capacité nouvelle, avec ses deux refus : pas d'écrasement, pas de code non commité).

## Modèle étendu : IPv6, VRF et sections collectées (Phase B2, v4)

**Ce qui est relevé en plus.** Adresses IPv6 des interfaces (globales dans `addresses6`, lien local à part dans
`link_local6`), table de routage IPv6, voisins OSPFv3 (`ospf6_neighbors`, à part des voisins OSPFv2), sessions et
préfixes BGP `ipv6 unicast` (`address_family`), et la **VRF** de chaque interface, route, session et préfixe BGP
(champ `vrf`, défaut `default`). Une route est identifiée par **(vrf, préfixe)** : le même préfixe dans deux VRF
est deux routes. Tout est relevé sur les trois labs en double pile (FRR, SR Linux, cEOS), sorties réelles dans
`tests/fixtures/dualstack/`.

**Commandes ajoutées à la liste blanche** (six noms logiques ; chacun validé avec la sortie réelle du driver avant
d'être ajouté). Trois traductions existantes sont élargies à toutes les VRF.

| Nom logique | FRR (`vtysh -c …`) | EOS (chaîne exacte) | SR Linux |
|---|---|---|---|
| `show interface json` | inchangée (contient déjà l'IPv6 et `vrfName`) | inchangée (sans IPv6 ni VRF) | inchangée (contient l'IPv6) |
| `show ipv6 interface json` | : | `show ipv6 interface \| json` | : |
| `show vrf json` | : | `show vrf \| json` | `info from state network-instance * interface * \| as json` |
| `show ip route json` (élargie) | `show ip route vrf all json` | `show ip route vrf all \| json` | `info from state network-instance * route-table \| as json` |
| `show ipv6 route json` | `show ipv6 route vrf all json` | `show ipv6 route vrf all \| json` | : (la table ci-dessus contient `ipv6-unicast`) |
| `show ipv6 ospf neighbor json` | `show ipv6 ospf6 neighbor json` | `show ospfv3 neighbor \| json` | : (la commande des voisins OSPF rend les instances v2 et v3) |
| `show bgp ipv6 unicast summary json`, `show bgp ipv6 unicast json` | idem | `show ipv6 bgp summary \| json`, `show ipv6 bgp \| json` | : (pas de BGP relevé) |

L'EOS passe de six à **douze** chaînes exactes (`ALLOWED_CLI`) ; l'ancienne `show ip route | json` n'est plus
autorisée. Chaque variante d'une chaîne (redirection, ajout, `tee`, second pipe, espaces, casse, `;`, retour à la
ligne, `&`, substitution, `vrf all` retiré ou remplacé) est refusée avant la connexion : un test par chaîne et par
variante.

**Sections collectées.** Chaque `DeviceState` dit quelles sections ont été **réellement relevées** (`collected` :
`interfaces`, `routes_v4`, `routes_v6`, `ospf_v2`, `ospf_v3`, `bgp_v4`, `bgp_v6`, `vrf`, `bgp_vrf`, `config`) et,
pour une section non relevée, pourquoi (`section_errors`). Une section **relevée mais vide** (r2 n'a pas de BGP : FRR
répond `{}` ou `{"warning": "Default BGP instance not found"}`) n'est pas une section **non relevée** (commande non
exécutée, réponse qui n'est pas du JSON, driver qui ne la lit pas) : la première donne des listes vides, la seconde
**NON ÉVALUABLE** (`assert`) ou un constat d'information « sections non comparées » (`diff`). Aucun driver ne relève
encore le BGP des VRF (`bgp_vrf`) : une assertion sur une session BGP d'une VRF est NON ÉVALUABLE. SR Linux ne relève
aucune session BGP (`bgp_v4`, `bgp_v6` absentes) : `bgp_session` sur r5 est NON ÉVALUABLE, jamais « aucune session ».

**Compatibilité.** Un snapshot de la v0.3.0 (sans `collected` ni `vrf`) se charge : il est lu comme un relevé de la VRF
`default` avec les sections de la v0.3.0 de son driver (test sur un vrai snapshot du lab mixte, de netcheck 0.3.0).
Comparé à un snapshot récent, `diff` compare ce qui est comparable et ne dit jamais « aucun changement » sur ce qu'il
n'a pas vu. Section relevée **avant** et non relevée **après** : perte de visibilité (souvent une collecte échouée
pendant l'intervention), constat **ATTENTION** par section et par équipement, donc `guard` ne rend jamais SUCCESS et
`monitor` passe en ATTENTION ; avec `--rollback-on attention`, le retour arrière se déclenche. Section relevée
seulement **après** (ancien snapshot contre un récent) : un constat d'information par équipement.

**`assert` et `diff`.** Paramètres `family` (`ipv4` | `ipv6` : OSPFv2 ou OSPFv3, famille de la table BGP ; déduite du
préfixe pour les routes et `path`, et de l'adresse du voisin pour une session BGP, **sans être contrôlée contre elle** :
un voisin IPv6 peut porter la famille IPv4, RFC 8950 qui remplace la RFC 5549) et `vrf` (défaut `default`) ; voir le tableau du format d'intent. `path` reste dans
la VRF de départ. Un next-hop IPv6 de **lien local** (`fe80::`) est résolu par la **paire (adresse, interface de
sortie)** : l'équipement dont une interface porte cette adresse **et** est sur le même lien (une adresse de l'une dans
un réseau de l'autre) ; l'adresse seule ne suffit jamais, la même `fe80::` pouvant exister sur plusieurs liens.
Introuvable ou ambigu : NON ÉVALUABLE, avec la raison. Les routes de lien local (`fe80::/10`) ne sont pas comparées
par `diff` (FRR n'en installe qu'une parmi celles des interfaces, au gré de leur ordre).

**Management.** Les interfaces de management et leurs routes sont exclues comme avant ; `management_vrfs` (clé de
l'inventaire, ex. `[mgmt]` pour l'instance réseau de gestion de SR Linux) exclut de même une VRF entière, ses
interfaces, ses routes et ses sessions BGP, dans `diff`, `assert` et `check`. Sur FRR, le périphérique d'une VRF
(`DEMO`), listé comme une interface sans adresse, n'est pas une interface du modèle.

**Limites connues.** OSPF (v2 et v3) n'est relevé que pour la VRF `default`. Une interface SR Linux dont les
sous-interfaces sont dans des VRF différentes est relevée une fois par VRF (même nom, VRF différente) ; une interface
passe d'une VRF à l'autre en « VRF modifiée », pas en « disparue ». Les règles de conformité restent sur la
configuration ; leur couverture IPv6 est décrite plus bas (Phase B3).

## Règles IPv6, objet des violations et dérogations (Phase B3, v4)

**Les trois silences IPv6 sont fermés** (avant B3, les règles ne disaient rien de : l'authentification OSPFv3
retirée, `::/0` autorisé en entrée, un préfixe IPv6 local autorisé en entrée). Chacun est testé par des mutations de
VRAIES configurations relevées sur les labs en double pile (`tests/test_ipv6_rules.py`), et le code des règles par
35 mutations, toutes détectées.

| Silence | Règle | Ce qui a changé |
|---|---|---|
| Authentification OSPFv3 | `ospf6-authentification` (FRR), `eos-ospf6-authentification-ipsec` (EOS), `srlinux-ospf6-authentification-keychain` (SR Linux), dans `netcheck/rules/security-ipv6.yml` | Toute interface OSPFv3 active (`ipv6 ospf6 area`, pas passive) doit être authentifiée. |
| `::/0` en entrée | `ebgp-pas-de-route-par-defaut` (FRR ; EOS depuis B4) | Lit aussi `match ipv6 address prefix-list` et les `ipv6 prefix-list` : une entrée `permit` dont le réseau est `::/0` (`le`/`ge` compris, écriture libre). |
| Préfixe local en entrée | `ebgp-pas-de-reinjection-de-prefixes-locaux` (FRR ; EOS depuis B4) | Compare aussi les préfixes IPv6 des `network` de l'`address-family ipv6 unicast`. |

Il n'existe **aucun mécanisme d'authentification OSPFv3 commun** aux trois constructeurs (constaté, pas supposé) :
FRR 10.2.1 n'a que l'en-tête d'authentification de la RFC 7166 (`key-id … key …` ou `keychain` ; `null` et `ipsec`
sont refusés par `vtysh -C`), EOS 4.34.8M n'a que l'IPsec (`ospfv3 authentication ipsec spi N sha1|md5 …`, `disabled`,
`null` et `encryption ipsec` refusés), et le schéma de SR Linux 26.7.2 n'offre que `authentication keychain`, que la
plateforme refuse pour une instance `ospf-v3`. Chaque règle évalue la même exigence dans la syntaxe de son driver ; le
lien r4–r5 des labs est donc un défaut connu, **couvert par une dérogation datée et jamais en retirant la règle**.

`security-ipv6.yml` est un fichier à part, à utiliser EN PLUS de `security.yml` : `check --rules security.yml --rules
security-ipv6.yml` (`--rules` est répétable pour `check` et `monitor` ; un identifiant en double entre deux fichiers
est refusé). Les fichiers de la v0.3.0 gardent ainsi exactement les règles que le gel de référence compare.

**SR Linux : une instance OSPF est jugée selon sa version.** Les règles OSPFv2 (authentification, point-à-point) ne lisent
plus les interfaces d'une instance `version ospf-v3` : avant B3, les interfaces de toutes les instances étaient
fusionnées par leur nom, et une keychain posée sur l'interface de l'instance OSPFv3 aurait masqué son absence dans
l'instance OSPFv2. Une instance sans ligne `version` est lue comme OSPFv2 (la v0.3.0 ne connaissait pas l'OSPFv3).

**Objet d'une violation (`Violation.subject`).** Chaque règle dit sur QUEL objet porte sa violation, sous une forme
exacte et stable (jamais un texte libre) : c'est ce que les dérogations visent. Un test par kind de règle
(`tests/test_violation_subjects.py`), et un garde-fou qui échoue si un kind est ajouté sans test d'objet. Le champ
`object` est dans le JSON de `check`.

| Kinds | Objet |
|---|---|
| OSPF (FRR, EOS, SR Linux, v2 et v3), `ospf_passive_on_interfaces`, `srlinux_interface_mtu_margin`, `interface_description_required` | le nom de l'interface (`eth2`, `Ethernet2`, `ethernet-1/1.0`) |
| BGP (mot de passe, GTSM, limite, politiques d'entrée et de sortie, `::/0`, réinjection) | l'IP du voisin (ou le réseau d'une plage dynamique) |
| `eos_management_api_disabled` | l'API (`http-commands`, `gnmi`, `netconf`) |
| `srlinux_login_banner_present` | `login-banner` |
| `line_present` | le motif de la règle |
| `line_absent` | la ligne trouvée, **secrets masqués** (jamais la valeur du secret) |

**Dérogations** (`netcheck/derogations.py`, `check --derogations FICHIER`, `monitor --derogations FICHIER`). Une
dérogation dit « cette violation précise est connue, voici pourquoi, qui l'a validée et jusqu'à quand » ; elle ne retire
jamais une règle.

```yaml
version: 1
derogations:
  - id: DER-LAB-FRR-001
    rule: ospf6-authentification        # identifiant exact d'une règle chargée
    targets:                            # paires (équipement, objet), correspondance EXACTE, sans regex
      - {device: r4, object: eth2}
      - {device: r5, object: eth1}
    justification: "..."                # obligatoire
    validated_by: "..."                 # obligatoire, texte libre
    validated_on: 2026-10-04            # date ISO, pas dans le futur
    expires: 2027-01-04                 # obligatoire, au plus 365 jours après validated_on
    references: ["https://..."]         # facultatif
```

- **Correspondance** : une violation est couverte quand sa règle, son équipement et son objet sont ceux d'une paire.
  Une violation sans objet ne peut pas être couverte. Le nom d'un objet diffère selon le constructeur : **un fichier
  par lab** (`derogations/lab.yml`, `lab-multivendor.yml`, `lab-ceos.yml`), avec les bonnes paires.
- **Sortie** : statut **DÉROGATION** dans les trois sorties (terminal, JSON, HTML), avec justification, validateur et
  expiration ; compté à part dans la synthèse (`summary.derogated`), **sans effet sur le code retour**. Chaque rapport
  indique le **chemin et l'empreinte SHA-256** du fichier utilisé.
- **Expirée** : elle ne couvre plus rien, la violation redevient active et le dit (« dérogation DER-… expirée le … : violation
  de nouveau active »). **Expire dans moins de 30 jours** : information, sans effet sur le code, pour que le
  renouvellement soit un acte conscient. **Orpheline** (aucune violation réelle sur une de ses paires, sur un équipement
  audité) : information.
- **Refus au chargement (code 3)** : règle inconnue, règle de gravité « critique » (jamais dérogeable), expiration absente
  ou à plus de 365 jours, validation dans le futur, paire (règle, équipement, objet) en double, `id` en double, clé inconnue,
  champ vide, YAML refusé par `safe_load`.
- **Horloge** : le moteur reçoit « aujourd'hui » en paramètre et n'appelle jamais l'horloge (un test le vérifie) ;
  `check --today AAAA-MM-JJ` audite « à une date donnée », de façon reproductible (les scénarios d'intégration l'utilisent :
  ils ne dépendent pas du calendrier). Sans `--today`, la date du jour.
- **Limite connue** : `validated_by` est du texte libre, que netcheck ne peut pas vérifier. Une signature du fichier est
  prévue en phase J.

Connu : `monitor --derogations` lit la date du jour (il n'a pas de `--today`).

## L'IPv6 n'est jamais un silence, `permit` seuls, politiques d'entrée EOS (Phase B4, v4)

**Information de couverture.** Si l'état relevé (adresse IPv6, voisin OSPFv3, session BGP `ipv6 unicast`, route IPv6 hors
lien local, management exclu) ou la configuration auditée (adresse ou préfixe IPv6, `router ospf6`, `address-family
ipv6`…) contient de l'IPv6, et qu'**aucune règle à évaluateur IPv6 ne s'applique à l'équipement**, `check` le dit :
« IPv6 configuré (r1, …), aucune règle IPv6 chargée pour ces équipements : l'authentification OSPFv3 n'est pas auditée.
Charge netcheck/rules/security-ipv6.yml en plus du fichier de règles ». Un évaluateur est « IPv6 » quand son driver le
déclare (`Check.ipv6` : les trois règles d'authentification OSPFv3) : la liste ne vit pas dans le moteur. Les deux règles
de politique d'entrée lisent bien les listes IPv6, mais ne comptent pas : `security.yml` seul laissait justement
l'authentification OSPFv3 sans règle.

| Sortie | Forme |
|---|---|
| Terminal | une ligne `information (couverture)` et un compteur dans la synthèse |
| JSON | `coverage_notes` (`kind`, `devices`, `text`) et `summary.coverage_notes`, **présents seulement** quand il y a une note |
| HTML | un paragraphe et un badge |
| `monitor` | mêmes rapports locaux (`check.json`, `check.html`) ; jamais une alerte |

C'est une **information** : aucun effet sur le code retour ni sur le statut (`CONFORME` reste `CONFORME`). Limites : une règle
`line_present`/`line_absent` dont le motif parle d'IPv6 n'est pas reconnue comme règle IPv6 ; et l'IPv6 écrit dans la
configuration d'une interface de management compte (le filtre du management ne s'applique qu'à l'état relevé).

**`permit` seuls, IPv4 comme IPv6.** Seules les entrées `permit` d'une prefix-list autorisent un préfixe. La v0.3.0
comptait aussi les `deny` IPv4 et signalait donc `deny 0.0.0.0/0` (le bon filtre) comme une autorisation, de même que
`deny <notre préfixe>` ; l'IPv4 est alignée sur l'IPv6 (B3). L'ordre des entrées n'est pas simulé (premier correspondant) :
un `permit` est signalé même précédé d'un `deny` plus large.

**EOS : les deux règles de politique d'entrée.** Depuis la v0.3.0, EOS n'avait ni règle « pas de route par défaut en entrée »
ni règle « pas de réinjection de nos préfixes en entrée » (un silence). Les règles `ebgp-pas-de-route-par-defaut` et
`ebgp-pas-de-reinjection-de-prefixes-locaux` sont maintenant `drivers: [frr, eos]` (mêmes kinds, mêmes textes de constat,
`drivers/ebgp_filters.py`), IPv4 et IPv6, avec le **voisin effectif** : un membre de peer group hérite de la
route-map d'entrée de son groupe, et son réglage propre masque celui du groupe **famille d'adresses par famille**
(`BgpView.lines_by_family`) ; une plage de voisins dynamiques hérite aussi de son groupe. Syntaxes relevées sur cEOS 4.34.8M
dans des sessions de configuration abandonnées :

| Objet | Ce que fait EOS |
|---|---|
| `ipv6 prefix-list` | **toujours en sous-mode** (`ipv6 prefix-list NOM` puis `seq N permit …` indenté) ; la forme sur une ligne est refusée (« Invalid input ») |
| `ip prefix-list` | sur **une ligne** OU en **sous-mode** ; dès qu'une liste IPv4 est saisie en sous-mode, EOS réécrit toutes les autres ainsi |
| `seq N` | facultatif à la saisie (affiché avec un numéro) |
| route-map en entrée | sous `router bgp` (IPv4) **ou** sous `address-family` ; EOS refuse la même ligne aux deux endroits (« Cannot configure route-map … while … is configured in mode … ») |
| `seq …` non indenté | appliqué à la liste ouverte, quelle que soit l'indentation : signalé comme les autres sous-commandes (ligne NON lue) |

Les deux formes de prefix-list sont lues. Seules les séquences `permit` d'un route-map comptent : `route-map X deny 5` +
une liste qui contient `0.0.0.0/0` est la manière classique de REFUSER la route par défaut, pas une faute.

**FRR aligné sur EOS.** Les deux évaluateurs partagent la même lecture des route-maps d'entrée
(`drivers/ebgp_filters.py`) : **tous** les route-maps d'entrée du voisin sont lus, par famille d'adresses (un voisin
actif en IPv4 et en IPv6 avec un route-map par famille n'en laisse plus passer un dangereux : avant, seul le premier
était lu), le réglage propre d'un membre de peer group ne masque celui de son groupe que dans sa famille, et les
séquences `deny` d'un route-map ne produisent aucune violation (`route-map X deny 5` + une liste qui contient `0.0.0.0/0`
est la manière classique de REFUSER la route par défaut). Zéro écart du gel : aucune entrée ne contient de séquence
`deny` ni de voisin à deux route-maps d'entrée.

**Limite connue.** Aucune des deux règles ne simule l'ordre des séquences d'un route-map ni des entrées d'une
prefix-list (premier correspondant) : un `permit` est signalé même précédé d'un `deny` plus large.

## Sécurité

- **C1 (lecture seule), à deux niveaux.** (1) `collector.ALLOWED_COMMANDS` est la liste des
  commandes *logiques* qui peuvent être demandées à un équipement ; vérifiée deux fois : sur tout
  `REQUIRED_COMMANDS` du driver avant même la connexion SSH, puis à nouveau avant l'envoi de
  chaque commande individuelle. (2) Depuis la Phase F, un driver peut déclarer `ALLOWED_CLI` : la
  liste des commandes CLI *réelles*, en **correspondance exacte** de la chaîne complète (le driver
  EOS : douze chaînes depuis la phase B2, suffixe `| json` compris). Le niveau 1 ne voit pas ce que `translate()`
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
| `bgp_session` | `neighbor` ; `state` (défaut `Established`), `min_prefixes_received`, `family`, `vrf` | la session existe (famille déduite de l'adresse du voisin si absente), dans l'état voulu, avec assez de préfixes |
| `ospf_neighbors` | `count` ; `state` (défaut `Full`), `family: ipv6` (OSPFv3) | **exactement** `count` voisins dans cet état |
| `route_present` | `prefix` ; `protocol`, `next_hop`, `interface`, `vrf` | route **sélectionnée** au préfixe EXACT (pas de LPM) dans la VRF, avec les attributs donnés (IPv4 ou IPv6, adresses comparées sans tenir compte de l'écriture) |
| `route_absent` | `prefix` ; `vrf` | aucune route sélectionnée à ce préfixe EXACT dans la VRF |
| `interface_up` | `interface` ; `vrf` | interface présente (dans la VRF si elle est donnée), administrativement et opérationnellement active |
| `path` | `prefix`, `via` (suite d'équipements après `device`) ; `mode: all\|any` (défaut `all`), `vrf` | le chemin logique calculé de saut en saut (IPv4 ou IPv6, dans la VRF de départ) |

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
injoignable, section non relevée, next-hop de lien local introuvable ou ambigu (Phase B2). En ECMP, `mode: all` exige que toutes les branches soient conformes, `any` qu'une
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
6. Règles YAML : toute règle de `rules/*.yml` dont le `kind` est propre à un constructeur
   (évaluateur dans `CONFIG_CHECKS` de son driver, point 12) doit porter `drivers: [<ce
   constructeur>]` (Phase D2) ; le moteur **refuse au chargement** une règle qui cite un driver
   n'implémentant pas son kind. Une règle qui ne lit que le modèle normalisé
   (`interface_description_required`) reste universelle, sans ce champ.
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
12. **Règles de configuration, dans le driver** (Phase A, v4 ; en v0.3.0 elles vivaient dans
    `compliance.py`, un jeu `eos_*` de +147 lignes en Phase F). Le driver fournit :
    `parse_config()` (une configuration analysée avec `confparse` : choisir `parse_indented`,
    `parse_braces` ou `parse_set` ; **chaque ligne que l'analyse ne sait pas classer doit produire un
    avertissement, jamais disparaître** ; si l'équipement lit selon le CONTEXTE et non l'indentation, comme
    FRR et EOS, signaler une sous-commande trouvée au premier niveau, voir `flag_misplaced_subcommands` ;
    un texte libre comme une bannière se déclare en `raw_blocks`), `CONFIG_CHECKS` (`{kind: Check(fn,
    needs)}` dans `drivers/<constructeur>_rules.py`, `needs` contenant `"interfaces"` si `fn` lit le
    modèle collecté, ce qui rend la règle « ÉTAT REQUIS » hors ligne), `CONFIG_FILENAMES` et
    `ROOT_KEYWORDS` (pour `check --config-dir` : le nom du fichier, et les premiers mots des lignes de
    premier niveau d'une vraie configuration, vérifiés contre toutes les configurations réelles du driver : un
    fichier de notes ne doit pas être audité). Les évaluateurs lisent l'arbre, jamais le texte ; les messages sont un contrat
    (le gel les compare). Si l'équipement a des peer groups, réutiliser `bgp_neighbors.BgpView` avec la
    syntaxe du constructeur (`Syntax`).
13. **Tests de la phase A pour un nouveau driver** : (a) des configurations **réelles** du driver dans le
    gel (`tests/tools/golden.py`, avec leurs mutations : `add --current-code`, jamais d'écrasement) ; (b) un
    test que toute sortie réelle ne produit aucun avertissement d'analyse ; (c) une règle par kind, avec
    sa preuve « pas vide » (retirer la ligne exigée la fait échouer) ; (d) si l'équipement a deux syntaxes
    pour la même configuration, une règle qui donne la même réponse dans les deux ; (e) l'équivalence
    hors ligne : les fichiers de démarrage du lab donnent le même verdict que le direct
    (`tests/test_config_dir_equivalence.py`) ; (f) les intents `intents/lab-<x>.yml` (état attendu).

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

**Mesure de la Phase A (v4), même exercice une version plus tard** : la syntaxe des constructeurs a quitté
`compliance.py`, qui passe de **836 à 397 lignes** (542 → 245 lignes de code, sans vides ni commentaires), et
vit dans les drivers :

| Fichier | Lignes | Rôle |
|---|---|---|
| `drivers/frr_rules.py` | 309 | 9 évaluateurs FRR, lus sur l'arbre |
| `drivers/eos_rules.py` | 202 | 5 évaluateurs EOS |
| `drivers/srlinux_rules.py` | 164 | 4 évaluateurs SR Linux, une seule règle pour les deux syntaxes |
| `drivers/bgp_neighbors.py` | 142 | vue du voisin BGP effectif, partagée FRR / EOS |
| `confparse.py` | 445 | analyse structurelle, neutre vis-à-vis des constructeurs |
| `configdir.py` | 153 | `check --config-dir` |

Ajouter un 4e constructeur ne touche donc plus `compliance.py` : un `<constructeur>_rules.py`, un
`parse_config` et deux lignes de registre (l'import et l'entrée de `drivers/registry.py`). Les tests passent de **695 (v0.3.0) à **.

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
