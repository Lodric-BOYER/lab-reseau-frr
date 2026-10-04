# Gel de référence de la conformité (SPEC_v4, Phase A)

`compliance_default.json` et `compliance_security.json` enregistrent ce que le moteur de conformité
de **netcheck 0.3.0** (code du commit `b56a775`) répond, constat par constat, sur :

- les fixtures réelles (`tests/fixtures/`) : FRR, Nokia SR Linux, Arista EOS (nominal et dégradés) ;
- les copies figées des configurations de démarrage des labs (`inputs/`, instantané du dépôt à
  `b56a775`) : la configuration seule, sans modèle, comme le fournira `check --config-dir` ;
- pour chaque équipement, une mutation par ligne de configuration (suppression) et des sondes nommées
  (`probe:*` : mot de passe en clair, route par défaut, voisin supplémentaire, limite à 0...).

`tests/test_golden_compliance.py` recalcule tout avec le code courant et exige la même réponse.
`tests/test_golden_secrets.py` vérifie qu'aucune valeur de secret de lab n'est présente, non masquée,
dans ces fichiers `.json` (`inputs/` contient, lui, des configurations de lab réelles : valeurs de lab
uniquement, voir « Secrets du lab » du README).

**Ne régénérez pas ces fichiers pour faire passer un test.** `python tests/tools/golden.py record`
ne se justifie qu'avec le code de référence, ou pour une modification voulue des entrées. Un écart
après la refonte est une régression, ou un changement de comportement à justifier et à documenter
(c'est le cas voulu des peer groups, des voisins `remote-as external|internal` et des règles
« non implémentées par le driver »).

`python tests/tools/golden.py reference record|compare` fait la même chose sur les snapshots réels
des trois labs (`snapshots/v4a-ref-*`, hors Git).

## Comment un écart voulu entre dans le gel

Jamais en bloc. L'écart est présenté sous forme de liste (cas, réponse v0.3.0, nouvelle réponse,
justification), validé, puis `python tests/tools/golden.py replace <règles> --reason ... <cas>@<clé>...`
met à jour **ces seules entrées** : une mutation (`<cas>@<clé>`) ou la réponse de base d'un cas
(`<cas>@base`, nommée en premier si des mutations du même cas changent aussi ; la commande refuse une
cible qui n'est pas réellement en écart, et
refuse de tourner si `netcheck/` n'est pas commité). Chaque révision est tracée dans `meta.revisions`.
`add` ajoute un cas nouveau sans toucher aux autres, sans jamais écraser un cas gelé. Trois modes :
sans option (le moteur doit encore répondre comme la v0.3.0), `--reference-code <commit>` (scénarios évalués
par l'ancien code) et `--current-code` (capacité nouvelle, sans réponse de la v0.3.0 à préserver : évalué
par le code courant, qui doit être commité ; `meta.additions` garde le commit). Dans ce dernier cas, la
réponse gelée doit avoir été validée avant, et un test la compare aux attentes écrites à la main.

## Écarts voulus déjà validés

**A3a, FRR : 10 mutations, toutes « suppression d'une ligne `exit` »** (1 dans `default`, 9 dans
`security`). La v0.3.0 ne retrouvait un bloc d'interface que s'il se terminait par `exit`, et une
route-map sans `exit` absorbait la suivante. Le moteur lit les blocs par indentation.

| Règles | Cas (ligne) | v0.3.0 | Maintenant |
|---|---|---|---|
| default | `fixture:frr-r1` (31) | `lan-en-ospf-passif` à tort, code 1 | conforme |
| security | `fixture:frr-r1` (17, 24), `fixture:frr-r3` (24, 31), `fixture:frr-r4` (31) | une interface disparaît du rapport (faux négatif) | rapportée |
| security | `fixture:frr-r3` (66), `fixture:frr-r4` (59) | 2 violations `reinjection` inventées (faux positif) | aucune |
| security | `config:frr-r3` (52), `config:frr-r4` (43) | 2 violations inventées, **code 2** sur une config durcie | conforme, code 0 |

**Hors gel (entrées fabriquées, encodées dans `tests/test_compliance_engine.py`)** : `no ip ospf passive`
n'est plus lu comme `ip ospf passive` ; une description contenant ce texte n'est plus lue comme la
commande ; des espaces multiples dans `neighbor X password Y` ne donnent plus « sans mot de passe » ;
un fichier sans `exit` est lu entièrement.

**A3b, SR Linux : 2 mutations de `security.yml`, toutes deux la suppression d'une ligne d'accolade**
(une configuration corrompue : le moteur la signale aussi, voir « STRUCTURE INCERTAINE » et « NON LUE »).

| Cas (ligne) | v0.3.0 | Maintenant |
|---|---|---|
| `fixture:srlinux-r5` (64), un `}` supprimé après `interface ethernet-1/1.0` | seule la bannière est signalée, code 1 : le `passive true` de l'interface suivante était lu comme celui de ethernet-1/1.0 (faux négatif) | violation d'authentification haute + bannière, code 2 |
| `fixture:srlinux-r5-hardened` (64), `authentication {` supprimé | conforme, code 0 : une ligne `keychain X` était acceptée n'importe où dans le bloc | violation haute « aucune keychain référencée » ; schéma vérifié : `authentication { keychain X }` |

**A3c, EOS : aucun écart du gel.** Hors gel (anciens moteurs comparés sur des entrées fabriquées) : le texte
d'une bannière n'est plus lu comme de la configuration, et des espaces multiples dans
`neighbor X maximum-routes N` ne donnent plus « sans limite ».

## Phase B3 : cas double pile et troisième fichier de règles (ajouts, aucun écart)

Rien du gel existant ne bouge : les deux fichiers de la v0.3.0 reçoivent des cas **ajoutés** (`add --current-code`,
zéro ligne supprimée du gel), et les règles OSPFv3 ont leur propre fichier de règles, donc leur propre gel.

- **Cas ajoutés** (`default` et `security`) : `dualstack:frr-r1` à `frr-r5`, `dualstack:eos-r4`, `dualstack:srlinux-r5`
  (les `running-config` relevées en direct sur les labs en double pile, `tests/fixtures/live_dualstack/`, configuration
  seule, une mutation par ligne) et `lab:dualstack-frr|multivendor|ceos`. Capacité nouvelle (IPv6) : aucune réponse de la
  v0.3.0 à préserver, la réponse gelée est celle du code B3 (commit `baba43e`, enregistré dans `meta.additions`).
- **Sondes IPv6** : `probe:ipv6-prefix-list-default[-le128]@<ligne>` ajoute `permit ::/0` à une `ipv6 prefix-list`
  existante. Elles ne s'appliquent qu'aux entrées qui ont de telles lignes : aucun des 37 cas d'avant n'en a, leur
  nombre de mutations est inchangé.
- **`compliance_security-ipv6.json`** : le gel de `netcheck/rules/security-ipv6.yml` (règles d'authentification OSPFv3),
  créé par `python tests/tools/golden.py record-new security-ipv6` avec le code courant commité ; la commande refuse
  d'écraser un gel existant et de toucher aux fichiers de la v0.3.0. Tous les cas y entrent (47) : les 37 d'avant ne
  disent rien d'OSPFv3 (règles « hors sujet » ou conformes), les cas double pile portent le défaut du lien r4-r5.
- **Vérification** : `tests/test_golden_dualstack.py` compare ces réponses à des attentes écrites à la main d'après les
  configurations réelles (aucune violation hors lien r4-r5 ; supprimer l'authentification d'une interface fait apparaître la
  violation ; une route par défaut IPv6 ajoutée à la politique d'entrée est signalée).
