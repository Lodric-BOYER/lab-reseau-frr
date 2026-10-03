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
met à jour **ces seules mutations** (la commande refuse une cible qui n'est pas réellement en écart, et
refuse de tourner si `netcheck/` n'est pas commité). Chaque révision est tracée dans `meta.revisions`.
`add` ajoute un cas nouveau sans toucher aux autres.

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
