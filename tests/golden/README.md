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
