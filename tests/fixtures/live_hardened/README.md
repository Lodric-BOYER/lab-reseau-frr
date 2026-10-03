# Configurations relevées EN DIRECT sur les labs durcis (SPEC_v4, Phase A5)

Chaque fichier est le `running_config` d'un snapshot réel pris par `netcheck snapshot` sur un lab démarré à
froid (2026-10-03, `snapshots/v4a-ref-frr` et `v4a-ref-ceos`, locaux et hors Git) : r1 à r5 du lab FRR
(`frr_r1.txt` à `frr_r5.txt`) et le r4 Arista cEOS 4.34.8M du lab cEOS (`eos_r4.txt`). Le r5 SR Linux durci
du lab mixte est déjà dans `../r5_hardened/state.json`. Valeurs de lab uniquement.

Elles servent à PROUVER que `check --config-dir` donne, sur les fichiers de démarrage du dépôt (`configs/`,
`configs-multivendor/`, `configs-ceos/`), le même verdict que l'audit en direct : la configuration en cours
d'exécution (formatée par l'équipement) et le fichier de démarrage (écrit à la main) n'ont pas la même
forme, et les règles doivent pourtant répondre pareil (`tests/test_config_dir_equivalence.py`).
