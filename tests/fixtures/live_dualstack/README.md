# Configurations relevées EN DIRECT sur les labs en double pile (SPEC_v4, Phase B1)

Chaque fichier est le `running_config` d'un snapshot réel pris par `netcheck snapshot` (lecture seule) sur un lab
démarré à froid, une fois la double pile convergée (OSPFv3 Full partout, eBGP IPv6 Established) : r1 à r5 du lab
FRR (`frr_r1.txt` à `frr_r5.txt`), le r4 Arista cEOS 4.34.8M du lab cEOS (`eos_r4.txt`) et le r5 Nokia SR Linux
26.7.2 du lab mixte (`srl_r5.txt`, sortie du driver : sections séparées par des marqueurs). Valeurs de lab uniquement.

Ils remplacent `live_hardened/` (relevés d'avant la double pile, conservés : ce sont de vraies configurations
d'avant la phase B) comme référence de « le fichier de démarrage donne le même verdict que le direct »
(`tests/test_config_dir_equivalence.py`) et du test qui rapproche le `config.cli` de r5 de sa configuration réelle
(`tests/test_confparse.py`).
