# Configurations relevées EN DIRECT sur les labs en double pile (SPEC_v4, Phase B1)

Chaque fichier est le `running_config` d'un snapshot réel pris par `netcheck snapshot` (lecture seule) sur un lab
démarré à froid, une fois la double pile convergée (OSPFv3 Full partout, eBGP IPv6 Established) : r1 à r5 du lab
FRR (`frr_r1.txt` à `frr_r5.txt`), le r4 Arista cEOS 4.34.8M du lab cEOS (`eos_r4.txt`) et le r5 Nokia SR Linux
26.7.2 du lab mixte (`srl_r5.txt`, sortie du driver : sections séparées par des marqueurs). Valeurs de lab uniquement.

Ils remplacent `live_hardened/` (relevés d'avant la double pile, conservés : ce sont de vraies configurations
d'avant la phase B) comme référence de « le fichier de démarrage donne le même verdict que le direct »
(`tests/test_config_dir_equivalence.py`) et du test qui rapproche le `config.cli` de r5 de sa configuration réelle
(`tests/test_confparse.py`).

**Phase B4, `eos_r4_inbound_lists.txt` et `eos_r4_inbound_peergroup.txt`** : le `show running-config` de r4 (cEOS) relevé
PENDANT le scénario C6 de `tests/integration_ceos.sh` (lecture seule ; configuration nominale modifiée puis restaurée,
retour prouvé par un diff à zéro constat et par l'empreinte de la startup-config). Le premier contient `permit
0.0.0.0/0 le 32` et `permit 10.2.0.0/16` dans `PL-EBGP-IN` et `permit ::/0 le 128` et `permit 2001:db8:2::/48` dans
`PL6-EBGP-IN` ; le second un peer group `PG-TEST` (route-map d'entrée `RM-TEST-IN` qui autorise `0.0.0.0/0` et
`192.168.2.0/24`) avec le membre fictif `192.0.2.77`. Seule la première ligne diffère de la sortie brute (l'écho de la
commande est retiré).
