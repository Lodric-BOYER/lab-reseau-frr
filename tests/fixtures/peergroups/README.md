# Peer groups BGP : configurations relevées en direct (SPEC_v4, Phase A4)

Chaque fichier est le `show running-config` COMPLET de l'équipement, relevé par `netcheck snapshot` (lecture
seule) pendant que le scénario était appliqué : r3 (FRR 10.2.1, AS 65001) pour `frr_*`, r4 (cEOS 4.34.8M,
AS 65002) pour `eos_*`. Les valeurs sont des valeurs de lab : mots de passe `lab-bgp-pg*` (en clair côté FRR,
en « type 7 » côté EOS), voisins fictifs sur 192.0.2.0/24 (RFC 5737). Le voisin eBGP réel du lab
(172.16.34.x) n'a jamais été touché : la session est restée `Established` et OSPF `Full` partout pendant
chaque scénario. Chaque scénario a été retiré ensuite, et la configuration est revenue à l'identique
(`running-config` strictement égale, diff `avant ↔ retour` sans aucun constat, fichiers de démarrage jamais
écrits).

| Fichier | Scénario | Ce qu'il contient |
|---|---|---|
| `*_s1_group.txt` | S1, tout sur le groupe | groupe `PG-TEST` (remote-as, mot de passe, GTSM, limite, route-maps) ; deux membres sans rien d'autre |
| `*_s2_override.txt` | S2, surcharge sur le membre | groupe `PG-OVR` ; un membre avec son propre mot de passe ; un membre avec son propre GTSM (2) et sa propre limite (20) |
| `*_s3_open_group.txt` | S3, groupe sans mot de passe | groupe `PG-OPEN` (remote-as seul) et un membre : le membre n'a aucun mot de passe |
| `frr_s4_external.txt` | S4, `remote-as external` / `internal` | voisins `external` et `internal`, groupe `PG-EXTERN` en `external` et un membre. FRR uniquement |
| `*_s5_orphan_group.txt` | S5, groupe sans membre | groupe `PG-ORPHAN` (remote-as, mot de passe) sans aucun membre : ce n'est pas un voisin |

## Faits constatés

- **Rendu FRR** : `neighbor <groupe> peer-group`, puis les options du groupe, puis les membres
  (`neighbor <ip> peer-group <groupe>`) ; les options de famille d'adresses (`maximum-prefix`,
  `route-map`) sont sous `address-family`, sous le nom du groupe ou du membre qui les porte.
- **Rendu EOS** : `neighbor <groupe> peer group`, les options du groupe, puis les membres
  (`neighbor <ip> peer group <groupe>`) ; pas de famille d'adresses pour ces options.
- **EOS refuse `remote-as external` et `remote-as internal`** (`% Invalid input`), sur un voisin comme sur
  un groupe : ces formes n'existent que sous FRR, d'où l'absence de S4 côté EOS.
- Retour : FRR et EOS retirent un membre avec `no neighbor <ip>` (surcharges comprises), puis le groupe avec
  `no neighbor <groupe> peer-group` (FRR) / `peer group` (EOS). Retirer seulement l'appartenance au groupe
  (`no neighbor <ip> peer group <groupe>`) laisse les surcharges du membre (constaté sur EOS).
