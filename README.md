# Lab réseau FRR : OSPF + eBGP + automatisation Python

Lab de routage multi-AS entièrement conteneurisé (containerlab + FRRouting), piloté par des scripts Python/Netmiko :
contrôle de santé, sauvegarde des configs et détection de dérive de configuration.
Il tourne sur un simple PC portable sous WSL2, sans aucun matériel réseau.

![Topologie du lab](docs/img/topologie.png)

| | |
|---|---|
| **Stack** | WSL2 (Ubuntu) · Docker 29 · containerlab 0.79 · FRRouting 10.2.1 · Python 3 · Netmiko 4.8 |
| **Routage** | OSPF (point-to-point, interfaces passives) dans chaque AS · eBGP filtré (prefix-list + route-map) entre AS65001 et AS65002 |
| **Automatisation** | `health.py` (état OSPF/BGP) · `backup.py` (sauvegardes + baseline) · `drift.py` (diff vs baseline, rapport Markdown) |
| **Rapport complet** | [docs/Rapport_Lab_Reseau_FRR.pdf](docs/Rapport_Lab_Reseau_FRR.pdf) : 28 pages, accessible aux non-spécialistes |

## Topologie

```
            AS65001 (OSPF area 0)                          AS65002 (OSPF area 0)
                                            eBGP
  pc1 ──── r1 ─────────── r3 ═══════════════════════════ r4 ─────────── r5 ──── pc2
            \            /        172.16.34.0/30
             \          /
              └── r2 ──┘
  LAN 192.168.1.0/24                                            LAN 192.168.2.0/24
```

| Lien | Réseau | Adresses |
|---|---|---|
| r1 eth1 ↔ r2 eth1 | 10.1.12.0/30 | r1 .1 / r2 .2 |
| r1 eth2 ↔ r3 eth1 | 10.1.13.0/30 | r1 .1 / r3 .2 |
| r2 eth2 ↔ r3 eth2 | 10.1.23.0/30 | r2 .1 / r3 .2 |
| r3 eth3 ↔ r4 eth1 (eBGP) | 172.16.34.0/30 | r3 .1 / r4 .2 |
| r4 eth2 ↔ r5 eth1 | 10.2.45.0/30 | r4 .1 / r5 .2 |
| LAN pc1 (r1 eth3) | 192.168.1.0/24 | r1 .1 / pc1 .10 |
| LAN pc2 (r5 eth2) | 192.168.2.0/24 | r5 .1 / pc2 .10 |
| Loopbacks AS65001 | 10.1.255.X/32 | r1 .1, r2 .2, r3 .3 |
| Loopbacks AS65002 | 10.2.255.X/32 | r4 .4, r5 .5 |
| Management (SSH) | 172.20.20.0/24 | r1 .11 … r5 .15, pc1 .21, pc2 .22 |

**Logique de routage**

- OSPF dans chaque AS : liens en `point-to-point` (adjacence immédiate, pas d'élection DR/BDR). LAN, loopbacks et lien eBGP sont en `passive` : annoncés, mais sans adjacence.
- eBGP entre r3 et r4. Chaque bord annonce son agrégat /16 et son LAN /24. L'agrégat s'appuie sur une route `Null0`, comme chez un opérateur.
- Filtrage entrant et sortant par `prefix-list` + `route-map`. FRR refuse d'échanger des routes eBGP sans politique (`ebgp-requires-policy`).
- r3 et r4 redistribuent les routes BGP dans OSPF : les routeurs internes les voient en externes (O E2).

## Arborescence

```
lab.clab.yml            topologie containerlab
docker/Dockerfile       image FRR 10.2.1 + SSH (compte netops)
configs/daemons         démons FRR activés
configs/rX/frr.conf     configuration de chaque routeur (montée dans le conteneur)
automation/             phase 2 : scripts Netmiko
```

---

## Phase 1 : le lab de routage

### 0. Préparer WSL2 (une seule fois)

Dans Windows, crée `C:\Users\<toi>\.wslconfig` pour que WSL ne mange pas toute la RAM :

```ini
[wsl2]
memory=4GB
processors=4
```

Puis PowerShell : `wsl --shutdown`, et relance Ubuntu. Dans Ubuntu (WSL) :

```bash
# Docker Engine natif dans WSL (plus fiable que Docker Desktop avec containerlab)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER      # puis ferme et rouvre le terminal

# containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"
```

> Travaille dans le système de fichiers Linux (`~/lab-reseau-frr`), pas dans `/mnt/c/...`, qui est lent et pose des soucis de permissions.

### 1. Construire l'image et déployer

```bash
cd ~/lab-reseau-frr
docker build -t frr-ssh:10.2.1 docker/
sudo containerlab deploy -t lab.clab.yml
```

containerlab affiche un tableau des 7 conteneurs (`clab-frr-lab-r1` …). Compte ~30 s pour la convergence OSPF + BGP.

### 2. Vérifier, du bas vers le haut

```bash
docker exec -it clab-frr-lab-r1 vtysh          # CLI type Cisco ; 'exit' pour sortir
```

| Commande (dans vtysh) | Sur | Attendu |
|---|---|---|
| `show interface brief` | tous | interfaces Up avec la bonne IP |
| `show ip ospf neighbor` | r1, r2, r3 | 2 voisins `Full/-` (r4 et r5 : 1) |
| `show ip route ospf` | r1 | 10.1.23.0/30 en ECMP (2 chemins), 10.2.0.0/16 et 192.168.2.0/24 via r3 |
| `show bgp ipv4 summary` | r3, r4 | voisin `Established`, PfxRcd = 2, PfxSnt = 2 |
| `show bgp ipv4` | r3 | 4 préfixes : 2 locaux (next-hop 0.0.0.0), 2 via AS 65002 |
| `show ip route` | r1 | routes externes marquées `O>*` ; sur r3, les routes BGP marquées `B>*` |

Test de bout en bout :

```bash
docker exec clab-frr-lab-pc1 ping -c3 192.168.2.10
docker exec clab-frr-lab-pc1 traceroute -n 192.168.2.10
```

Chemin attendu (testé) : `192.168.1.1 → 10.1.13.2 → 172.16.34.2 → 10.2.45.2 → 192.168.2.10`.

### 3. Exercices (du plus simple au plus formateur)

1. **Convergence OSPF** : coupe le lien r1-r3 (`docker exec clab-frr-lab-r1 ip link set eth2 down`) et lance un `ping` continu depuis pc1. Le trafic doit repasser par r2 après environ 40 s (dead-interval). Réduis ensuite ce délai avec `ip ospf dead-interval minimal hello-multiplier 4` puis avec BFD.
2. **Ingénierie de trafic OSPF** : remets le lien, puis mets `ip ospf cost 100` sur r1 eth2. Vérifie avec traceroute que le chemin passe par r2.
3. **Politique BGP** : sur r3, supprime `192.168.1.0/24` de `PL-EBGP-OUT`, puis `clear bgp ipv4 * soft out`. pc2 ne doit plus joindre pc1 : explique pourquoi.
4. **BFD sur eBGP** : `neighbor 172.16.34.2 bfd` sur r3 (et l'équivalent sur r4), puis `show bfd peers`. Coupe le lien et compare le temps de bascule.
5. **Capture Wireshark** : `sudo ip netns exec clab-frr-lab-r3 tcpdump -i eth3 -w /tmp/bgp.pcap`, puis `clear bgp ipv4 *` sur r3. Ouvre le pcap depuis Windows (`\\wsl$\Ubuntu\tmp\bgp.pcap`) et identifie OPEN, UPDATE et KEEPALIVE.
6. **Multihoming** (avancé) : ajoute un second lien eBGP r2-r4 dans `lab.clab.yml`, puis joue avec `local-preference` (sortant) et `as-path prepend` (entrant) pour choisir le lien principal.

> Les changements faits dans vtysh sont perdus au redéploiement. Pour garder une modification, copie-la dans `configs/rX/frr.conf`.

---

## Phase 2 : automatisation (NetDevOps)

Les routeurs exposent SSH sur le réseau de management. Les scripts se connectent en `netops` (non-root, membre du groupe `frrvty`) et exécutent `vtysh` à distance. **Lance-les depuis WSL**, pas depuis Python Windows : le réseau 172.20.20.0/24 n'est joignable que depuis WSL.

```bash
cd ~/lab-reseau-frr/automation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

| Script | Rôle | Code retour |
|---|---|---|
| `health.py` | voisins OSPF Full et sessions BGP comparés à `inventory.yml` (via les sorties JSON de FRR) | 0 OK / 1 KO |
| `backup.py [--baseline]` | running-config → `backups/<horodatage>/` ; `--baseline` fige la référence dans `baseline/` | 0 / 1 |
| `drift.py [--report f.md]` | diff running vs baseline, rapport Markdown en option | 0 conforme / 1 dérive / 2 erreur |

Tous acceptent `-r r1 r3` pour cibler des routeurs. Les connexions partent en parallèle (ThreadPoolExecutor) : un routeur en panne n'empêche pas de traiter les autres.

### Scénario de démo (testé)

```bash
python health.py                    # tout OK
python backup.py --baseline         # fige la référence

# Modification « sauvage » + panne simulée
docker exec clab-frr-lab-r2 vtysh -c 'conf t' -c 'interface eth1' -c 'ip ospf cost 50'
docker exec clab-frr-lab-r4 vtysh -c 'conf t' -c 'router bgp 65002' -c 'neighbor 172.16.34.1 shutdown'

python health.py                    # r3/r4 KO : BGP Active / Idle (Admin)
python drift.py --report drift_report.md
```

Sortie de `drift.py` :

```diff
=== r2 ===
@@ -6,4 +6,5 @@
  ip address 10.1.12.2/30
  ip ospf area 0
+ ip ospf cost 50
  ip ospf network point-to-point

=== r4 ===
@@ -24,4 +24,5 @@
  neighbor 172.16.34.1 description r3-AS65001
+ neighbor 172.16.34.1 shutdown
```

### Exercices phase 2

1. **Git** : `git init`, commit de `baseline/`, puis un commit à chaque `backup.py`. `git log -p backups/` donne l'historique des changements.
2. **Planification** : lance `drift.py` toutes les 15 minutes (cron dans WSL) et écris le rapport uniquement quand le code retour vaut 1.
3. **Remédiation** : écris `remediate.py`, qui transforme chaque ligne `+` du diff en `no <ligne>` (dans le bon contexte `interface`/`router`) et l'applique via `vtysh -c 'conf t' ...`. Relance ensuite `drift.py` pour prouver le retour à la conformité.
4. **Templates Jinja2** : génère les 5 `frr.conf` depuis un seul fichier YAML (plan d'adressage). C'est la base de l'infra-as-code.
5. **Nornir** : réécris `health.py` avec Nornir + nornir_netmiko, le standard pour passer à l'échelle.

---

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `permission denied ... docker.sock` | utilisateur pas dans le groupe docker | `sudo usermod -aG docker $USER`, puis rouvrir le terminal |
| OSPF bloqué en `Init`/`ExStart` | interface mal nommée ou IP absente | `show interface brief` ; vérifier les `endpoints` du YAML |
| BGP `Active` en permanence | pas de joignabilité r3 ↔ r4 | `ping 172.16.34.2` depuis r3 ; `show bgp neighbor` |
| BGP `Established` mais 0 préfixe | politique ou route absente du RIB | `show ip prefix-list` ; `network` exige une route existante |
| Netmiko `TCP connection ... failed` | sshd non démarré ou script lancé depuis Windows | `docker exec clab-frr-lab-r1 /usr/sbin/sshd` ; lancer depuis WSL |
| `% Can't open configuration file vtysh.conf` | droits du fichier (non bloquant) | déjà géré par le Dockerfile et filtré par les scripts |
| PC qui rame | RAM WSL trop large ou autres VM | baisser `memory` dans `.wslconfig` ; fermer les autres VM |

## Arrêt et nettoyage

```bash
sudo containerlab destroy -t lab.clab.yml --cleanup
```

---

*Validation : lab déployé et testé sur un PC portable Windows (WSL2, Docker 29.8, containerlab 0.79, FRR 10.2.1). Résultats vérifiés : convergence OSPF/BGP, ping et traceroute pc1 → pc2, scripts health/backup/drift en SSH non-root, détection d'une panne BGP et d'une dérive de configuration simulées.*

*Réalisé avec l'assistance de Claude (Anthropic) pour la conception, le code et la documentation. Le déploiement, les tests et la validation ont été faits sur ma machine. Le détail de la démarche est dans le rapport, section 2.4.*
