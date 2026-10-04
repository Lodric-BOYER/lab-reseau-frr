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
| **netcheck** (v0.3.0, [CHANGELOG](CHANGELOG.md)) | Validation de changements (état avant/après : routes, OSPF, BGP) · audit de conformité par règles YAML · rapports HTML · 3 drivers (FRR, Nokia SR Linux, Arista EOS) |
| **v2 (multi-constructeurs)** | `lab-multivendor.clab.yml` : mêmes r1-r4, r5 = Nokia SR Linux 26.7.2 · registre de drivers + champ `drivers:` par règle de conformité + identifiants par driver |
| **v3 (audit de sécurité)** | `netcheck/rules/security.yml` : authentification OSPF (message-digest / keychain SR Linux) + TCP-MD5/GTSM/`maximum-prefix` sur eBGP + bannière SR Linux · rapports avant/après dans `docs/audit/` · secrets masqués dans les 3 sorties (`netcheck/secrets.py`) · `assert` (état attendu) · `guard` : changements prévus (`--expect`) et retour arrière prouvé (`--rollback`) · `monitor` : surveillance planifiée, alertes webhook uniquement au changement de statut |
| **v3 (cEOS)** | `lab-cEOS.clab.yml` : r4 = Arista cEOS 4.34.8M (image importée localement) · driver `eos` (`enable()`, liste blanche exacte, secrets type 7 masqués) · 5 règles de sécurité EOS · lab testé : 26 + 38 contrôles |
| **Sécurité** | Commandes en lecture seule (liste blanche, à deux niveaux) · YAML chargé en `safe_load` · rapports protégés contre le XSS (testé) · secrets masqués dans toutes les sorties · valeurs de lab uniquement : voir « [Secrets du lab](#secrets-du-lab) » |
| **Licence** | [Apache-2.0](LICENSE) · voir « [Licence](#licence) » |

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
lab.clab.yml                    topologie containerlab (lab FRR)
lab-multivendor.clab.yml        topologie containerlab (lab v2 : FRR + Nokia SR Linux)
docker/Dockerfile               image FRR 10.2.1 + SSH (compte netops) ; clés d'hôte générées au démarrage (docker/entrypoint-sshkeys.sh)
lab-access/pin_hostkeys.sh      épingle les clés d'hôte d'un lab déployé (lues dans les conteneurs) dans le known_hosts de netcheck
configs/daemons                 démons FRR activés
configs/rX/frr.conf             configuration de chaque routeur FRR (montée dans le conteneur)
configs-multivendor/r5/         config de démarrage SR Linux (syntaxe "set", lab v2)
automation/                     phase 2 : scripts Netmiko (health, backup, drift)
automation/inventory.yml            inventaire du lab FRR
automation/inventory-multivendor.yml inventaire du lab v2 (driver par routeur)
automation/inventory-ceos.yml       inventaire du lab Arista cEOS (r4 = driver eos)
lab-cEOS.clab.yml               topologie containerlab (lab v3 : FRR + Arista cEOS ; image importée localement)
configs-ceos/r4/startup-config  configuration de démarrage de r4 (cEOS, syntaxe EOS)
automation/monitor.sh               enveloppe à planifier (cron/systemd) pour `netcheck monitor`
netcheck/                       validation de changement et conformité (snapshot/diff/check/assert/guard/monitor)
netcheck/rules/                 règles de conformité (default.yml) et d'audit de sécurité (security.yml + security-ipv6.yml)
intents/                        états attendus du réseau, pour `netcheck assert` (lab FRR, lab v2, lab cEOS)
docs/audit/                     rapports d'audit de sécurité avant/après durcissement (v3)
tests/                          fixtures et scénarios de bout en bout de netcheck
tests/expect/                   fichiers --expect de référence (changement prévu, effet de bord oublié)
tests/tools/webhook_recorder.py récepteur de webhook LOCAL (tests et scénarios, aucun appel externe)
tests/integration.sh                lab FRR (S1-S5, C1/C2, guard, A1/A2 assert, D1/D2 --expect et rollback, E1 monitor, H1 clés d'hôte)
tests/integration_multivendor.sh    lab v2 (S1, coupure r4<->r5, C1, A1/A2 assert, M1 monitor, H1 clés d'hôte)
tests/integration_ceos.sh           lab cEOS (S1, C1, A1, N1 mauvaise clé OSPF, N2 API exposée, G1 guard, M1 monitor, H1 clés d'hôte)
test_lab.sh                     scénario de bout en bout du lab FRR (phases 1 et 2), 28 contrôles
test_lab_multivendor.sh         scénario de bout en bout du lab v2 (topologie + routage)
test_lab_ceos.sh                scénario de bout en bout du lab cEOS (topologie, routage, durcissement), 26 contrôles
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

Les clés d'hôte SSH des routeurs sont générées **au démarrage de chaque conteneur** (pas à la construction de
l'image) : chaque routeur a la sienne, et elle change à chaque déploiement. netcheck vérifie ces clés : voir
[Clés d'hôte SSH et migration](#clés-dhôte-ssh-et-migration-v4-phase-c1).

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

## netcheck : validation de changement et conformité

Outil en ligne de commande (`netcheck/`) qui répond à deux questions : **« mon intervention
a-t-elle cassé quelque chose ? »** (snapshot avant/après + diff) et **« mes équipements
respectent-ils les règles de conception ? »** (audit de conformité contre des règles YAML).
Développé et testé sur ce lab, mais pensé pour s'étendre à d'autres constructeurs : voir
[netcheck/README.md](netcheck/README.md) pour l'architecture et le détail de sécurité.

> ⚠️ **N'utilisez netcheck sur un réseau réel qu'avec une autorisation écrite.** Même
> strictement en lecture seule (liste blanche de commandes, jamais de configuration), une
> découverte non autorisée d'un réseau qui ne vous appartient pas peut être illégale.

### Installation

```bash
cd ~/lab-reseau-frr/netcheck
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # ajoute pytest ; requirements.txt suffit en usage normal
```

Toutes les commandes s'utilisent avec `python -m netcheck`, lancées **depuis la racine du
dépôt** (comme les scripts de `automation/`, uniquement joignable depuis WSL).

### Les commandes

`snapshot`, `list`, `diff`, `check`, `guard`, `assert` et `monitor`. Les cinq premières sont
détaillées ci-dessous ; `assert` et `monitor` ont leur propre section plus bas (**état attendu**,
**surveillance planifiée**).

#### `snapshot <nom> [-d r1 r3] [--force]`

Interroge tous les équipements en parallèle, écrit `snapshots/<nom>/<équipement>.json`.

```
$ python -m netcheck snapshot avant
Snapshot 'avant' écrit dans snapshots/avant
  r1       OK
  r2       OK
  r3       OK
  r4       OK
  r5       OK
```

#### `list`

```
$ python -m netcheck list
Nom                  Horodatage             Équipements
avant                2026-09-28T16:49:25+00:00 5
```

#### `diff <avant> <après> [--json f.json] [--html f.html]`

Compare deux snapshots, classe les constats par gravité (CRITIQUE / ATTENTION / INFO).
Exemple réel, après un `ip ospf cost 100` sur l'interface de r1 vers r3 :

```
$ python -m netcheck diff avant apres
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Gravité   ┃ Équipement ┃ Catégorie ┃ Message                                 ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ATTENTION │ r1         │ next_hop  │ next-hop modifié pour 10.1.23.0/30 :    │
│           │            │           │ [('10.1.12.2', 'eth1'), ('10.1.13.2',   │
│           │            │           │ 'eth2')] -> [('10.1.12.2', 'eth1')]     │
│ ATTENTION │ r1         │ metric    │ métrique modifiée pour 10.1.255.3/32 :  │
│           │            │           │ 10 -> 20                                │
│ INFO      │ r1         │ config    │ --- avant                               │
│           │            │           │ +++ après                               │
│           │            │           │ @@ -14,4 +14,5 @@                       │
│           │            │           │   ip address 10.1.13.1/30               │
│           │            │           │   ip ospf area 0                        │
│           │            │           │ + ip ospf cost 100                      │
│           │            │           │   ip ospf network point-to-point        │
│           │            │           │  exit                                   │
└───────────┴────────────┴───────────┴─────────────────────────────────────────┘
Verdict : ATTENTION  (0 critique(s), 8 attention, 1 info)
```

(sortie réelle tronquée à 3 des 9 constats pour la lisibilité ici — les 6 autres sont des
`next_hop`/`metric` du même type, sur les préfixes qui empruntent désormais le chemin via r2).

Sans rien changer entre les deux snapshots :

```
$ python -m netcheck diff avant avant
Aucun constat.
Verdict : OK  (0 critique(s), 0 attention, 0 info)
```

#### `check [--snapshot nom] [--rules f.yml] [--json f.json] [--html f.html]`

Audite les configurations contre `netcheck/rules/default.yml` (8 règles), en direct ou hors
ligne (`--snapshot`, aucune connexion). Sur le lab dans son état nominal :

```
$ python -m netcheck check
Aucune non-conformité.
Conformité : CONFORME  (0 non-conformité(s))
```

Après avoir retiré `neighbor 172.16.34.2 route-map RM-EBGP-IN in` sur r3 :

```
$ python -m netcheck check
┏━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Gravité ┃ Équipement ┃ Règle                   ┃ Détail                      ┃
┡━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HAUTE   │ r3         │ ebgp-politique-entrante │ voisin eBGP 172.16.34.2     │
│         │            │                         │ sans route-map/prefix-list  │
│         │            │                         │ en entrée                   │
└─────────┴────────────┴─────────────────────────┴─────────────────────────────┘
Conformité : NON CONFORME  (1 non-conformité(s))
```

#### `guard --change script.sh [--wait 30] [--yes]`

Encadre automatiquement une intervention : snapshot avant, exécution de `script.sh` (c'est
**lui** qui modifie, jamais netcheck), attente de convergence (sondée en boucle, jamais une
pause fixe — délai maximum `--wait`), snapshot après, puis diff. `--yes` saute la confirmation
interactive (utile en script ou en CI). Les deux snapshots sont horodatés automatiquement.
`--expect` (changements prévus) et `--rollback` (retour arrière prouvé, codes retour 0 à 6) sont
décrits dans « [Changements attendus et retour arrière](#changements-attendus-et-retour-arrière-v3) ».
Depuis la v3, un script `--change` en échec rend au minimum le code 2.

#### `assert --intent f.yml [--snapshot s] [--json f] [--html f]`

Vérifie que le réseau est **dans l'état voulu**, sans référence « avant » : on déclare ce qui doit
être vrai (une session eBGP établie, exactement deux voisins OSPF, une route avec tel next-hop,
une interface active, un chemin traversant tels équipements) et netcheck le vérifie, en direct ou
sur un snapshot (hors ligne). Là où `diff` répond « qu'est-ce qui a changé ? », `assert` répond
« est-ce que ce qui doit être vrai l'est ? ».

```yaml
assertions:
  - id: chemin-r1-vers-lan-r5
    description: "Le trafic de r1 vers le LAN de pc2 passe par r3, r4 puis r5"
    device: r1
    type: path
    prefix: 192.168.2.0/24
    via: [r3, r4, r5]
    mode: all
```

Six types (`bgp_session`, `ospf_neighbors`, `route_present`, `route_absent`, `interface_up`,
`path`), évalués **uniquement sur le modèle normalisé** : les mêmes assertions fonctionnent sur
FRR, SR Linux et Arista EOS. Chaque assertion rend **OK**, **ÉCHEC** ou **NON ÉVALUABLE** (jamais
un OK silencieux). `path` calcule le chemin de saut en saut par *longest prefix match* ; un
**trou noir** (aucune route, ou route Null0) est un **ÉCHEC** (« trou noir sur r4 : … »), alors
que NON ÉVALUABLE est réservé aux limites de la méthode (boucle, 16 sauts dépassés, next-hop
inconnu). Format complet : [netcheck/README.md](netcheck/README.md#formats-de-fichiers--intent-assert-et-expect---expect).
Exemples réels : `intents/lab.yml`, `intents/lab-multivendor.yml`, `intents/lab-ceos.yml`.
Code retour : **0** tout OK, **2** au moins un ÉCHEC, **3** erreur d'usage (intent invalide).

```
$ python -m netcheck assert --intent intents/lab-ceos.yml -i automation/inventory-ceos.yml
…
Verdict : OK  (11 OK, 0 échec(s), 0 non évaluable(s))
```

#### `monitor --baseline <snapshot> [--intent f.yml] [--rules f.yml] [--confirm N]`

Surveillance à exécution unique, pour cron ou un timer systemd : statut global (le pire du diff,
des assertions et de la conformité), alerte par webhook **seulement quand le statut change**.
Lecture seule stricte. Voir « [Surveillance planifiée et alertes](#surveillance-planifiée-et-alertes-v3) ».

### Clés d'hôte SSH et migration (v4, phase C1)

**Avant la v0.4.0, netcheck acceptait n'importe quelle clé d'hôte** (un défaut de Netmiko, `ssh_strict=False`, jamais
surchargé) : un équipement imité sur le réseau de management était invisible. Maintenant la clé de chaque équipement
doit figurer dans un fichier `known_hosts` **dédié** à netcheck ; le `~/.ssh/known_hosts` de l'utilisateur n'est jamais
lu.

| Élément | Valeur |
|---|---|
| Fichier | `--known-hosts FICHIER`, sinon `NETCHECK_KNOWN_HOSTS`, sinon `~/.netcheck/known_hosts` (format OpenSSH ; refusé s'il est modifiable par d'autres comptes) |
| `--host-keys strict` (défaut) | clé inconnue : refusée (« clé d'hôte inconnue ») ; clé changée : refusée (« clé d'hôte CHANGÉE », les deux empreintes sont affichées) |
| `--host-keys accept-new` | **réservé au lab** : le premier contact enregistre la clé, puis la connexion se fait en strict ; une clé changée reste refusée. Refusé (code 3, avant toute connexion) si l'inventaire ne déclare pas `lab: true` ; avertit à chaque usage |
| Valeur « ignorer » | **n'existe pas** (`--host-keys ignore` est refusé par la CLI ; un test échoue si une politique qui accepte tout revient) |
| Variables | `NETCHECK_HOST_KEYS` (mode), `NETCHECK_KNOWN_HOSTS` (fichier) ; l'option de la CLI l'emporte |
| Commandes concernées | `snapshot`, `check` (en direct), `guard`, `assert` (en direct), `monitor` |

**Migration depuis la v0.3.0** (sans elle, toute collecte échoue avec « clé d'hôte inconnue ») :

1. **Vos équipements.** Obtenez l'empreinte par un canal de confiance (console, documentation, inventaire), puis
   épinglez la clé après l'avoir comparée :
   ```bash
   ssh-keyscan -t ed25519 192.0.2.10 > /tmp/cle.pub && ssh-keygen -lf /tmp/cle.pub   # comparez l'empreinte
   mkdir -p -m 700 ~/.netcheck && cat /tmp/cle.pub >> ~/.netcheck/known_hosts && chmod 600 ~/.netcheck/known_hosts
   ```
   (`ssh-keyscan` lit la clé par le réseau : ce n'est une vérification que si vous comparez l'empreinte à une source
   indépendante.)
2. **Le lab** (clés générées au démarrage des conteneurs, donc nouvelles à chaque déploiement). Après chaque
   `containerlab deploy` :
   ```bash
   bash lab-access/pin_hostkeys.sh frr            # ou multivendor, ceos
   export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
   ```
   Le script lit les clés **dans les conteneurs** (`docker exec`, pas le réseau) et refuse deux routeurs qui annoncent
   la même clé. L'image `frr-ssh` génère maintenant ses clés au démarrage : **reconstruisez-la**
   (`docker build -t frr-ssh:10.2.1 docker/`), sinon tous les routeurs FRR partagent la clé cuite dans l'ancienne image.
3. **Une clé « CHANGÉE »** n'est jamais à contourner : vérifiez l'équipement (réinstallation légitime ?), retirez
   l'ancienne entrée (`ssh-keygen -R 192.0.2.10 -f ~/.netcheck/known_hosts`) et épinglez la nouvelle.
4. **`monitor` planifié** : `automation/monitor.sh` lance netcheck avec le `HOME` du planificateur, donc
   `~/.netcheck/known_hosts` ; sinon ajoutez `--known-hosts /chemin/known_hosts` aux arguments.
   **Après un redéploiement du lab, les clés des conteneurs changent : relancez `lab-access/pin_hostkeys.sh`**
   (et reprenez une référence si le lab a changé). Sans cela, `monitor` passe en **ÉCHEC** (code 2, « équipement
   injoignable » : le détail, « clé d'hôte CHANGÉE », est dans le rapport local). C'est voulu : un changement de
   clé doit alerter, jamais être accepté en silence. Constaté en direct sur le lab FRR (clé de r1 changée : ÉCHEC,
   r1 injoignable ; clés réépinglées : OK) et rejoué par le scénario H1 des trois scripts d'intégration.

**Limite.** `automation/labtools.py` (scripts `health.py`, `backup.py`, `drift.py`, hors netcheck) garde
`AutoAddPolicy` : la vérification ne concerne que `netcheck`.

### Identifiants : variables, fichiers 0600 et source (v4, phase C2)

Le mot de passe d'un équipement peut venir d'une variable, d'un **fichier 0600** ou, en dernier, de l'inventaire.
Ordre de priorité, du plus spécifique au moins spécifique (à spécificité égale, la variable avant le fichier) :

| # | Source | Portée |
|---|---|---|
| 1 | `NETCHECK_<DRIVER>_USER` / `_PASS` (variable) | ce driver seulement (`NETCHECK_SRLINUX_PASS`, `NETCHECK_EOS_PASS`…) |
| 2 | `NETCHECK_<DRIVER>_USER_FILE` / `_PASS_FILE` (fichier) | ce driver seulement |
| 3 | `NETCHECK_USER` / `NETCHECK_PASS` (variable) | tous les drivers |
| 4 | `NETCHECK_USER_FILE` / `NETCHECK_PASS_FILE` (fichier) | tous les drivers |
| 5 | `LAB_USER` / `LAB_PASS` (variable historique) | tous les drivers |
| 6 | valeur du fichier d'inventaire | valeurs par défaut des images de lab (C11) |

(HashiCorp Vault s'insérera entre 5 et 6 à l'étape C3 : une variable ou un fichier posé par l'opérateur l'emporte
toujours.) Le niveau « driver » passe avant le niveau générique, **fichier ou non** : un `NETCHECK_PASS` posé pour
FRR n'écrase pas le `NETCHECK_SRLINUX_PASS_FILE` de r5 (la garantie de la v0.3 est conservée).

- **Fichier de secret** : texte brut, **une seule ligne** (la fin de ligne finale est retirée, rien d'autre). Refusé
  (code 3, avant toute connexion, sans jamais citer le contenu) s'il n'est pas un fichier régulier (un lien
  symbolique est refusé), s'il n'appartient pas à l'utilisateur courant, si ses droits ne sont pas **0600 ou 0400**,
  s'il est vide, de plus de 4 Ko ou de plusieurs lignes. Un fichier désigné mais refusé est **une erreur, jamais un
  repli silencieux** sur la valeur suivante :
  ```bash
  install -m 600 /dev/null ~/.netcheck-pass && printf '%s' 'mon-mot-de-passe' > ~/.netcheck-pass   # saisie hors historique à préférer
  NETCHECK_PASS_FILE=~/.netcheck-pass python -m netcheck snapshot avant -i mon-inventaire.yml
  ```
- **`SecretStr`** : le mot de passe d'un routeur n'est jamais une `str` ordinaire. `str()`, `repr()`, f-string,
  `json.dumps`, `yaml.dump`, `pickle` et `copy` ne donnent jamais la valeur ; la seule porte est `.reveal()`, appelée en
  un seul endroit (l'ouverture de la connexion). Sa valeur est inscrite dans un registre : tout message d'erreur de
  collecte, rapport ou alerte qui la contiendrait (une bibliothèque qui recopie le mot de passe dans son exception)
  est expurgé en `****`.
- **La source est dite, jamais la valeur** : une ligne « Identifiants, mot de passe : variable NETCHECK_PASS (r1, r2) ;
  inventaire (r3) » sur le terminal de `snapshot`, `check`, `assert` et `guard` ; dans le JSON (`credential_sources`)
  de `check` et `assert` ; dans le HTML de `check` et `assert` ; dans `meta.json` d'un snapshot ; dans le journal de
  `guard` ; dans `summary.json` des rapports de `monitor` (sans rien écrire sur la sortie d'erreur, que cron envoie par
  courriel). Rien en mode hors ligne (`diff`, `check --config-dir`, `check --snapshot`, `assert --snapshot` : aucun
  identifiant n'y est résolu, un fichier de secret absent n'y est donc jamais une erreur).
- **Test sentinelle** (`tests/test_secret_sentinel.py`) : une valeur connue sert de mot de passe par variable, par
  fichier puis par l'inventaire ; `snapshot`, `check`, `assert`, `monitor` et `guard` tournent de bout en bout, en
  réussite puis avec une exception qui recopie le mot de passe. La valeur n'apparaît nulle part : sorties, journaux,
  snapshots, rapports JSON et HTML, état et rapports de `monitor`, journal de `guard`, alerte webhook.
- **Limites.** Les valeurs de **moins de 8 caractères** ne sont pas retirées des textes par valeur (« admin » ou
  « netops » effaceraient ces mots partout, jusque dans « network-admin ») : seul `SecretStr` les protège. Seule la
  valeur exacte est cherchée (pas sa forme en base64 ou en pourcentage). Les mots de passe par défaut des images de
  lab restent en clair dans `automation/inventory*.yml` (C11) ; sur un vrai réseau, utilisez une variable ou un fichier.

### Codes retour

| Commande | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `diff` / `guard` | OK | ATTENTION | ÉCHEC (≥ 1 CRITIQUE) | erreur d'utilisation / snapshot manquant |
| `check` | conforme | non-conformité(s) moyenne/basse | non-conformité critique/haute | règles ou équipement introuvable |
| `snapshot` | tout OK | au moins un équipement injoignable | — | snapshot existant sans `--force` |
| `assert` | tout OK | — | au moins un ÉCHEC | intent invalide |
| `monitor` | statut OK | statut ATTENTION | statut ÉCHEC | refusé (4 : verrou tenu) |

**Une option invalide ou un argument manquant sort en code 3 pour toutes les commandes** (jamais le 2 d'argparse :
ici, 2 veut dire ÉCHEC, et un pipeline ou `monitor.sh` prendrait une faute de frappe pour une panne).

**Toute erreur d'usage sort en code 3, avec UNE ligne sur la sortie d'erreur (`Erreur : …`), jamais de trace.** C'est
une faute de l'opérateur, vue avant la moindre connexion : inventaire absent, illisible, mal formé (YAML invalide,
`routers` vide, `host` ou `device_type` manquant, driver inconnu, mot de passe écrit sans guillemets et lu comme un
nombre, `port` hors 1-65535) ; équipement inconnu avec `-d` ; fichier de règles, d'intent, de dérogations ou
d'attentes (`--expect`) absent, dossier, illisible, invalide, ou **vide** (zéro règle ou zéro assertion : rien ne serait
audité) ; snapshot absent ou corrompu ; nom de snapshot invalide (lettres, chiffres, `.`, `-`, `_`) ; options
incohérentes (`--config-dir` avec `--snapshot`, `--driver` sans `--config-dir`, `--today` sans `--derogations`,
`--host-keys`/`--known-hosts` avec une source hors ligne) ; fichier de sortie (`--json`, `--html`, `--state-file`) dans
un dossier absent ou non inscriptible, **vérifié avant le changement pour `guard`** ; `known_hosts` qui existe mais est
un dossier ou modifiable par d'autres comptes ; `guard` sans `--yes` quand l'entrée standard est fermée (cron). Un
message d'erreur YAML donne la ligne et la colonne, **jamais l'extrait** : un inventaire peut contenir un mot de passe.

**Un défaut interne de netcheck sort en code 70** (avec la trace, expurgée des secrets connus), jamais en 0, 1 ou 2 :
Python sortirait en code 1, lu à tort comme ATTENTION. 70 est distinct des codes d'usage (3) et de ceux de `guard` (0 à 6).
Si vous le voyez, ce n'est pas votre configuration : signalez-le.

`guard` a ses propres codes 4 à 6 (annulation réussie, annulation échouée, interrompu) : voir
« [Changements attendus et retour arrière](#changements-attendus-et-retour-arrière-v3) ».

### Écrire une règle de conformité

Une règle est une entrée YAML dans `netcheck/rules/default.yml` (ou un fichier passé à
`--rules`) :

```yaml
- id: identifiant-court-unique
  description: "Phrase humaine expliquant la règle."
  severity: critique | haute | moyenne | basse
  applies_to: all              # ou une liste explicite : [r3, r4]
  kind: line_present           # un des 6 types, voir le tableau ci-dessous
  pattern: "..."               # paramètre propre au kind
```

| `kind` | Paramètre(s) | Vérifie |
|---|---|---|
| `line_present` | `pattern` (regex) | la ligne doit exister dans la running-config |
| `line_absent` | `pattern` (regex) | la ligne ne doit apparaître nulle part |
| `bgp_neighbor_inbound_policy` | — | chaque voisin eBGP a une route-map/prefix-list en entrée |
| `bgp_neighbor_outbound_policy` | — | idem, en sortie |
| `ospf_passive_on_interfaces` | `pattern` (regex sur la description) | les interfaces concernées sont en `ip ospf passive` |
| `interface_description_required` | `exclude` (liste, optionnel) | toute interface avec IP, hors loopback, a une description |

Le fichier complet en tête de `netcheck/rules/default.yml` documente le format en détail. Les
règles sont chargées avec `yaml.safe_load` exclusivement : un fichier de règles malformé ou
contenant un tag Python (`!!python/...`) est refusé au chargement, jamais exécuté.

---

## Tester tout le lab en une commande

```bash
bash test_lab.sh            # teste tout et laisse le lab démarré
bash test_lab.sh --destroy  # teste tout puis détruit le lab
```

Le script enchaîne 28 contrôles automatiques et renvoie le code 0 si tout passe :

| Étape | Ce qui est vérifié |
|---|---|
| Prérequis | Docker sans sudo, containerlab, module venv de Python |
| Déploiement | construction de l'image, 7 conteneurs en état running |
| Routage | voisins OSPF Full sur chaque routeur, eBGP Established avec 2 préfixes dans chaque sens, route vers le LAN distant, ping et chemin exact pc1 → pc2 |
| Automatisation | environnement Python créé si besoin, `health.py`, `backup.py --baseline` et `drift.py` au vert |
| Pannes simulées | coût OSPF modifié sur r2 et session BGP coupée sur r4 : `health.py` et `drift.py` doivent les détecter, pc2 doit devenir injoignable |
| Retour à la normale | pannes annulées, session BGP rétablie, tous les contrôles de nouveau au vert |

`bash tests/integration.sh` fait de même pour netcheck : les scénarios S1 à S5 (diff), C1/C2
(conformité) et un `guard --change` de bout en bout, 30 contrôles, sur le lab déjà déployé.

## Lab multi-constructeurs (v2 : FRR + Nokia SR Linux)

Deuxième topologie, [`lab-multivendor.clab.yml`](lab-multivendor.clab.yml) : mêmes r1-r4 et
même adressage que le lab FRR (`configs/` **strictement inchangé**), mais r5 devient un vrai
équipement Nokia SR Linux (`ghcr.io/nokia/srlinux:26.7.2-519`) au lieu de FRR. Objectif :
vérifier que `netcheck` fonctionne réellement sur un lab hétérogène, pas seulement sur un
seul constructeur.

```
            AS65001 (OSPF area 0)                          AS65002 (OSPF area 0)
                                            eBGP
  pc1 ──── r1 ─────────── r3 ═══════════════════════════ r4 ─────────── r5 ──── pc2
            \            /        172.16.34.0/30                    (SR Linux)
             \          /
              └── r2 ──┘
  LAN 192.168.1.0/24                                            LAN 192.168.2.0/24
```

Réseau de management distinct (`172.20.21.0/24`) et nom de lab distinct
(`frr-lab-multivendor`) : les deux labs ne se mélangent jamais **et ne tournent jamais en même
temps** (même méthode de test des deux côtés : destroy le lab en cours avant de déployer
l'autre).

### Démarrage

```bash
sudo containerlab deploy -t lab-multivendor.clab.yml
```

r5 démarre depuis [`configs-multivendor/r5/config.cli`](configs-multivendor/r5/config.cli)
(syntaxe SR Linux `set`, appliquée dès le premier démarrage, sans intervention manuelle --
prouvé par plusieurs redéploiements à froid pendant le développement). Convergence OSPF
complète observée en ~25 s.

### Mesures réelles (WSL, 15 Gi de RAM disponible)

| | |
|---|---|
| Taille de l'image SR Linux | 752 789 953 octets (~718 Mo), vérifiée via l'API du registre GHCR avant le premier téléchargement |
| Temps de démarrage SR Linux | ~18 s entre `containerlab deploy` et une CLI `sr_cli` utilisable |
| RAM supplémentaire du lab mixte | ~1,9 Go, dont ~1,8 Go attribuables à r5 seul (mesurée par différence sur `free -h` ; `docker stats --no-stream` affiche 0B/0B pour r5 -- observé deux fois, sans source officielle confirmant un défaut connu, donc décrit ici comme une simple observation) |

### Deux pièges MTU (réellement rencontrés, pas anticipés)

**1. MTU du lien r4 ↔ r5.** La MTU par défaut d'un lien containerlab (veth) est 9500 octets ;
le châssis SR Linux de ce lab plafonne bien plus bas en pratique. Résultat observé : les
paquets DBD (Database Description) envoyés par FRR à 9500 étaient systématiquement rejetés
par SR Linux (compteur `Bad MTUs` non nul), l'adjacence restant bloquée en Exchange/ExStart
indéfiniment, sans erreur explicite côté FRR.

Point de vocabulaire important (corrigé après relecture) : **OSPF ne "négocie" pas le MTU, il
le contrôle.** Chaque routeur annonce sa propre MTU dans ses paquets DBD ; le voisin compare
cette valeur annoncée à *sa* MTU locale et rejette le paquet si l'annonce dépasse (RFC 2328,
section 10.6) -- ce n'est pas un accord négocié entre les deux MTU, mais un refus unilatéral
en cas de désaccord. `mtu-ignore` (contourner ce refus) est une extension propre à certains
constructeurs, **hors standard** : la RFC ne prévoit aucune façon officielle de l'ignorer.

Correctif retenu : fixer `mtu: 1500` (standard Ethernet) sur ce lien précis, dans
`lab-multivendor.clab.yml`, plutôt que du jumbo proche du plafond du châssis -- aligne les
deux côtés sans dépendre d'une limite matérielle propre à ce modèle particulier.

**2. `ip-mtu` doit rester strictement inférieur au `mtu` L2, d'au moins 14 octets.** Une fois
le MTU du lien aligné à 1500, la sous-interface SR Linux restait `down, reason
ip-mtu-too-large` tant que son `ip-mtu` (1500) n'était pas strictement inférieur au `mtu` L2
de l'interface porteuse. Correctif : `mtu 1514` sur l'interface L2, `ip-mtu 1500` sur la
sous-interface -- une marge de 14 octets, exactement la taille d'un en-tête Ethernet.
Constaté sur l'équipement réel, jamais dans la documentation officielle consultée : la règle
de conformité `srlinux-mtu-marge-suffisante` (netcheck) vérifie ce point en continu.

### Différences FRR / SR Linux qui comptent pour netcheck

| | FRR | SR Linux |
|---|---|---|
| CLI | `vtysh -c "..."`, impératif | `sr_cli -- "..."`, hiérarchique (datastores `show` / `info from state` / `info from running`) |
| Config texte | blocs `interface X ... exit`, à plat | blocs `interface X { ... }` imbriqués (JSON-like) |
| Next-hop d'une route | porté directement par la route | indirection à deux niveaux (`next-hop-group` -> `next-hop`), support ECMP natif |
| Type d'interface OSPF | `point-to-point` explicite (convention de ce lab) | défaut `broadcast` sur Ethernet -- `interface-type point-to-point` à positionner explicitement (règle `srlinux-ospf-point-to-point`) |
| Identifiants par défaut | `netops` / `netops` | `admin` / `NokiaSrl1!` (défaut de l'image containerlab, lab de développement uniquement) |

### Identifiants : variables par driver

`NETCHECK_USER`/`NETCHECK_PASS` s'appliquent à **tous** les routeurs, y compris ceux d'un
autre driver -- les positionner pour cibler FRR écraserait silencieusement les identifiants
SR Linux de r5, et inversement. Utiliser plutôt les variables spécifiques à un driver, plus
prioritaires que le générique :

```bash
export NETCHECK_SRLINUX_USER=admin
export NETCHECK_SRLINUX_PASS='NokiaSrl1!'
```

Ordre complet, du plus spécifique au moins spécifique : `NETCHECK_<DRIVER>_USER/PASS` >
`NETCHECK_USER/PASS` > `LAB_USER/PASS` > l'inventaire lui-même.

### Utiliser netcheck sur ce lab

```bash
python -m netcheck snapshot avant -i automation/inventory-multivendor.yml
python -m netcheck check -i automation/inventory-multivendor.yml
```

`bash test_lab_multivendor.sh` (topologie + routage, 15/15) et `bash
tests/integration_multivendor.sh` (netcheck sur les deux drivers à la fois : diff, coupure du
lien r4↔r5 vue des deux côtés, conformité, 13/13) couvrent ce lab de bout en bout -- voir
[netcheck/README.md](netcheck/README.md) pour le détail du registre de drivers.

## Lab Arista cEOS (v3 : FRR + Arista EOS)

Troisième constructeur, troisième topologie : [`lab-cEOS.clab.yml`](lab-cEOS.clab.yml). Mêmes
adresses et même logique que le lab FRR (`configs/` **strictement inchangé**), mais **r4 devient un
Arista cEOS** (`ceos:4.34.8M`), configuré par
[`configs-ceos/r4/startup-config`](configs-ceos/r4/startup-config). Nom de lab `frr-lab-ceos`,
réseau de management `172.20.22.0/24`. Un seul lab tourne à la fois (même règle que pour les deux
autres : `containerlab destroy` avant de déployer le suivant).

**Pourquoi r4.** C'est le routeur qui porte *tout* : eBGP avec r3 (TCP-MD5, GTSM, limite de routes,
prefix-lists, route-maps, agrégat `Null0`), OSPF avec r5 (MD5) et la redistribution BGP → OSPF.
L'interopérabilité avec FRR est donc testée des deux côtés, sur OSPF **et** sur BGP, et chaque
type de donnée du modèle (voisins OSPF, sessions et préfixes BGP, routes, interfaces) est
exercé par le nouveau driver.

### Obtenir l'image (à faire soi-même, jamais dans le dépôt)

Arista exige un compte gratuit sur arista.com pour télécharger l'image (documentation containerlab,
« Arista cEOS », <https://containerlab.dev/manual/kinds/ceos/>). Télécharger le fichier x86
`cEOS-lab-<version>.tar.xz` (testé ici avec **4.34.8M**), puis :

```bash
docker import cEOS-lab-4.34.8M.tar.xz ceos:4.34.8M
docker image inspect ceos:4.34.8M --format '{{.Architecture}} {{.Size}}'   # amd64 3105225191
```

**Version minimale : 4.32.0F**. Avant elle, cEOS exige cgroups v1 ; WSL2 récent est en cgroup v2
(`stat -fc %T /sys/fs/cgroup` affiche `cgroup2fs`), et l'image détecte v1 ou v2 seule depuis
4.32.0F. L'archive n'est **jamais commitée** : `.gitignore` ignore `*.tar`, `*.tar.xz`, `*.tar.gz`,
`*.tgz` et `*.txz` (vérifié avec `git check-ignore` sur le vrai nom du fichier). Les identifiants par
défaut de l'image sont `admin` / `admin` (lab uniquement, uniquement dans
`automation/inventory-ceos.yml` et `NETCHECK_EOS_USER` / `NETCHECK_EOS_PASS`).

### Démarrage et mesures réelles

```bash
bash test_lab_ceos.sh            # déploie, vérifie topologie + routage + durcissement (26 contrôles)
bash tests/integration_ceos.sh   # netcheck sur FRR + cEOS, avec tests négatifs (38 contrôles)
```

| Mesure (WSL2, 15 Gi de RAM) | Valeur |
|---|---|
| Image dans Docker | 3,11 Go (contenu 801 Mo ; `Architecture: i686` dans `show version` : image 32 bits, normal pour cEOS-lab) |
| `containerlab deploy` à froid | 26 à 27 s |
| OSPF Full + BGP Established sur cEOS | environ 36 s après le début du déploiement |
| RAM de r4 (`docker stats`) | 952 à 1014 MiB, soit **environ +1 GiB** ; lab complet environ +1,15 GiB (SR Linux : +1,8 Go) |

La doc containerlab signale que « When running under WSL2 ceos datapath might appear not working »
(contournement `iptables -P INPUT ACCEPT` daté de février 2022) : **inutile ici**, OSPF, BGP et le
ping de bout en bout fonctionnent sans lui sur cEOS 4.34.8M.

### Le durcissement est identique, et prouvé des deux côtés

OSPF MD5 vers r5, eBGP avec r3 en TCP-MD5 + GTSM + limite de routes. Preuves **négatives** rejouées
(chacune suivie d'un retour à l'état nominal) : mauvaise clé OSPF → adjacence perdue des deux
côtés ; mauvais mot de passe BGP **plus réinitialisation** → les deux côtés en `Connect` ; GTSM
retiré côté EOS → EOS envoie un TTL de 1 (`TTL is 1`) et r3 reste en `Idle` ; 14 préfixes annoncés
pour une limite de 10 → `Idle(MaxPath)`, « Put into idle state forever ». **Aucune API de gestion**
(eAPI, gNMI, NETCONF) n'est activée : seul SSH écoute (et BGP), vérifié par `ss -ltn` dans le
conteneur.

### Différences FRR / SR Linux / EOS qui comptent pour netcheck

| | FRR | SR Linux | Arista EOS |
|---|---|---|---|
| Accès | `vtysh -c` | `sr_cli --` | SSH, Netmiko `arista_eos`, **mode utilisateur (`r4>`) : `enable()` obligatoire** pour `show running-config` |
| Sorties structurées | `... json` | `... \| as json` | `... \| json` |
| Config texte | blocs `... exit` | accolades imbriquées | blocs **indentés**, séparateur `!` |
| Secrets | clair | `$aes1$...` | **« type 7 » réversible** (`md5 7 <hash>`, `password 7 <hash>`), `secret sha512 $6$...` ; le hash est déterministe (même clé, même hash) |
| Réinitialiser une session BGP | `clear bgp <ip>` | — | **`clear ip bgp <ip>`** (`clear ip bgp neighbor <ip>` est refusé) |
| GTSM | `ttl-security hops N` | — | `ttl maximum-hops N` (envoie un TTL de 255) |
| Limite de routes BGP | `maximum-prefix N` | — | `maximum-routes N` — **voir ci-dessous** |
| Route de rejet | nexthop `blackhole` | — | `routeType: dropRoute`, `vias: []` (mais `directlyConnected: true`, trompeur) |
| Interface de management | `eth0` | `mgmt0` | `Management0` (+ son sous-réseau connecté) |

**`maximum-routes` (EOS) n'est PAS strictement équivalent à `maximum-prefix` (FRR).** EOS compte
les routes **reçues, avant la politique d'entrée** (constaté : la limite est dépassée même quand la
politique n'en accepte que 2 sur 14) ; FRR compte par défaut les préfixes **acceptés après filtre**,
sauf avec `maximum-prefix N force` (documentation FRR, « BGP — FRR latest documentation »,
<https://docs.frrouting.org/en/stable-8.2/bgp.html>). L'effet de protection est le même, le seuil ne
l'est pas : une valeur de 10 n'a pas la même marge sur les deux constructeurs.

**Deux pièges constatés en direct.** (1) Une session BGP déjà établie **garde son socket** quand on
change le mot de passe ou le GTSM : sans réinitialisation, un test « mauvais mot de passe » ne prouve
rien. (2) EOS écrit ses secrets en type 7 : le masquage de `netcheck/secrets.py` laissait fuir
**les trois formes** (`md5 7`, `password 7`, `secret sha512`) avant la Phase F ; il applique
maintenant une règle générique (mot-clé, type facultatif, valeur ; tout est masqué sauf le
mot-clé), avec des tests sur les lignes réelles et un test qui échoue si un hash survit.

### Utiliser netcheck sur ce lab

```bash
python -m netcheck snapshot avant -i automation/inventory-ceos.yml
python -m netcheck check --rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml \
    --derogations derogations/lab-ceos.yml -i automation/inventory-ceos.yml
python -m netcheck assert --intent intents/lab-ceos.yml -i automation/inventory-ceos.yml
```

`check` applique cinq règles `drivers: [eos]` à r4 (authentification OSPF, mot de passe BGP,
GTSM, limite de routes, **API de gestion exposée**), l'authentification OSPFv3 d'EOS (`security-ipv6.yml`) et, depuis la phase
B4, les deux règles de **politique d'entrée** partagées avec FRR (pas de route par défaut, pas de réinjection de nos
préfixes, IPv4 et IPv6, peer groups compris) ; les règles FRR et SR Linux y sont « non
applicables » (jamais une fausse violation), et inversement. `assert` utilise les mêmes types
d'assertion que sur les autres labs, y compris `path`, qui traverse r4 : une route `dropRoute`
(Null0) y est un **trou noir → ÉCHEC**, même sémantique qu'en Phase C.

**Liste blanche à deux niveaux.** La liste blanche *logique* du collecteur n'a pas changé. Le
driver EOS ajoute une liste blanche en **correspondance exacte de la commande complète**, suffixe
`| json` compris : seules six chaînes pouvaient partir (douze depuis la phase B2, voir `netcheck/README.md`) (`show interfaces | json`, `show ip route |
json`, `show ip ospf neighbor | json`, `show ip bgp summary | json`, `show ip bgp | json`, `show
running-config`). Une redirection (`>`), un ajout (`>>`), `tee`, un second pipe, une variante
d'espacement ou de casse sont refusés **avant la connexion**, un test par cas. `enable()` est la
méthode Netmiko, jamais `send_command("enable")`.

### Ce que ce troisième constructeur a changé hors de `drivers/`

C'est le vrai test de l'architecture. Mesure honnête (`git diff`, lignes ajoutées) :

| Fichier | Changement |
|---|---|
| `netcheck/drivers/eos.py` | **nouveau**, 192 lignes : tout le dialecte EOS |
| `netcheck/drivers/base.py` | +19 : deux crochets génériques (`NEEDS_ENABLE`, `ALLOWED_CLI` + `check_cli`), sans effet pour FRR et SR Linux |
| `netcheck/collector.py` | +12 : une ligne de registre, l'appel à `enable()`, le contrôle exact de la commande CLI |
| `netcheck/compliance.py` | **+147** : cinq évaluateurs `eos_*` et leur analyse de blocs indentés — la syntaxe d'un constructeur vit encore dans ce fichier (c'était déjà vrai de SR Linux) |
| `netcheck/secrets.py` | +35 / −11 : règle générique de masquage (faille réelle trouvée, voir plus haut) |
| `netcheck/rules/security.yml` | +77 : cinq règles EOS |
| `automation/inventory-ceos.yml`, `intents/lab-ceos.yml` | nouveaux (aucun code : les identifiants par driver existaient déjà) |

**Rien d'autre** : `model.py`, `diff.py`, `assertions.py`, `management.py`, `report.py`, `guard.py`,
`monitor.py`, `cli.py`, `inventory.py` et les gabarits n'ont pas bougé d'une ligne. `diff`, `assert`
(trou noir compris), `guard --rollback` et `monitor` fonctionnent sur EOS sans modification. Le
point faible reste `compliance.py` : tant que les évaluateurs de texte de configuration y vivent,
chaque constructeur y ajoute son dialecte.

## Double pile IPv6 et VRF de démonstration (v4, phase B1)

Les trois labs tournent en double pile IPv4 / IPv6 (adressage de documentation `2001:db8::/32`, RFC 3849) et r2
porte une VRF de démonstration. Les configurations existantes (FRR, EOS, SR Linux) sont **inchangées** : B1 n'y ajoute que des lignes (+247 lignes dans 11 fichiers ; une seule ligne existante change, `ospf6d=no` devient `ospf6d=yes`).

| Objet | IPv4 existant | IPv6 |
|---|---|---|
| Loopbacks AS65001 / AS65002 | 10.1.255.1-3 / 10.2.255.4-5 | `2001:db8:1:ff::1-3` / `2001:db8:2:ff::4-5` (/128) |
| Liens point à point (/127, RFC 6164) | 10.1.12.0, 10.1.13.0, 10.1.23.0, 172.16.34.0, 10.2.45.0 (/30) | `2001:db8:1:12::`, `1:13::`, `1:23::`, `2001:db8:34::`, `2001:db8:2:45::` : adresse IPv4 `.1` devient `::2`, `.2` devient `::3` |
| LAN pc1 / pc2 | 192.168.1.0/24, 192.168.2.0/24 | `2001:db8:a1::/64`, `2001:db8:a2::/64` |
| Agrégats eBGP (route de rejet `Null0`) | 10.1.0.0/16, 10.2.0.0/16 | `2001:db8:1::/48` (r3), `2001:db8:2::/48` (r4) |
| VRF `DEMO` sur r2 | 10.99.2.0/24, route de rejet 10.99.9.0/24 | `2001:db8:99::/64`, route de rejet `2001:db8:99:9::/64` |

- **IGP** : OSPFv3 (aire 0) sur tous les routeurs, `redistribute bgp` sur r3 et r4, comme en IPv4.
- **BGP** : une session IPv6 **distincte** r3 ↔ r4 (`2001:db8:34::3` ↔ `::2`), avec le même durcissement que l'IPv4
  (TCP-MD5, GTSM, limite de préfixes, route-maps entrante et sortante). Dans l'IPv4 AF, `no neighbor <v6> activate`.
- **Authentification OSPFv3 : une dérogation constatée.** FRR utilise l'en-tête d'authentification de la RFC 7166
  (`ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key …`) sur les **trois liens FRR–FRR** de l'AS65001.
  Le lien r4–r5 n'est **pas authentifié** : SR Linux 26.7.2 refuse (« Authentication keychain not supported on
  ospf-v3 », constaté par `commit validate`), EOS 4.34.8M n'a que `ospfv3 authentication ipsec spi …` (6 formes essayées)
  et FRR n'a pas d'IPsec : aucun mécanisme commun. Les fichiers `configs/r4` et `configs/r5` étant partagés entre les
  labs, le lien est sans authentification dans les trois. La règle d'audit correspondante
  (`netcheck/rules/security-ipv6.yml`) le signale, et la dérogation datée de chaque lab (`derogations/*.yml`, expire le
  2027-01-04) le couvre : voir `netcheck/README.md`, « Règles IPv6, objet des violations et dérogations ».
- **VRF `DEMO` (r2)** : un VRF Linux (table 100) avec une interface `dum-demo` (dummy) et deux routes de rejet, créés
  par les `exec` de containerlab après le démarrage de FRR (vérifié : FRR passe le VRF de « inactive » à actif dès
  sa création). r2 est un routeur de transit sans LAN ni eBGP et il est en FRR dans les trois labs : aucun chemin de
  bout en bout n'est touché. Aucune session BGP n'est placée dans la VRF.

**Contrôles** : `test_lab.sh` passe de 28 à **47** contrôles, `test_lab_multivendor.sh` de 15 à **28**,
`test_lab_ceos.sh` de 26 à **44** (OSPFv3 Full, authentification RFC 7166, BGP IPv6, `ping6`, chemin IPv6, VRF,
durcissement IPv6 des deux côtés, coupure de l'IPv6 seul sur le lab FRR). Les scripts d'intégration de netcheck
(80, 27 et 38 contrôles en B1 ; 117, 47 et 72 en B4 ; **128, 59 et 83 depuis la phase C1**, qui ajoute le scénario H1 des clés d'hôte) sont verts, rejoués à froid. `automation/health.py` lit OSPFv3 et BGP IPv6 quand l'inventaire
déclare `ospf6_neighbors` et `bgp6_peers`.

**Mesures** (démarrage à froid, 3 essais par lab, convergence comptée depuis la fin du déploiement, sonde à 1 s) :

| Lab | Référence IPv4 | Double pile : IPv4 / IPv6 | RAM des conteneurs |
|---|---|---|---|
| FRR | 16, 16, 15 s | 16, 16, 15 s / 17, 17, 16 s | 147 → 166 Mo (`ospf6d` ≈ 5 Mo par routeur) |
| Mixte (SR Linux) | 11, 11, 11 s (déploiement 15-16 s) | 14, 15, 15 s (déploiement 23 s) / 5, 5, 5 s | WSL ≈ 3,12 Go, inchangée |
| cEOS | 14, 18, 13 s (déploiement 22-23 s) | 13, 14, 13 s (déploiement 26-32 s) / 14, 17, 14 s | WSL ≈ 2,2 Go, inchangée |

Sur le lab FRR, la double pile ne ralentit pas l'IPv4 et l'IPv6 converge une seconde après. Sur le lab mixte, le
déploiement dure environ 7 s de plus et l'IPv4 converge 3 à 4 s plus tard (cause non cherchée) ; sur le lab cEOS, le
déploiement dure 4 à 9 s de plus. La RAM utilisée par WSL ne bouge pas de façon mesurable.

**Ce que netcheck voit depuis la phase B2** : le modèle contient l'IPv6 (adresses, routes, voisins OSPFv3, BGP
`ipv6 unicast`) et la VRF de chaque interface, route et session ; `diff`, `assert` (dont `path` en IPv6) et leurs
sections collectées sont décrits dans `netcheck/README.md`. **Depuis la phase B3**, les règles vérifient aussi les trois
points IPv6 qu'elles ignoraient (authentification OSPFv3, `::/0` autorisé en entrée, préfixe local autorisé en entrée) :
un lab double pile n'est plus « conforme » sans qu'ils aient été vérifiés. Le seul défaut restant, le lien r4–r5 en
OSPFv3 sans authentification, est une dérogation datée (voir ci-dessus). Une seule adaptation de code a été nécessaire en B1 : le driver SR Linux ne
compte que les instances OSPFv2 (`"version": "ospf-v2"`) dans ses voisins OSPF, sinon le voisin OSPFv3 de r5 était
compté comme un second voisin OSPFv2.

## Audit de sécurité (v3)

`netcheck/rules/security.yml` durcit les deux labs (authentification OSPF, TCP-MD5 + GTSM +
`maximum-prefix` sur eBGP, bannière SR Linux), distinct de `default.yml` (bonnes pratiques de
conception, inchangé). Rapports avant/après dans [`docs/audit/`](docs/audit/) : `avant-*`
(lab non durci, Phase A -- **non conforme** volontairement, c'est le point de départ) et
`apres-*` (lab durci, Phase B -- **conforme** sur les deux labs).

Depuis la phase B3, l'audit des labs en double pile utilise **deux fichiers de règles** (`--rules` est répétable) :
`security.yml` (v0.3.0) **et** `security-ipv6.yml` (authentification OSPFv3), et la dérogation datée du lab pour le seul
défaut connu (lien r4–r5). Avec `security.yml` seul, `check` le dit : « IPv6 configuré, aucune règle IPv6 chargée »
(information, dans les trois sorties ; voir `netcheck/README.md`).

```bash
python -m netcheck check --rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml \
    --derogations derogations/lab.yml
python -m netcheck check --rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml \
    --derogations derogations/lab-multivendor.yml -i automation/inventory-multivendor.yml
python -m netcheck check --rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml \
    --derogations derogations/lab-ceos.yml -i automation/inventory-ceos.yml
```

**Le rapport avant/après** (`docs/audit/`, fichiers `.html` autonomes et `.json`) : même règles,
même commande, avant puis après le durcissement de la Phase B.

| Lab | Avant (`avant-*`) | Après (`apres-*`) |
|---|---|---|
| FRR | **NON CONFORME** : 14 non-conformités (10 haute, 4 moyenne ; 8 OSPF, 6 BGP) | **CONFORME** : 0 |
| Mixte FRR + SR Linux | **NON CONFORME** : 15 (10 haute, 4 moyenne, 1 basse ; 8 OSPF, 6 BGP, 1 accès : la bannière SR Linux) | **CONFORME** : 0 |

Ces rapports sont des **preuves datées**, produites par netcheck 0.2.0 sur les labs de l'époque :
ils ne sont pas régénérés (le lab « avant » n'existe plus, il a été durci). Le lab Arista cEOS est
né durci : il n'a pas de rapport « avant », mais ses preuves négatives sont rejouées par
`tests/integration_ceos.sh` (mauvaise clé OSPF, API de gestion exposée, route par défaut et préfixe
local autorisés en entrée), et `security.yml` compte cinq règles `drivers: [eos]` et deux règles de politique d'entrée
communes à FRR et EOS. Les secrets de ce dépôt sont décrits dans « [Secrets du lab](#secrets-du-lab) ».

### Ce que l'authentification OSPF et TCP-MD5 protègent réellement (et ce qu'elles ne protègent pas)

Les deux mécanismes (authentification OSPF message-digest, RFC 2328 Annexe D ; TCP-MD5 pour
BGP, RFC 2385) prouvent qu'un paquet vient bien d'un pair qui connaît le secret partagé -- ils
empêchent un tiers sans la clé d'injecter de fausses routes ou de couper une session en
usurpant l'adresse IP d'un routeur légitime (spoofing). **Ils ne chiffrent pas le trafic** : les
routes elles-mêmes (préfixes, next-hops) continuent de circuler en clair, visibles à quiconque
peut observer le lien -- ce n'est pas de la confidentialité, seulement de l'authentification
d'origine. Le MD5 utilisé par les deux est en outre cryptographiquement faible pour un usage
moderne (collisions connues) : c'est pourquoi TCP-AO (RFC 5925), qui corrige ce point, existe --
mais il est hors de portée de ce lab (voir plus bas). Ces mécanismes ne protègent pas non plus
contre un routeur légitime mal configuré ou compromis : une fois authentifié, il reste un pair
de confiance.

### Limites vérifiées en direct (pas supposées)

- **TCP-AO (RFC 5925) hors de portée** : ni le kernel WSL2 de ce lab (`CONFIG_TCP_AO` absent de
  `/proc/config.gz`) ni bgpd (FRRouting/frr#7240, jamais mergée) ne le supportent. TCP-MD5 est
  la seule authentification eBGP réaliste ici.
- **`service password-encryption` (FRR) ne chiffre rien** : accepté sans erreur mais la clé
  OSPF et le mot de passe BGP restent en clair dans `show running-config`, vérifié en direct.
  Les secrets de lab (`lab-ospf-*`, `lab-bgp-r3r4`) sont donc des valeurs de démonstration
  uniquement, jamais réutilisables ailleurs -- et les snapshots netcheck, qui contiennent ces
  clés en clair, restent hors Git (`.gitignore`). Les **rapports**, eux, les masquent
  systématiquement (`netcheck/secrets.py`) : `password ****`, jamais la valeur.
- **`banner motd` (FRR) absent de `security.yml`** : cette commande ne configure que la session
  vtysh elle-même (jamais partagée avec zebra/bgpd/ospfd, jamais persistée sans `write`) -- elle
  n'apparaît dans aucune sortie `show running-config`, donc netcheck ne peut pas la vérifier par
  sa méthode de collecte actuelle. La bannière de connexion SSH du conteneur, elle, dépend de
  `sshd` (Linux), hors du périmètre de netcheck. La bannière **SR Linux** (`login-banner`), elle,
  est bien vérifiable : voir plus bas.
- **`maximum-prefix` : comportement vérifié en direct en cas de dépassement.** La session passe
  immédiatement en `Idle (PfxCt)` -- pas d'attente du hold-timer. Elle **ne se rétablit pas
  automatiquement**, même après avoir relevé la limite au-dessus du nombre réel de préfixes :
  seul un `clear bgp <voisin>` explicite force une nouvelle négociation. Valeur retenue : **10**
  (marge ×5 sur les 2 préfixes réellement échangés aujourd'hui).
- **Authentification OSPF FRR ↔ SR Linux (lien r4↔r5)** : modèles de configuration différents
  (FRR : clé inline sur l'interface ; SR Linux : keychain nommée au niveau système, référencée
  depuis l'interface -- `set / system authentication keychain ... type ospf`), mais même
  mécanisme sur le fil. Seul le **MD5 classique** est commun aux deux constructeurs pour OSPF :
  FRR n'implémente aucune variante HMAC-SHA (RFC 5709), et le schéma YANG SR Linux interdit
  `hmac-md5`/`hmac-sha-*` pour une keychain de type `ospf` (réservés à `isis`) -- vérifié en
  sondant le schéma en direct. Interopérabilité confirmée par un déploiement à froid complet
  (adjacence Full des deux côtés en 15 secondes, sans intervention manuelle).
- **Stockage de la clé côté SR Linux** : `show system authentication` révèle la clé sous une
  forme obscurcie par la plateforme (`authentication-key $aes1$...$...$`), jamais en clair --
  mais ce n'est pas documenté comme un chiffrement sûr pour autant, donc masqué comme les autres
  secrets dans les rapports netcheck.

## Changements attendus et retour arrière (v3)

> ⚠️ **`guard` exécute des scripts sur les équipements** (les vôtres : netcheck n'en écrit jamais
> un seul, il reste en lecture seule). Un retour arrière automatique est une intervention comme
> une autre : **n'utilisez `guard --rollback` que sur un réseau dont vous avez l'autorisation
> écrite d'exploiter les équipements.**

### `--expect` : dire ce que l'intervention est censée changer

`diff` et `guard` acceptent `--expect fichier.yml`. Un constat que le fichier prévoit devient
**PRÉVU** : il reste affiché (avec sa gravité d'origine et le critère qui l'a prévu) mais n'entre
plus dans le verdict. Référence : [`tests/expect/ospf-cost-r1.yml`](tests/expect/ospf-cost-r1.yml).

```yaml
findings:                        # critères sur les constats du diff
  - id: r1-bascule-next-hop
    description: "r1 passe par r2 pour 5 préfixes"
    device: r1                   # obligatoire : un équipement précis (ni liste, ni "all")
    category: next_hop           # obligatoire : une catégorie réelle du diff
    pattern: "10\\.1\\.23\\.0/30" # optionnel : regex sur le message
    severity: attention          # optionnel : PLAFOND (défaut attention)
    count: 5                     # optionnel : nombre EXACT de constats attendus
after:                           # assertions (format `assert`) vraies APRÈS le changement
  - {id: chemin, description: "...", device: r1, type: path, prefix: 192.168.2.0/24, via: [r2, r3, r4, r5]}
```

| Situation | Résultat |
|---|---|
| constat couvert par un critère | PRÉVU, sans effet sur le verdict |
| critère sans aucun constat | ATTENTION « changement attendu absent » |
| `count` différent du nombre observé | ATTENTION « nombre de constats différent (attendu N, observé M) » |
| assertion `after` en ÉCHEC / NON ÉVALUABLE | ÉCHEC (CRITIQUE) / ATTENTION |

Garde-fous contre un critère qui masquerait un vrai problème, tous refusés **au chargement**
(code 3, avant la moindre action sur le réseau) : `device` et `category` obligatoires, motif trop
large (`.*`, `.+`, `.`, `^`...), clés inconnues. **Un constat CRITIQUE n'est jamais PRÉVU sans
`severity: critique` explicite** (c'est un plafond, pas une égalité). Exemple mesuré sur le lab : un
`ip ospf cost 100` sur r1 produit aussi un constat sur **r2** ; un fichier limité à r1 le laisse en
ATTENTION (`tests/expect/ospf-cost-r1-sans-r2.yml` le démontre).

### `guard --rollback` : retour arrière prouvé

```bash
python -m netcheck guard --change change.sh --rollback annule.sh \
    [--rollback-on echec|attention] [--script-timeout 120] [--expect attendu.yml] [--wait 30] [--yes]
```

Les **deux scripts sont affichés ensemble** puis confirmés **une seule fois** avant toute action.
Déroulé : snapshot avant → changement → convergence → snapshot après → diff (avec `--expect`) → si
le verdict atteint le seuil **ou si le script de changement échoue ou se bloque** : annulation
(**une seule exécution, jamais rejouée**) → convergence → snapshot « retour » → **preuve** : le diff
avant ↔ retour doit contenir **zéro constat, quelle qu'en soit la gravité** (un simple « verdict
OK » tolérerait une ligne de config restée). L'état est relevé plusieurs fois pendant `--wait`
(l'état finit parfois de se stabiliser après la convergence OSPF/BGP), mais le script, lui, ne
tourne qu'une fois. Chaque script a un délai (`--script-timeout`) : le **groupe de processus
entier** est tué (un `docker exec` fils bloqué ne survit pas) et le script compte comme en échec.

| Code | Situation |
|---|---|
| **0** | succès (OK, ou uniquement des constats prévus) |
| **1** | attention, aucun rollback déclenché |
| **2** | échec **sans** rollback (pas de `--rollback`) |
| **3** | erreur d'usage, **avant toute action** (script ou fichier introuvable/invalide, confirmation refusée) |
| **4** | échec **annulé avec succès** : retour à l'état initial prouvé |
| **5** | échec **et annulation échouée** : le réseau n'est pas dans son état initial (cadre rouge, liste des écarts restants) |
| **6** | **interrompu** (Ctrl+C ou SIGTERM) ou erreur interne : état inconnu, **aucun rollback lancé** |

Le code 5 est un état grave : message final dans un cadre rouge sur stderr, et une annulation est
aussi comptée en échec si le script d'annulation lui-même rend un code non nul ou se bloque, même
si l'état semble revenu. **Une interruption ne déclenche jamais d'annulation automatique** (on ne
sait pas où en était le réseau) : guard arrête le script en cours, écrit le journal avec
`final_state: INTERRUPTED` et l'étape concernée, et le dit.

> **Changement de comportement par rapport à la v0.2** : un script `--change` qui se termine avec
> un code non nul n'est plus un simple avertissement. Sans `--rollback`, `guard` rend désormais au
> minimum le **code 2** (une intervention dont le script échoue est une intervention échouée).

**Journal** `reports/guard_<horodatage>.json` (dossier ignoré par Git, comme `snapshots/`) :
chaque étape avec ses horodatages, les codes de sortie des scripts, les verdicts, la preuve du
retour, l'état final. Les scripts y figurent avec leur **SHA-256** et leur contenu **masqué** (un
script de changement peut contenir un secret) ; toute la sortie du journal passe par le masquage
des secrets. Au terminal, au contraire, les scripts s'affichent **en clair** : c'est votre fichier
local et il faut pouvoir lire exactement ce qu'on confirme.

## Surveillance planifiée et alertes (v3)

> ⚠️ `monitor` interroge les équipements à chaque exécution, toutes les quelques minutes. Ne le
> planifier que sur un réseau où vous avez une **autorisation écrite** : même en lecture seule, un
> relevé répété et non autorisé peut être illégal. Ce dépôt ne vise que le lab.

```bash
python -m netcheck monitor --baseline nominal [--intent intents/lab.yml] [--rules fichier.yml]... \
    [--derogations derogations/lab.yml] [--confirm N] [--webhook-format generic|discord] [--state-file f.json] [--dry-run] [-i inventaire]
```

Pour les labs en double pile : `--rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml
--derogations derogations/<lab>.yml` (`monitor` lit la date du jour pour les dérogations, il n'a pas de `--today`).

**Une exécution = un relevé** (pas de démon : le planificateur est externe, voir plus bas). Un seul
relevé en direct sert au diff contre la référence, aux assertions (`--intent`) et à la conformité
(`--rules`) ; un composant dont l'entrée est absente n'est pas exécuté (« non exécuté » dans la
sortie). **Lecture seule stricte** : `monitor` ne lance jamais `guard`, aucun script, aucun
rollback (un test statique vérifie qu'il n'importe pas `guard`) ; il n'écrit que son état, son
verrou et ses rapports dans `reports/` (ignoré par Git).

**Statut global = le pire de quatre composants :**

| Composant | OK | ATTENTION | ÉCHEC |
|---|---|---|---|
| diff (contre `--baseline`) | aucun constat ≥ ATTENTION | constat ATTENTION | constat CRITIQUE |
| assert | tout OK | au moins une assertion **NON ÉVALUABLE** | au moins un ÉCHEC |
| check | conforme | violation `moyenne` / `basse` | violation `critique` / `haute` |
| collecte | tout joignable | | un équipement **injoignable** |

| Code | Situation |
|---|---|
| **0 / 1 / 2** | statut global OK / ATTENTION / ÉCHEC |
| **3** | refusé **avant toute collecte** (référence, intent ou règles introuvables ou invalides, `--confirm` < 1, `NETCHECK_WEBHOOK_URL` invalide, fichier d'état inscriptible nulle part) |
| **4** | exécution **ignorée** : une exécution précédente tient encore le verrou |
| **70** | défaut interne : monitor n'a pas pu conclure, aucune alerte, état inchangé |

Une exception Python non gérée sortirait en code 1, que le planificateur lirait à tort comme
« ATTENTION » : toute erreur interne est donc convertie en code 70 avec un message, distinct du code 3 (refus
d'usage, que l'opérateur corrige) : le 70 se signale, il ne se corrige pas dans la configuration.

### Anti-bruit : une alerte seulement quand le statut change

Le fichier d'état (`reports/monitor_state.json`, droits 0600, écrit de façon atomique) distingue
deux choses : **`observed`**, ce que le dernier relevé a vu, et **`notified`**, le dernier statut
**réellement annoncé** (webhook réussi).

```json
{
  "version": 1,
  "observed":  {"status": "ECHEC", "since": "2026-10-03T10:00:03+00:00", "at": "2026-10-03T10:05:02+00:00"},
  "notified":  {"status": "ECHEC", "at": "2026-10-03T10:00:04+00:00"},
  "candidate": null,
  "incident_since": "2026-10-03T10:00:03+00:00",
  "components": {"collect": "OK", "diff": "ECHEC", "assert": "ECHEC", "check": null},
  "baseline": "nominal",
  "last_report": "reports/monitor_2026-10-03_100003"
}
```

- Une alerte part quand `observed ≠ notified`, **dans les deux sens** et pour toute transition
  (OK → ATTENTION/ÉCHEC, ATTENTION → ÉCHEC, ÉCHEC → ATTENTION « amélioration », → OK « retour à la
  normale », avec la durée de l'incident). OK → ÉCHEC → ÉCHEC → OK donne exactement une alerte,
  aucune, puis un retour à la normale.
- **Première exécution** (pas de fichier d'état) : alerte seulement si le statut n'est pas OK.
- **Fichier illisible ou corrompu** (JSON invalide, version inconnue, champ absurde, binaire,
  dossier à la place du fichier) : monitor ne plante pas, garde une copie en `<fichier>.corrupt`,
  le traite comme une première exécution et le dit dans sa sortie.
- **Envoi en échec** : `notified` n'avance pas, donc l'exécution suivante réessaie. Sans cela, une
  alerte perdue serait supprimée à jamais par l'anti-bruit. Si l'incident est fini entre-temps, rien
  n'a été annoncé et rien ne l'est (le retour à la normale d'une panne jamais annoncée serait absurde).
- **`--confirm N`** (défaut 1) : un **nouveau** statut doit être observé N fois de suite avant
  d'être annoncé, aussi bien pour une dégradation que pour un retour à la normale. Le compteur
  (`candidate`) est dans le fichier d'état. Avec `--confirm 2`, une panne isolée (un SSH qui
  échoue une fois) n'envoie rien ; une panne persistante envoie une alerte à la 2ᵉ exécution. Le
  code retour, lui, est toujours le statut réel du relevé.
- **`--dry-run`** : affiche le message exact qui serait envoyé (même sans changement de statut, pour
  voir le format) ; n'envoie rien, n'écrit ni état ni rapport.

**Limites assumées**
- De **nouveaux constats pendant un ÉCHEC déjà annoncé n'envoient rien** (le statut n'a pas changé) :
  le rapport local est à jour, pas le salon.
- **Après un changement légitime, refaites la référence** : `python -m netcheck snapshot nominal
  --force`. Sinon le diff reste en ATTENTION ou ÉCHEC tant que l'état nominal d'hier est la référence.
- L'envoi précède l'écriture de l'état : un crash entre les deux renverrait la même alerte
  (livraison « au moins une fois »).

**Verrou** : un `flock` non bloquant sur `<état>.lock`, tenu pendant toute l'exécution (collecte
comprise). Une exécution qui trouve le verrou pris s'arrête proprement (code 4, âge du détenteur
affiché, aucune collecte, aucun état modifié). **Verrou orphelin** : le noyau libère un `flock` à la
mort du processus, même par `kill -9`, donc un crash ne peut pas laisser un verrou qui bloquerait les
exécutions suivantes (un fichier `.pid` qu'il faudrait deviner périmé, si). Un monitor bloqué dans une
collecte tiendrait le verrou : en systemd, `TimeoutStartSec=` l'arrête.

**Rapports** : `reports/monitor_latest/` est réécrit à chaque exécution (`diff`, `assert`, `check` en
JSON et HTML, plus `summary.json`) ; `reports/monitor_<horodatage>/` n'est écrit que quand un message
part, c'est le chemin cité dans l'alerte.

### Alertes par webhook

L'URL vient **uniquement** de la variable d'environnement `NETCHECK_WEBHOOK_URL` : c'est un secret
(quiconque la connaît peut poster dans le salon), jamais dans le dépôt ni en argument de commande.
Sans elle, monitor fonctionne et dit « alertes désactivées ».

- **https obligatoire** ; `http` n'est accepté que vers `localhost`, `127.0.0.1` et `[::1]` (tests).
  Identifiants dans l'URL, schéma inconnu, hôte absent : refusés (code 3, avant toute collecte).
- **Aucune redirection suivie** (un 3xx est un échec, la cible n'est jamais contactée), **délai de
  5 s** par opération réseau, **un seul réessai** (erreur réseau, délai dépassé ou 5xx ; jamais un 4xx).
  Tout 2xx vaut succès.
- **Un échec d'envoi est journalisé** (« webhook : échec d'envoi (HTTP 500) après 2 tentative(s) »)
  **sans changer le code retour** de monitor. Un **HTTP 400** ajoute une indication, sans l'URL :
  « HTTP 400, format refusé par le destinataire : vérifier --webhook-format » (constaté en réel :
  Discord refuse le format `generic` avec un 400).
- **Format choisi automatiquement** : sans `--webhook-format`, une URL **Discord** (hôte `discord.com`
  ou `discordapp.com`, chemin `/api/webhooks/…`) donne le format `discord`, toute autre URL le format
  `generic`. Un `--webhook-format generic` **forcé** vers Discord est respecté mais affiche un
  avertissement à chaque exécution (sur stderr, sans l'URL).
- **L'URL n'apparaît jamais** : ni dans la sortie, ni dans l'état, ni dans les rapports, ni dans un
  message d'erreur (celles-ci sont construites à partir du type d'erreur et du code HTTP, jamais de
  `str(exception)`, qui peut citer l'URL). Les formats d'URL Discord, Slack et Teams sont de plus
  reconnus et masqués par `secrets.py` partout où du texte est publié.

**Contenu d'une alerte** (liste blanche) : statut et statut précédent, horodatage, état de chaque
composant, équipements concernés, **au plus 10 constats** résumés (gravité, équipement, message
tronqué à 200 caractères, puis « et N autres »), chemin **relatif** du rapport local. Jamais de
configuration (pour la conformité : l'identifiant et la description de la règle, jamais le détail
qui peut citer une ligne de config) ; tout passe par le masquage des secrets.

`--webhook-format generic` (défaut pour une URL qui n'est pas Discord) :

```json
{"source": "netcheck", "netcheck_version": "0.3.0", "event": "status_change", "kind": "degradation",
 "status": "ECHEC", "previous_status": "OK", "timestamp": "2026-10-03T10:05:02+02:00",
 "components": {"collect": "OK", "diff": "ECHEC", "assert": "ECHEC", "check": null},
 "devices": ["r1", "r3"],
 "findings": [{"severity": "CRITIQUE", "component": "diff", "device": "r1",
               "category": "ospf_neighbor", "message": "voisin OSPF perdu : 10.1.255.3"}],
 "more": 4, "report": "reports/monitor_2026-10-03_100502"}
```

`kind` vaut `first_report`, `degradation`, `improvement` ou `recovery` (alors `event: "recovery"`,
avec `incident_duration_s`). `--webhook-format discord` produit un embed (titre « 🔴 netcheck :
ÉCHEC (OK → ÉCHEC) », couleur par statut, constats en liste) avec **`allowed_mentions: {"parse": []}`
obligatoire** : les textes viennent d'équipements, aucun « @everyone » ne doit pouvoir sonner. La
description est limitée à 3500 caractères (la limite Discord est 4096, 6000 cumulés).

**Slack et Teams (documenté, non implémenté).** Seule la fonction qui construit le corps change ;
l'envoi (https, pas de redirection, 5 s, un réessai) reste identique.
- **Slack** : corps `{"text": "…"}` (avec `blocks` en option) ; la réponse réussie est **HTTP 200 avec
  `ok`**, pas 204 (d'où « tout 2xx vaut succès »). Pas d'embeds ni d'`allowed_mentions`.
- **Teams** : les connecteurs Microsoft 365 sont annoncés comme « nearing deprecation » : viser un
  webhook **Workflows**. Corps `{"type": "message", "attachments": [{"contentType":
  "application/vnd.microsoft.card.adaptive", "content": {…carte adaptative…}}]}` ; taille maximale
  28 Ko, limitation au-delà de 4 requêtes par seconde.

Références vérifiées : Discord, « Webhook Resource » (<https://docs.discord.com/developers/resources/webhook>)
et « Message Resource » (<https://docs.discord.com/developers/resources/message>) ; Slack, « Sending
messages using incoming webhooks »
(<https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks>) ; Microsoft, « Create an
Incoming Webhook - Teams | Microsoft Learn »
(<https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook>).

### Planifier dans WSL

`automation/monitor.sh` est l'enveloppe à planifier. Elle fournit `NETCHECK_WEBHOOK_URL` à monitor
depuis `~/.config/netcheck/env` **sans jamais exécuter ce fichier** (pas de `source` : ce serait
exécuter du code toutes les 5 minutes) : le fichier est lu comme du texte, seule la ligne
`NETCHECK_WEBHOOK_URL=` est retenue (guillemets simples ou doubles retirés), toute autre ligne est
ignorée. Il doit appartenir à l'utilisateur, être un **fichier régulier** (pas un lien) et n'être
lisible que par lui (**0600**, ou 0400) : sinon refus avec un message clair (code 3). Une
`NETCHECK_WEBHOOK_URL` déjà exportée l'emporte sur le fichier.

**Clés d'hôte.** `monitor` vérifie les clés SSH comme les autres commandes (`~/.netcheck/known_hosts` du
planificateur, ou `--known-hosts`). Sur le lab, **après chaque redéploiement, relancez
`lab-access/pin_hostkeys.sh`** : les clés des conteneurs ont changé et `monitor` passerait en ÉCHEC (voir
[Clés d'hôte SSH et migration](#clés-dhôte-ssh-et-migration-v4-phase-c1)). C'est le comportement voulu.

À taper vous-même (rien de tout cela n'est fait par le dépôt, et aucun `sudo` n'est nécessaire) :

```bash
# 1. Enregistrer l'URL SANS qu'elle entre dans l'historique du shell
mkdir -p ~/.config/netcheck && chmod 700 ~/.config/netcheck
read -rsp 'URL du webhook : ' U; echo
( umask 077; printf "NETCHECK_WEBHOOK_URL='%s'\n" "$U" > ~/.config/netcheck/env ); unset U

# 2. La référence : l'état nominal, lab sain et déployé
cd ~/lab-reseau-frr && python -m netcheck snapshot nominal

# 3. Vérifier le message sans rien envoyer
automation/monitor.sh --baseline nominal --intent intents/lab.yml --webhook-format discord --dry-run
```

**Option recommandée : cron** (`crontab -e`, puis ajouter la ligne) :

```
*/5 * * * * /home/<vous>/lab-reseau-frr/automation/monitor.sh --baseline nominal --intent intents/lab.yml --confirm 2 --webhook-format discord >> /home/<vous>/lab-reseau-frr/reports/monitor.log 2>&1
```

`--confirm 2` : une panne doit être vue deux fois de suite (donc 5 à 10 minutes) avant d'alerter.
Le journal grossit d'environ 100 Ko par jour avec une sortie d'une ligne par exécution et n'est pas
roté (acceptable pour un lab ; `: > reports/monitor.log` le vide).

**Variante : timer systemd utilisateur.** Deux fichiers, puis activation :

```ini
# ~/.config/systemd/user/netcheck-monitor.service
[Unit]
Description=netcheck monitor (surveillance du lab)

[Service]
Type=oneshot
WorkingDirectory=%h/lab-reseau-frr
ExecStart=%h/lab-reseau-frr/automation/monitor.sh --baseline nominal --intent intents/lab.yml --confirm 2 --webhook-format discord
SuccessExitStatus=1 2
TimeoutStartSec=300

# ~/.config/systemd/user/netcheck-monitor.timer
[Unit]
Description=netcheck monitor toutes les 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

```bash
systemctl --user daemon-reload && systemctl --user enable --now netcheck-monitor.timer
systemctl --user list-timers
```

`SuccessExitStatus=1 2` : ATTENTION et ÉCHEC sont des statuts, pas des plantages de l'unité.

| | cron | timer systemd utilisateur |
|---|---|---|
| Prérequis dans WSL | service `cron` actif (`systemctl is-active cron` ; sans systemd, `sudo service cron start` à chaque démarrage) | `systemd=true` dans la section `[boot]` de `/etc/wsl.conf` (documenté par Microsoft pour les versions récentes de WSL) |
| Dépend d'une session ouverte | non : service système, lance les crontabs utilisateur | oui, sauf si `loginctl enable-linger <vous>` (modifie la configuration : non testé ici) |
| Journaux | fichier (`reports/monitor.log`) | journald (`journalctl --user -u netcheck-monitor`) |

Constaté sur la machine de développement : `systemd=true`, `cron.service` actif et activé,
gestionnaire systemd utilisateur actif, `Linger=no`.

**L'instance WSL doit rester active.** Rien ne s'exécute si WSL est arrêté (ni cron ni systemd ne
tournent alors), et un PC en veille met la VM en pause. Deux façons de l'éviter, avec leur coût :
1. **Garder un terminal WSL ouvert** pendant la surveillance (choix retenu pour ce lab) : aucun
   réglage, la VM s'arrête normalement quand on ferme tout.
2. **`instanceIdleTimeout=-1`** dans `%UserProfile%\.wslconfig` (section `[general]`, fichier à créer
   soi-même puis `wsl --shutdown`) : désactive l'arrêt automatique de l'instance. Coût : **la VM et le
   lab restent en mémoire en permanence** (les 7 conteneurs et leur RAM), même sans rien faire.
   Selon la documentation Microsoft (« Advanced settings configuration in WSL | Microsoft Learn »,
   <https://learn.microsoft.com/en-us/windows/wsl/wsl-config>), `instanceIdleTimeout` vaut 15000 ms par
   défaut et `vmIdleTimeout` (section `[wsl2]`) 60000 ms. Cette page ne dit pas si un processus de
   fond (cron, timer) compte comme une activité qui empêche l'arrêt : non vérifié, d'où la
   recommandation d'un terminal ouvert ou du réglage explicite.

## Secrets du lab

**Tous les secrets de ce dépôt sont des valeurs de lab, sans aucune valeur hors du lab.** Ils sont
là parce qu'un lab reproductible doit démarrer sans étape manuelle, pas parce que c'est une bonne
pratique. **Ne réutilisez jamais ces fichiers, ces clés ni ces mots de passe sur un équipement
réel.**

| Où | Quoi | Forme |
|---|---|---|
| `configs/r*/frr.conf` | clés OSPF `lab-ospf-r1r2`, `lab-ospf-r1r3`, `lab-ospf-r2r3`, `lab-ospf-r4r5` ; mot de passe BGP `lab-bgp-r3r4` | **en clair** |
| `configs-multivendor/r5/config.cli` | la clé OSPF `lab-ospf-r4r5` (keychain SR Linux) | en clair dans le fichier ; **`$aes1$…`** (obscurci par la plateforme, pas un chiffrement garanti) dans la configuration relevée |
| `configs-ceos/r4/startup-config` | `lab-ospf-r4r5` et `lab-bgp-r3r4` ; hash `sha512` du compte `admin` | clés en clair dans le fichier ; **type 7** (réversible) dans la running-config ; le hash sha512 est celui du mot de passe par défaut `admin` de l'image |
| `automation/inventory*.yml` | identifiants par défaut des images : `netops` / `netops` (FRR), `admin` / `NokiaSrl1!` (SR Linux), `admin` / `admin` (cEOS) | en clair, documentés comme identifiants de lab ; surchargeables par `NETCHECK_USER` / `NETCHECK_PASS` ou, par driver, `NETCHECK_SRLINUX_*`, `NETCHECK_EOS_*` |
| `tests/fixtures/` | configurations et sorties **réelles** capturées sur les labs | mêmes valeurs de lab : type 7 et sha512 (`ceos/`) ; les fixtures FRR (`r1/`…`r4/`) et SR Linux (`r5/`) ont été capturées avant le durcissement et ne contiennent aucune clé. Les formes `$aes1$…` de SR Linux, relevées sur le lab durci, ne figurent que dans des chaînes de `tests/test_secrets.py` et `tests/test_compliance.py` |
| `tests/golden/` | rapports de conformité gelés (v0.3.0) et copies figées des configurations de démarrage des labs (`inputs/`) | les `.json` sont **masqués** (vérifié par un test) ; `inputs/` contient les valeurs de lab des fichiers `configs*/` |
| `tests/test_*.py`, `tests/integration*.sh` | valeurs **inventées** pour tester le masquage (`hunter2`, jetons `SENTINEL-…`, fausses URL de webhook à identifiants fictifs) | fictives : jamais une vraie URL |
| `docs/audit/` | rapports d'audit | secrets **masqués** (`password ****`) |

Trois précisions. (1) Le **type 7** d'EOS n'est pas un chiffrement : il se déchiffre ; il est masqué
dans les rapports comme les autres, mais il reste lisible dans les snapshots. (2) Les **snapshots**
et les **rapports locaux** (`snapshots/`, `reports/`) contiennent des configurations brutes : ils
sont exclus de Git (`.gitignore`). (3) L'**URL d'un webhook** n'est, elle, jamais dans le dépôt : elle
vient de `NETCHECK_WEBHOOK_URL`, d'un fichier `~/.config/netcheck/env` en 0600 lu comme du texte, et
n'apparaît dans aucune sortie ; les exemples du dépôt n'utilisent que des valeurs fictives.

## Limites connues et pistes v4

**Limites connues (documentées, pas cachées).**
- **Les évaluateurs de règles qui lisent le texte de la configuration vivent dans
  `compliance.py`**, un jeu par constructeur (FRR, SR Linux, EOS : +147 lignes pour EOS). C'est le
  point faible de l'architecture : chaque nouveau constructeur y ajoute son dialecte.
- **Peer groups** : les règles BGP lisent `neighbor X remote-as N` voisin par voisin. Un voisin
  défini par un peer group (EOS comme FRR) échappe à ces règles : faux négatif possible. Les peer
  groups EOS n'ont jamais été observés dans ce lab.
- **Adresses IPv4 secondaires** (EOS) ignorées, faute d'avoir été observées ; **IPv6** hors modèle
  (le modèle est IPv4) ; **VRF** : seule la VRF par défaut est lue.
- **États OSPF autres que `full`** : seul `full` a été observé sur EOS ; les autres sont simplement
  mis en majuscule initiale, jamais devinés.
- **Pas de TCP-AO** (RFC 5925) : ni le noyau WSL2 de ce lab ni FRR (bgpd) ne le supportent ; TCP-MD5,
  cryptographiquement plus faible, est la seule authentification eBGP réaliste ici.
- **`maximum-routes` (EOS) ≠ `maximum-prefix` (FRR)** : EOS compte les routes reçues *avant* la
  politique d'entrée, FRR les préfixes *acceptés* après filtre (sauf `force`) : même protection,
  seuil différent.
- **Ordre des séquences non simulé** : les règles de politique d'entrée (`ebgp-pas-de-route-par-defaut`,
  `ebgp-pas-de-reinjection-de-prefixes-locaux`, FRR et EOS) ne simulent ni l'ordre des séquences d'un route-map ni celui
  des entrées d'une prefix-list. Un `permit` précédé d'un `deny` plus large est donc signalé à tort (faux positif ; pas
  de faux négatif connu). Ouverture prévue en phase E : la première entrée ou séquence qui correspond décide.
- **`monitor`** : de nouveaux constats pendant un ÉCHEC déjà annoncé n'envoient rien ; livraison
  « au moins une fois » ; délai du webhook appliqué à chaque opération réseau, pas au total ;
  Slack et Teams documentés, **non implémentés**.
- **SR Linux** : pas de BGP dans ce lab (le driver n'analyse pas BGP).
- **`guard`** n'est pas une transaction : son « retour arrière » est un script fourni par
  l'utilisateur, et le retour est *prouvé* par un diff vide, pas garanti par l'équipement.
- **Les tests d'intégration** exigent Docker et containerlab et ne tournent pas en CI (seuls les
  tests unitaires, ruff et shellcheck y tournent) ; l'instance WSL doit rester active pour une
  surveillance planifiée.

**Pistes v4.**
1. Extraire les évaluateurs texte de `compliance.py` **vers les drivers** (chaque driver fournit
   ses propres vérifications de configuration, `compliance.py` ne garde que le moteur).
2. Une configuration **structurée** dans le modèle (arbre de configuration par driver) pour
   remplacer les expressions régulières par des requêtes, et traiter peer groups et héritage.
3. **TCP-AO** dès que le noyau et FRR le supportent ; IPv6 ; VRF multiples ; adresses secondaires.
4. `monitor` : alertes Slack et Teams, anti-rebond par composant, délai total du webhook.
5. Intégration continue du lab (runner avec Docker et containerlab) pour rejouer les scénarios.
6. Phase E : simuler l'ordre des séquences (route-maps et prefix-lists, première correspondance) pour supprimer le faux
   positif « permit précédé d'un deny plus large ».

## Licence

Ce dépôt est distribué sous licence **Apache-2.0** (texte complet dans [LICENSE](LICENSE),
copyright 2026 Lodric BOYER). Le paquet `netcheck` la déclare dans `pyproject.toml`.

**Dépendances.** Celles d'exécution (netmiko, PyYAML, Jinja2, rich) et de développement (pytest,
ruff) sont sous licences permissives (MIT ou BSD). Une dépendance future doit rester compatible :
MIT, BSD ou Apache-2.0. Une licence copyleft (GPL) n'est pas acceptée sans décision explicite.

Les images de routeurs (Arista cEOS, Nokia SR Linux, et les suivantes) restent soumises à leurs
propres licences : elles ne sont jamais dans ce dépôt ni redistribuées par lui.

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

*Validation : lab déployé et testé sur un PC portable Windows (WSL2, Docker 29.8, containerlab 0.79, FRR 10.2.1). Résultats vérifiés : convergence OSPF/BGP, ping et traceroute pc1 → pc2, scripts health/backup/drift en SSH non-root, détection d'une panne BGP et d'une dérive de configuration simulées. netcheck : `pytest` au vert, `tests/integration.sh` (S1-S5, C1/C2, `guard`) 30/30 en conditions réelles sur ce même lab. Lab v2 (FRR + Nokia SR Linux) : `test_lab_multivendor.sh` et `tests/integration_multivendor.sh` (diff, coupure du lien r4↔r5 vue des deux côtés, conformité) également validés en conditions réelles -- voir la section "Lab multi-constructeurs" ci-dessus pour le détail.*

*Réalisé avec l'assistance de Claude (Anthropic) pour la conception, le code et la documentation. Le déploiement, les tests et la validation ont été faits sur ma machine. Le détail de la démarche est dans le rapport, section 2.4.*
