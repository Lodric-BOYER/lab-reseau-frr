#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
#
# Test de bout en bout du lab Arista cEOS (Phase F, SPEC_v3.md) : r1-r3 et r5 = FRR
# (identiques à lab.clab.yml, C9), r4 = Arista cEOS 4.34.8M. Portée : topologie, routage et
# durcissement EN VIGUEUR des deux côtés (OSPF MD5, TCP-MD5, GTSM, limite de routes, aucune API
# de gestion). L'automatisation netcheck est testée à part (tests/integration_ceos.sh).
# Prérequis : l'image ceos:4.34.8M importée LOCALEMENT (téléchargement avec un compte arista.com,
# jamais dans le dépôt : voir README, « Lab Arista cEOS »).
#   bash test_lab_ceos.sh            -> teste tout, laisse le lab démarré à la fin
#   bash test_lab_ceos.sh --destroy  -> teste tout puis détruit le lab
# Code retour : 0 si tous les contrôles passent, 1 sinon.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

LAB=clab-frr-lab-ceos
IMAGE=ceos:4.34.8M
PASS=0; FAIL=0
ok()    { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko()    { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else ko "$d"; fi; }
title() { echo; echo "=== $1 ==="; }
vt()    { docker exec "$LAB-$1" vtysh -c "$2" 2>/dev/null; }
eos()   { docker exec "$LAB-r4" Cli -p 15 -c "$1" 2>/dev/null; }

# Nombre de voisins OSPF en état Full sur un routeur FRR
ospf_full() { vt "$1" "show ip ospf neighbor json" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("neighbors", {})
print(sum(any((n.get("nbrState") or n.get("state", "")).startswith("Full") for n in l) for l in d.values()))'; }

# Nombre de voisins OSPF en état FULL sur r4 (cEOS)
ospf_full_eos() { eos "show ip ospf neighbor" | grep -c FULL; }

# "Etat préfixes_reçus" d'un voisin BGP, vu de r3 (FRR) puis de r4 (cEOS)
bgp_peer_frr() { vt "$1" "show bgp ipv4 unicast summary json" | python3 -c '
import json, sys
p = json.load(sys.stdin).get("peers", {}).get(sys.argv[1], {})
print(p.get("state", "absent"), p.get("pfxRcd", 0))' "$2"; }
bgp_peer_eos() { eos "show ip bgp summary | json" | python3 -c '
import json, sys
p = json.load(sys.stdin).get("vrfs", {}).get("default", {}).get("peers", {}).get(sys.argv[1], {})
print(p.get("peerState", "absent"), p.get("prefixReceived", 0))' "$1"; }

# Attend que la session eBGP r3 <-> r4 soit établie avec 2 préfixes de chaque côté (90 s max)
wait_bgp() {
  for _ in $(seq 1 45); do
    [[ "$(bgp_peer_frr r3 172.16.34.2)" == "Established 2" && "$(bgp_peer_eos 172.16.34.1)" == "Established 2" ]] && return 0
    sleep 2
  done
  return 1
}

# Attend que chaque routeur ait tous ses voisins OSPF en Full (60 s max)
wait_ospf() {
  for _ in $(seq 1 30); do
    [[ "$(ospf_full r1)$(ospf_full r2)$(ospf_full r3)$(ospf_full_eos)$(ospf_full r5)" == "22211" ]] && return 0
    sleep 2
  done
  return 1
}

# Traduit une adresse en nom d'équipement (un routeur a une adresse par interface)
owner() {
  case "$1" in
    192.168.1.1|10.1.12.1|10.1.13.1|10.1.255.1) echo r1 ;;
    10.1.12.2|10.1.23.1|10.1.255.2)             echo r2 ;;
    10.1.13.2|10.1.23.2|172.16.34.1|10.1.255.3) echo r3 ;;
    172.16.34.2|10.2.45.1|10.2.255.4)           echo r4 ;;
    10.2.45.2|192.168.2.1|10.2.255.5)           echo r5 ;;
    192.168.2.10)                               echo pc2 ;;
    *)                                          echo "?($1)" ;;
  esac
}

# Suite des équipements traversés de pc1 vers pc2
route_path() {
  docker exec "$LAB-pc1" traceroute -n -w 1 -q 1 192.168.2.10 2>/dev/null \
    | awk 'NR>1{print $2}' | while read -r ip; do owner "$ip"; done | paste -sd' '
}

# ---------------------------------------------------------------- 1. Prérequis
title "1. Prérequis"
check "docker accessible sans sudo"              docker info
check "containerlab installé"                    containerlab version
check "image $IMAGE importée localement"         docker image inspect "$IMAGE"
(( FAIL > 0 )) && { echo; echo "Prérequis manquants : voir le README (« Lab Arista cEOS »)."; exit 1; }

# ---------------------------------------------------------------- 2. Image et déploiement
title "2. Image et déploiement"
check "construction de l'image frr-ssh:10.2.1"   docker build -q -t frr-ssh:10.2.1 docker/
start=$(date +%s)
check "déploiement du lab (7 conteneurs)"        containerlab deploy -t lab-cEOS.clab.yml --reconfigure
echo "  … déploiement : $(( $(date +%s) - start )) s"
running=$(docker ps --filter "name=$LAB-" --filter status=running -q | wc -l)
[[ $running -eq 7 ]] && ok "7 conteneurs en état running" || ko "$running/7 conteneurs en état running"

# ---------------------------------------------------------------- 3. Routage
title "3. Routage (FRR <-> cEOS)"
echo "  … attente de la convergence OSPF/BGP (jusqu'à 90 s)"
if wait_bgp; then ok "eBGP r3 (FRR) <-> r4 (cEOS) Established, 2 préfixes dans chaque sens"
else ko "eBGP non établi : r3=[$(bgp_peer_frr r3 172.16.34.2)] r4=[$(bgp_peer_eos 172.16.34.1)]"; fi
wait_ospf || true
sleep 5   # laisse OSPF et BGP installer les routes après les dernières adjacences
for spec in r1:2 r2:2 r3:2 r5:1; do
  r=${spec%%:*}; want=${spec##*:}; got=$(ospf_full "$r")
  [[ "$got" == "$want" ]] && ok "OSPF $r (FRR) : $got/$want voisins Full" || ko "OSPF $r (FRR) : ${got:-0}/$want voisins Full"
done
got_eos=$(ospf_full_eos)
[[ "$got_eos" == "1" ]] && ok "OSPF r4 (cEOS) : $got_eos/1 voisin Full" || ko "OSPF r4 (cEOS) : ${got_eos:-0}/1 voisin Full"
check "r1 connaît le LAN distant 192.168.2.0/24"  bash -c "docker exec $LAB-r1 vtysh -c 'show ip route 192.168.2.0/24' | grep -q ospf"
check "ping pc1 -> pc2 sans perte"                docker exec "$LAB-pc1" ping -c 3 -W 1 192.168.2.10
for _ in 1 2 3; do
  path=$(route_path)
  [[ "$path" == "r1 r3 r4 r5 pc2" ]] && break
  sleep 5
done
[[ "$path" == "r1 r3 r4 r5 pc2" ]] && ok "chemin r1 -> r3 -> r4 (cEOS) -> r5 -> pc2" || ko "chemin inattendu : $path"

# ---------------------------------------------------------------- 4. Durcissement en vigueur
title "4. Durcissement en vigueur (preuve des deux côtés)"
eos "show ip ospf interface Ethernet2" | grep -q "Message-digest authentication, using key id 1" \
  && ok "OSPF r4 (cEOS) : authentification message-digest active" || ko "OSPF r4 : authentification absente"
vt r5 "show ip ospf interface eth1" | grep -q "Cryptographic authentication enabled" \
  && ok "OSPF r5 (FRR) : authentification cryptographique active" || ko "OSPF r5 : authentification absente"
neigh=$(eos "show ip bgp neighbors 172.16.34.1")
echo "$neigh" | grep -q "MD5 authentication is enabled" \
  && ok "BGP r4 (cEOS) : TCP-MD5 actif" || ko "BGP r4 : TCP-MD5 absent"
echo "$neigh" | grep -q "TTL is 255, BGP neighbor may be up to 1 hops away" \
  && ok "BGP r4 (cEOS) : GTSM actif (TTL 255, 1 saut)" || ko "BGP r4 : GTSM absent"
echo "$neigh" | grep -q "Configured maximum total number of routes is 10" \
  && ok "BGP r4 (cEOS) : maximum-routes 10 actif" || ko "BGP r4 : limite de routes absente"
frr_neigh=$(vt r3 "show bgp neighbors 172.16.34.2")
echo "$frr_neigh" | grep -q "External BGP neighbor may be up to 1 hops away" \
  && ok "BGP r3 (FRR) : ttl-security actif" || ko "BGP r3 : ttl-security absent"
echo "$frr_neigh" | grep -q "Maximum prefixes allowed 10" \
  && ok "BGP r3 (FRR) : maximum-prefix 10 actif" || ko "BGP r3 : maximum-prefix absent"
[[ "$(docker exec "$LAB-r5" cat /sys/class/net/eth1/mtu)" == "1500" && "$(eos "show interfaces Ethernet2 | json" | python3 -c '
import json, sys
print(json.load(sys.stdin)["interfaces"]["Ethernet2"]["mtu"])')" == "1500" ]] \
  && ok "MTU du lien r4 <-> r5 alignée à 1500 des deux côtés" || ko "MTU du lien r4 <-> r5 non alignée"
listening=$(docker exec "$LAB-r4" ss -ltn 2>/dev/null)
echo "$listening" | grep -qE ':22[[:space:]]' && ok "SSH en écoute sur r4 (seul accès de gestion)" || ko "SSH absent sur r4"
echo "$listening" | grep -qE ':(80|443|830|6030|8080)[[:space:]]' \
  && ko "une API de gestion écoute sur r4 (eAPI, NETCONF ou gNMI)" || ok "aucune API de gestion en écoute sur r4 (ni 80/443, ni 830, ni 6030)"

# ---------------------------------------------------------------- 5. Ressources
title "5. Ressources (mesure, pas seulement un test)"
# docker stats écrit « 1013MiB » ou « 1.002GiB » : converti en MiB pour comparer.
mem_mib=$(docker stats --no-stream --format '{{.MemUsage}}' "$LAB-r4" | awk '{print $1}' | python3 -c '
import re, sys
value, unit = re.match(r"([0-9.]+)([A-Za-z]+)", sys.stdin.read().strip()).groups()
print(round(float(value) * {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024}[unit]))')
echo "  … RAM de r4 (cEOS) : ${mem_mib} MiB ; hôte : $(free -m | awk 'NR==2{print $3 " MiB utilisés / " $2 " MiB"}')"
[[ "$mem_mib" =~ ^[0-9]+$ ]] && (( mem_mib < 1536 )) \
  && ok "RAM de r4 (cEOS) sous 1,5 GiB (${mem_mib} MiB)" || ko "RAM de r4 inattendue : ${mem_mib:-inconnue} MiB"

# ---------------------------------------------------------------- Bilan
[[ "${1:-}" == "--destroy" ]] && containerlab destroy -t lab-cEOS.clab.yml --cleanup >/dev/null 2>&1 && echo && echo "Lab détruit."
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab Arista cEOS est fonctionnel (topologie, routage, durcissement)." || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
