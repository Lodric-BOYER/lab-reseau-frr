#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
#
# Test de bout en bout du lab multi-constructeurs (Phase C, SPEC_v2.md) : r1-r4 = FRR
# (identiques à lab.clab.yml, C9), r5 = Nokia SR Linux. Portée : topologie et routage
# uniquement (OSPF FRR <-> SR Linux, eBGP inchangé, MTU du lien r4<->r5). L'automatisation
# netcheck pour SR Linux (driver Phase D) n'existe pas encore : pas de section pannes/drift
# ici, contrairement à test_lab.sh.
#   bash test_lab_multivendor.sh            -> teste tout, laisse le lab démarré à la fin
#   bash test_lab_multivendor.sh --destroy  -> teste tout puis détruit le lab
# Code retour : 0 si tous les contrôles passent, 1 sinon.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

LAB=clab-frr-lab-multivendor
PASS=0; FAIL=0
ok()    { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko()    { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else ko "$d"; fi; }
title() { echo; echo "=== $1 ==="; }
vt()    { docker exec "$LAB-$1" vtysh -c "$2" 2>/dev/null; }
srl()   { docker exec "$LAB-r5" sr_cli -- "$@" 2>/dev/null; }

# Nombre de voisins OSPF en état Full sur un routeur FRR
ospf_full() { vt "$1" "show ip ospf neighbor json" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("neighbors", {})
print(sum(any((n.get("nbrState") or n.get("state", "")).startswith("Full") for n in l) for l in d.values()))'; }

# Nombre de voisins OSPF en état "full" sur r5 (SR Linux)
ospf_full_srl() { srl show network-instance default protocols ospf neighbor | grep -ci '\bfull\b'; }

# "Etat préfixes_reçus" d'un voisin BGP
bgp_peer() { vt "$1" "show bgp ipv4 unicast summary json" | python3 -c '
import json, sys
p = json.load(sys.stdin).get("peers", {}).get(sys.argv[1], {})
print(p.get("state", "absent"), p.get("pfxRcd", 0))' "$2"; }

# Attend que la session eBGP r3 <-> r4 soit établie avec 2 préfixes (90 s max)
wait_bgp() {
  for _ in $(seq 1 45); do
    [[ "$(bgp_peer r3 172.16.34.2)" == "Established 2" && "$(bgp_peer r4 172.16.34.1)" == "Established 2" ]] && return 0
    sleep 2
  done
  return 1
}

# Attend que chaque routeur (FRR et SR Linux) ait tous ses voisins OSPF en Full (60 s max)
wait_ospf() {
  for _ in $(seq 1 30); do
    [[ "$(ospf_full r1)$(ospf_full r2)$(ospf_full r3)$(ospf_full r4)$(ospf_full_srl)" == "22211" ]] && return 0
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
check "docker accessible sans sudo"        docker info
check "containerlab installé"              containerlab version
(( FAIL > 0 )) && { echo; echo "Prérequis manquants : voir l'étape 0 du README."; exit 1; }

# ---------------------------------------------------------------- 2. Image et déploiement
title "2. Image et déploiement"
check "construction de l'image frr-ssh:10.2.1"  docker build -q -t frr-ssh:10.2.1 docker/
check "déploiement du lab (7 conteneurs)"        containerlab deploy -t lab-multivendor.clab.yml --reconfigure
running=$(docker ps --filter "name=$LAB-" --filter status=running -q | wc -l)
[[ $running -eq 7 ]] && ok "7 conteneurs en état running" || ko "$running/7 conteneurs en état running"

# ---------------------------------------------------------------- 3. Routage
title "3. Routage (FRR <-> SR Linux)"
echo "  … attente de la convergence OSPF/BGP (jusqu'à 90 s)"
if wait_bgp; then ok "eBGP r3 <-> r4 Established, 2 préfixes dans chaque sens"; else ko "eBGP non établi : r3=[$(bgp_peer r3 172.16.34.2)] r4=[$(bgp_peer r4 172.16.34.1)]"; fi
wait_ospf || true
sleep 5   # laisse OSPF recalculer et installer les routes après les dernières adjacences
for spec in r1:2 r2:2 r3:2 r4:1; do
  r=${spec%%:*}; want=${spec##*:}; got=$(ospf_full "$r")
  [[ "$got" == "$want" ]] && ok "OSPF $r : $got/$want voisins Full" || ko "OSPF $r : ${got:-0}/$want voisins Full"
done
got_srl=$(ospf_full_srl)
[[ "$got_srl" == "1" ]] && ok "OSPF r5 (SR Linux) : $got_srl/1 voisin full" || ko "OSPF r5 (SR Linux) : ${got_srl:-0}/1 voisin full"
badmtus=$(srl show network-instance default protocols ospf neighbor detail | awk '/Bad MTUs/{print $NF}')
[[ "$badmtus" == "0" ]] && ok "r5 : compteur Bad MTUs à 0 (MTU du lien r4<->r5 alignée)" || ko "r5 : Bad MTUs = ${badmtus:-inconnu}"
check "r1 connaît le LAN distant 192.168.2.0/24"  bash -c "docker exec $LAB-r1 vtysh -c 'show ip route 192.168.2.0/24' | grep -q ospf"
check "ping pc1 -> pc2 sans perte"                docker exec "$LAB-pc1" ping -c 3 -W 1 192.168.2.10
for _ in 1 2 3; do
  path=$(route_path)
  [[ "$path" == "r1 r3 r4 r5 pc2" ]] && break
  sleep 5
done
[[ "$path" == "r1 r3 r4 r5 pc2" ]] && ok "chemin r1 -> r3 -> r4 -> r5 -> pc2" || ko "chemin inattendu : $path"

# ---------------------------------------------------------------- Bilan
[[ "${1:-}" == "--destroy" ]] && containerlab destroy -t lab-multivendor.clab.yml --cleanup >/dev/null 2>&1 && echo && echo "Lab détruit."
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab multi-constructeurs est fonctionnel (topologie + routage)." || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
