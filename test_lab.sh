#!/usr/bin/env bash
# Test de bout en bout du lab : prérequis, déploiement, routage, automatisation, détection de pannes.
#   bash test_lab.sh            -> teste tout, laisse le lab démarré à la fin
#   bash test_lab.sh --destroy  -> teste tout puis détruit le lab
# Code retour : 0 si tous les contrôles passent, 1 sinon.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

LAB=clab-frr-lab
PASS=0; FAIL=0
ok()    { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko()    { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else ko "$d"; fi; }
title() { echo; echo "=== $1 ==="; }
vt()    { docker exec "$LAB-$1" vtysh -c "$2" 2>/dev/null; }

# Nombre de voisins OSPF en état Full sur un routeur
ospf_full() { vt "$1" "show ip ospf neighbor json" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("neighbors", {})
print(sum(any((n.get("nbrState") or n.get("state", "")).startswith("Full") for n in l) for l in d.values()))'; }

# "Etat préfixes_reçus" d'un voisin BGP
bgp_peer() { vt "$1" "show bgp ipv4 unicast summary json" | python3 -c '
import json, sys
p = json.load(sys.stdin).get("peers", {}).get(sys.argv[1], {})
print(p.get("state", "absent"), p.get("pfxRcd", 0))' "$2"; }

# Attend que les deux sessions eBGP soient établies avec 2 préfixes (90 s max)
wait_bgp() {
  for _ in $(seq 1 45); do
    [[ "$(bgp_peer r3 172.16.34.2)" == "Established 2" && "$(bgp_peer r4 172.16.34.1)" == "Established 2" ]] && return 0
    sleep 2
  done
  return 1
}

# Attend que chaque routeur ait tous ses voisins OSPF en Full (60 s max)
wait_ospf() {
  for _ in $(seq 1 30); do
    [[ "$(ospf_full r1)$(ospf_full r2)$(ospf_full r3)$(ospf_full r4)$(ospf_full r5)" == "22211" ]] && return 0
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
check "python3 avec module venv"           python3 -m venv --help
(( FAIL > 0 )) && { echo; echo "Prérequis manquants : voir l'étape 0 du README."; exit 1; }

# ---------------------------------------------------------------- 2. Image et déploiement
title "2. Image et déploiement"
check "construction de l'image frr-ssh:10.2.1"  docker build -q -t frr-ssh:10.2.1 docker/
check "déploiement du lab (7 conteneurs)"        containerlab deploy -t lab.clab.yml --reconfigure
running=$(docker ps --filter "name=$LAB-" --filter status=running -q | wc -l)
[[ $running -eq 7 ]] && ok "7 conteneurs en état running" || ko "$running/7 conteneurs en état running"

# ---------------------------------------------------------------- 3. Routage
title "3. Routage (phase 1)"
echo "  … attente de la convergence OSPF/BGP (jusqu'à 90 s)"
if wait_bgp; then ok "eBGP r3 <-> r4 Established, 2 préfixes dans chaque sens"; else ko "eBGP non établi : r3=[$(bgp_peer r3 172.16.34.2)] r4=[$(bgp_peer r4 172.16.34.1)]"; fi
wait_ospf || true
sleep 5   # laisse OSPF recalculer et installer les routes après les dernières adjacences
for spec in r1:2 r2:2 r3:2 r4:1 r5:1; do
  r=${spec%%:*}; want=${spec##*:}; got=$(ospf_full "$r")
  [[ "$got" == "$want" ]] && ok "OSPF $r : $got/$want voisins Full" || ko "OSPF $r : ${got:-0}/$want voisins Full"
done
check "r1 connaît le LAN distant 192.168.2.0/24"  bash -c "docker exec $LAB-r1 vtysh -c 'show ip route 192.168.2.0/24' | grep -q ospf"
check "ping pc1 -> pc2 sans perte"                docker exec "$LAB-pc1" ping -c 3 -W 1 192.168.2.10
for _ in 1 2 3; do
  path=$(route_path)
  [[ "$path" == "r1 r3 r4 r5 pc2" ]] && break
  sleep 5
done
[[ "$path" == "r1 r3 r4 r5 pc2" ]] && ok "chemin r1 -> r3 -> r4 -> r5 -> pc2" || ko "chemin inattendu : $path"

# ---------------------------------------------------------------- 4. Automatisation
title "4. Automatisation (phase 2)"
cd automation || exit 1
if [[ ! -x .venv/bin/python ]]; then
  echo "  … création de l'environnement Python"
  python3 -m venv .venv && .venv/bin/pip install -q --disable-pip-version-check -r requirements.txt
fi
PY=.venv/bin/python
check "dépendances Python (netmiko, yaml)"   $PY -c "import netmiko, yaml"
check "health.py : tout OK (code 0)"         $PY health.py
check "backup.py --baseline (code 0)"        $PY backup.py --baseline
check "drift.py : conforme (code 0)"         $PY drift.py

# ---------------------------------------------------------------- 5. Pannes simulées
title "5. Détection de pannes simulées"
docker exec "$LAB-r2" vtysh -c "conf t" -c "interface eth1" -c "ip ospf cost 50" >/dev/null
docker exec "$LAB-r4" vtysh -c "conf t" -c "router bgp 65002" -c "neighbor 172.16.34.1 shutdown" >/dev/null
sleep 5
$PY health.py >/dev/null 2>&1; rc=$?
[[ $rc -eq 1 ]] && ok "health.py détecte la panne BGP (code 1)" || ko "health.py n'a pas détecté la panne (code $rc)"
out=$($PY drift.py 2>&1); rc=$?
[[ $rc -eq 1 ]] && ok "drift.py signale une dérive (code 1)" || ko "drift.py code $rc au lieu de 1"
grep -q "+ ip ospf cost 50" <<<"$out"                   && ok "dérive r2 identifiée (ip ospf cost 50)"       || ko "dérive r2 non identifiée"
grep -q "+ neighbor 172.16.34.1 shutdown" <<<"$out"     && ok "dérive r4 identifiée (neighbor shutdown)"     || ko "dérive r4 non identifiée"
if docker exec "$LAB-pc1" ping -c 2 -W 1 192.168.2.10 >/dev/null 2>&1; then ko "pc2 encore joignable malgré la coupure BGP"; else ok "pc2 injoignable pendant la panne (attendu)"; fi

# ---------------------------------------------------------------- 6. Retour à la normale
title "6. Retour à la normale"
docker exec "$LAB-r4" vtysh -c "conf t" -c "router bgp 65002" -c "no neighbor 172.16.34.1 shutdown" >/dev/null
docker exec "$LAB-r2" vtysh -c "conf t" -c "interface eth1" -c "no ip ospf cost 50" >/dev/null
if wait_bgp; then ok "session eBGP rétablie"; else ko "session eBGP non rétablie"; fi
check "health.py : tout OK (code 0)"   $PY health.py
check "drift.py : conforme (code 0)"   $PY drift.py
check "ping pc1 -> pc2 rétabli"        docker exec "$LAB-pc1" ping -c 3 -W 1 192.168.2.10
cd ..

# ---------------------------------------------------------------- Bilan
[[ "${1:-}" == "--destroy" ]] && containerlab destroy -t lab.clab.yml --cleanup >/dev/null 2>&1 && echo && echo "Lab détruit."
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab est entièrement fonctionnel." || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
