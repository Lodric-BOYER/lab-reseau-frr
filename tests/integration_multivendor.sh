#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
#
# Scénarios d'intégration netcheck sur le lab multi-constructeurs (Phase E, SPEC_v2.md) :
# S1 (diff, aucun changement), coupure du lien r4 <-> r5 (FRR <-> SR Linux), C1 (conformité).
# Portée volontairement réduite par rapport à tests/integration.sh (S2-S5, C2, guard) : ce
# fichier vérifie que netcheck fonctionne bien SUR LES DEUX DRIVERS À LA FOIS, pas de
# redémontrer tout ce qui l'est déjà côté FRR seul.
#   bash tests/integration_multivendor.sh
# Code retour : 0 si tous les scénarios passent, 1 sinon. Le lab est laissé démarré et dans
# son état nominal (chaque scénario annule son propre changement avant de rendre la main).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LAB=clab-frr-lab-multivendor
NC="netcheck/.venv/bin/python -m netcheck"
INV=(-i automation/inventory-multivendor.yml)  # doit venir APRÈS la sous-commande (argparse)
JSON_DIR=/tmp/netcheck_integration_multivendor
mkdir -p "$JSON_DIR"

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }

# Voisins OSPF Full sur r4 (FRR, vtysh) et r5 (SR Linux, sr_cli) : deux commandes différentes,
# un seul critère de convergence -- comme wait_ospf() dans test_lab_multivendor.sh.
ospf_full_r4() { docker exec "$LAB-r4" vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c Full; }
ospf_full_r5() { docker exec "$LAB-r5" sr_cli -- "show network-instance default protocols ospf neighbor" 2>&1 | grep -ci full; }

wait_converged() {
  for _ in $(seq 1 20); do
    [[ "$(ospf_full_r4)" == "1" && "$(ospf_full_r5)" == "1" ]] && return 0
    sleep 3
  done
  return 1
}
wait_link_down() {
  for _ in $(seq 1 20); do
    [[ "$(ospf_full_r4)" == "0" && "$(ospf_full_r5)" == "0" ]] && return 0
    sleep 3
  done
  return 1
}

run_diff() {
  local id="$1" expect_code="$2" expect_verdict="$3" expect_pattern="$4"
  local out; out=$($NC diff "${id}_avant" "${id}_apres" --json "$JSON_DIR/${id}.json" "${INV[@]}" 2>&1); local code=$?

  [[ "$code" == "$expect_code" ]] && ok "code retour = $expect_code" || ko "code retour = $code (attendu $expect_code)"
  echo "$out" | grep -q "Verdict : $expect_verdict" && ok "verdict = $expect_verdict" \
    || { ko "verdict inattendu (attendu $expect_verdict)"; echo "$out"; }
  if [[ -n "$expect_pattern" ]]; then
    grep -qE "$expect_pattern" "$JSON_DIR/${id}.json" && ok "constat attendu présent ($expect_pattern)" \
      || { ko "constat manquant : $expect_pattern"; cat "$JSON_DIR/${id}.json"; }
  fi
}

# ---------------------------------------------------------------- S1 : aucun changement
title "S1 : aucun changement -> OK"
$NC snapshot s1_avant --force "${INV[@]}" >/dev/null
sleep 3
$NC snapshot s1_apres --force "${INV[@]}" >/dev/null
run_diff s1 0 OK ""

# ---------------------------------------------------------------- S2 : coupure du lien r4<->r5
title "S2 : ip link set eth2 down sur r4 (lien FRR <-> SR Linux) -> ÉCHEC"
$NC snapshot s2_avant --force "${INV[@]}" >/dev/null

docker exec "$LAB-r4" ip link set eth2 down
wait_link_down && ok "voisin OSPF perdu des deux côtés (poll actif)" \
  || ko "voisin OSPF encore présent d'au moins un côté après 60s"

$NC snapshot s2_apres --force "${INV[@]}" >/dev/null

docker exec "$LAB-r4" ip link set eth2 up
wait_converged && ok "retour à la normale : OSPF Full des deux côtés" \
  || ko "OSPF non reconvergé après restauration du lien"

run_diff s2 2 ÉCHEC 'voisin OSPF perdu'
# Vue depuis r4 (FRR) : le voisin r5 (10.2.255.5) disparaît de ses voisins Full.
grep -q '"device": "r4"' "$JSON_DIR/s2.json" && ok "constat localisé sur r4 (FRR)" \
  || { ko "r4 absent du rapport"; cat "$JSON_DIR/s2.json"; }
# Vue depuis r5 (SR Linux) : le voisin r4 (10.2.255.4) disparaît de ses voisins Full.
grep -q '"device": "r5"' "$JSON_DIR/s2.json" && ok "constat localisé sur r5 (SR Linux)" \
  || { ko "r5 absent du rapport"; cat "$JSON_DIR/s2.json"; }
# Route vers le LAN distant (192.168.2.0/24, derrière r5) perdue, vue depuis r1.
grep -q 'préfixe injoignable : 192.168.2.0/24' "$JSON_DIR/s2.json" \
  && ok "route 192.168.2.0/24 signalée injoignable" \
  || { ko "perte de route vers 192.168.2.0/24 non signalée"; cat "$JSON_DIR/s2.json"; }

# ---------------------------------------------------------------- C1 : conformité nominale
title "C1 : lab mixte dans son état nominal -> conforme"
out=$($NC check --json "$JSON_DIR/c1.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "conformité = CONFORME" \
  || { ko "conformité inattendue"; echo "$out"; }
# Les règles SR Linux doivent apparaître évaluées (ni absentes, ni en violation) : présentes
# quelque part dans le rapport (comme "non applicable" pour r1-r4, ou simplement non listées
# en violation pour r5, ce que confirme déjà le verdict CONFORME ci-dessus).
grep -q 'srlinux-mtu-marge-suffisante' "$JSON_DIR/c1.json" && ok "règle SR Linux présente dans le rapport" \
  || { ko "règle SR Linux absente du rapport"; cat "$JSON_DIR/c1.json"; }

# ---------------------------------------------------------------- Bilan
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab multi-constructeurs est conforme au cahier des charges (netcheck)." \
                || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
