#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
# Scénarios d'intégration netcheck (S1 à S5, §6 du cahier des charges) sur le lab déployé.
#   bash tests/integration.sh
# Code retour : 0 si tous les scénarios passent, 1 sinon. Le lab est laissé démarré et dans
# son état nominal (chaque scénario annule son propre changement avant de rendre la main).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LAB=clab-frr-lab
NC="netcheck/.venv/bin/python -m netcheck"
HEALTH="automation/.venv/bin/python automation/health.py"
JSON_DIR=/tmp/netcheck_integration
mkdir -p "$JSON_DIR"

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }

# Exécute plusieurs commandes vtysh en une seule session (mode configuration).
vtconf() { local r="$1"; shift; local args=(); for c in "$@"; do args+=(-c "$c"); done
  docker exec "$LAB-$r" vtysh "${args[@]}" >/dev/null; }
vt() { docker exec "$LAB-$1" vtysh -c "$2" >/dev/null; }

wait_healthy() { for _ in $(seq 1 30); do $HEALTH >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

# Snapshot -> diff (avec rapport JSON) -> vérifie code retour + verdict + un motif dans le JSON.
run_diff() {
  local id="$1" expect_code="$2" expect_verdict="$3" expect_pattern="$4"
  local out; out=$($NC diff "${id}_avant" "${id}_apres" --json "$JSON_DIR/${id}.json" 2>&1); local code=$?

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
$NC snapshot s1_avant --force >/dev/null
sleep 3
$NC snapshot s1_apres --force >/dev/null
run_diff s1 0 OK ""

# ---------------------------------------------------------------- S2 : coût OSPF sur r1 eth2
title "S2 : ip ospf cost 100 sur r1 eth2 -> ATTENTION"
$NC snapshot s2_avant --force >/dev/null
vtconf r1 "conf t" "interface eth2" "ip ospf cost 100"
sleep 5
$NC snapshot s2_apres --force >/dev/null
vtconf r1 "conf t" "interface eth2" "no ip ospf cost 100"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s2 1 ATTENTION '"category": "next_hop"'

# ---------------------------------------------------------------- S3 : lien OSPF coupé
title "S3 : ip link set eth2 down sur r1 -> ÉCHEC"
$NC snapshot s3_avant --force >/dev/null
docker exec "$LAB-r1" ip link set eth2 down
sleep 5
$NC snapshot s3_apres --force >/dev/null
docker exec "$LAB-r1" ip link set eth2 up
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s3 2 ÉCHEC 'voisin OSPF perdu|passée à l.état down'

# ---------------------------------------------------------------- S4 : session BGP coupée
title "S4 : neighbor 172.16.34.1 shutdown sur r4 -> ÉCHEC"
$NC snapshot s4_avant --force >/dev/null
vtconf r4 "conf t" "router bgp 65002" "neighbor 172.16.34.1 shutdown"
sleep 5
$NC snapshot s4_apres --force >/dev/null
vtconf r4 "conf t" "router bgp 65002" "no neighbor 172.16.34.1 shutdown"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s4 2 ÉCHEC '"category": "bgp_session"'

# ---------------------------------------------------------------- S5 : politique BGP (retrait de préfixe)
title "S5 : retrait de 192.168.1.0/24 de PL-EBGP-OUT sur r3 -> ÉCHEC"
$NC snapshot s5_avant --force >/dev/null
vtconf r3 "conf t" "no ip prefix-list PL-EBGP-OUT seq 20 permit 192.168.1.0/24"
vt r3 "clear bgp ipv4 * soft out"
sleep 5
$NC snapshot s5_apres --force >/dev/null
vtconf r3 "conf t" "ip prefix-list PL-EBGP-OUT seq 20 permit 192.168.1.0/24"
vt r3 "clear bgp ipv4 * soft out"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s5 2 ÉCHEC 'préfixe BGP perdu : 192.168.1.0/24'

# ---------------------------------------------------------------- C1 : conformité nominale
title "C1 : aucun changement -> conforme"
out=$($NC check --json "$JSON_DIR/c1.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "conformité = CONFORME" \
  || { ko "conformité inattendue"; echo "$out"; }

# ---------------------------------------------------------------- C2 : politique BGP retirée
title "C2 : suppression de route-map RM-EBGP-IN in sur r3 -> non conforme"
vtconf r3 "conf t" "router bgp 65001" "no neighbor 172.16.34.2 route-map RM-EBGP-IN in"
out=$($NC check --json "$JSON_DIR/c2.json" 2>&1); code=$?
vtconf r3 "conf t" "router bgp 65001" "neighbor 172.16.34.2 route-map RM-EBGP-IN in"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"

[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
echo "$out" | grep -q "Conformité : NON CONFORME" && ok "conformité = NON CONFORME" \
  || { ko "conformité inattendue"; echo "$out"; }
grep -q "ebgp-politique-entrante" "$JSON_DIR/c2.json" && ok "règle 'ebgp-politique-entrante' signalée" \
  || { ko "règle attendue absente du rapport"; cat "$JSON_DIR/c2.json"; }
grep -q '"device": "r3"' "$JSON_DIR/c2.json" && ok "non-conformité localisée sur r3" \
  || ko "équipement r3 absent du rapport"

# ---------------------------------------------------------------- A1 : état attendu, nominal
title "A1 : état attendu (assert) -> OK, en direct et hors ligne"
out=$($NC assert --intent intents/lab.yml --json "$JSON_DIR/a1_direct.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "en direct : code retour = 0" || { ko "en direct : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "en direct : verdict = OK" || { ko "verdict inattendu"; echo "$out"; }

$NC snapshot a1_hors_ligne --force >/dev/null
out=$($NC assert --intent intents/lab.yml --snapshot a1_hors_ligne --json "$JSON_DIR/a1_snapshot.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "hors ligne : code retour = 0" || { ko "hors ligne : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "hors ligne : verdict = OK" || { ko "verdict inattendu (hors ligne)"; echo "$out"; }

# ---------------------------------------------------------------- A2 : coupure du lien r4<->r5
title "A2 : ip link set eth2 down sur r4 (lien vers r5) -> ÉCHEC (assert)"
docker exec "$LAB-r4" ip link set eth2 down
sleep 15
out=$($NC assert --intent intents/lab.yml --json "$JSON_DIR/a2.json" 2>&1); code=$?
docker exec "$LAB-r4" ip link set eth2 up
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"

[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
echo "$out" | grep -q "Verdict : ÉCHEC" && ok "verdict = ÉCHEC" || { ko "verdict inattendu"; echo "$out"; }
grep -q '"id": "chemin-r1-vers-lan-r5"' "$JSON_DIR/a2.json" && grep -q "trou noir" "$JSON_DIR/a2.json" \
  && ok "assertion 'path' en ÉCHEC avec la raison 'trou noir'" \
  || { ko "constat 'path' attendu manquant"; cat "$JSON_DIR/a2.json"; }
grep -q '"id": "interface-r4-vers-r5"' "$JSON_DIR/a2.json" && ok "assertion 'interface_up' présente dans le rapport" \
  || ko "assertion 'interface_up' absente du rapport"

# ---------------------------------------------------------------- Guard : encadre S2 via --change
title "Guard : encadre S2 (coût OSPF) via --change --yes"
cat > "$JSON_DIR/guard_change.sh" <<'EOF'
#!/bin/bash
docker exec clab-frr-lab-r1 vtysh -c 'conf t' -c 'interface eth2' -c 'ip ospf cost 100'
EOF
out=$($NC guard --change "$JSON_DIR/guard_change.sh" --yes --wait 30 --json "$JSON_DIR/guard.json" 2>&1); code=$?
docker exec "$LAB-r1" vtysh -c "conf t" -c "interface eth2" -c "no ip ospf cost 100" >/dev/null
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"

[[ "$code" == "1" ]] && ok "code retour = 1 (ATTENTION)" || { ko "code retour = $code (attendu 1)"; echo "$out"; }
echo "$out" | grep -q "Verdict : ATTENTION" && ok "verdict = ATTENTION" || { ko "verdict inattendu"; echo "$out"; }
# Si --yes n'avait pas sauté la confirmation, input() aurait échoué (EOFError) ou bloqué : le
# fait d'obtenir un verdict complet et correct prouve que --yes a fonctionné.
grep -q '"category": "next_hop"' "$JSON_DIR/guard.json" && ok "constat next_hop présent (effet réel de --change)" \
  || { ko "constat manquant"; cat "$JSON_DIR/guard.json"; }
$NC list 2>/dev/null | grep -q "guard_" && ok "snapshots avant/après horodatés créés par guard" \
  || ko "aucun snapshot 'guard_*' trouvé"

# ---------------------------------------------------------------- Bilan
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Tous les scénarios netcheck sont conformes au cahier des charges." \
                || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
