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
NC_PY="netcheck/.venv/bin/python"
HEALTH="automation/.venv/bin/python automation/health.py"
JSON_DIR=/tmp/netcheck_integration
mkdir -p "$JSON_DIR"

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }

# Clés d'hôte (phase C1) : strict par défaut. Les clés du lab sont lues DANS les conteneurs et épinglées
# dans le known_hosts dédié (jamais le ~/.ssh/known_hosts) ; à refaire après chaque déploiement.
export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
# shellcheck source=tests/lib_hostkeys.sh
source "$(dirname "$0")/lib_hostkeys.sh"
bash lab-access/pin_hostkeys.sh frr >/dev/null || { echo "épinglage des clés d'hôte impossible (lab déployé ?)"; exit 1; }

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

# ---------------------------------------------------------------- S6 : session BGP IPv6 coupée (phase B2)
title "S6 : neighbor 2001:db8:34::2 shutdown sur r4 (IPv6 seul) -> ÉCHEC"
$NC snapshot s6_avant --force >/dev/null
vtconf r4 "conf t" "router bgp 65002" "neighbor 2001:db8:34::2 shutdown"
sleep 5
$NC snapshot s6_apres --force >/dev/null
vtconf r4 "conf t" "router bgp 65002" "no neighbor 2001:db8:34::2 shutdown"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s6 2 ÉCHEC 'session BGP 2001:db8:34::'
# La panne est propre à l'IPv6 : aucun constat ne parle de la session IPv4 ni d'un préfixe IPv4.
grep -q 'session BGP 172.16.34' "$JSON_DIR/s6.json" && ko "la session IPv4 est signalée alors que seule l'IPv6 est coupée" \
  || ok "aucun constat sur la session IPv4 (la panne est propre à l'IPv6)"

# ---------------------------------------------------------------- S7 : voisin OSPFv3 perdu (phase B2)
title "S7 : ipv6 ospf6 passive sur r1 eth2 (OSPFv3 seul) -> ÉCHEC"
$NC snapshot s7_avant --force >/dev/null
vtconf r1 "conf t" "interface eth2" "ipv6 ospf6 passive"
sleep 8
$NC snapshot s7_apres --force >/dev/null
vtconf r1 "conf t" "interface eth2" "no ipv6 ospf6 passive"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
run_diff s7 2 ÉCHEC '"category": "ospf6_neighbor"'
grep -q 'voisin OSPF perdu' "$JSON_DIR/s7.json" && ko "un voisin OSPFv2 est signalé alors que seul l'OSPFv3 est touché" \
  || ok "aucun voisin OSPFv2 signalé (la panne est propre à l'OSPFv3)"

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

# Les deux fichiers de règles et la dérogation du lab, à une date FIXE (--today) : le scénario ne dépend pas du
# calendrier (la dérogation du lab expire le 2027-01-04).
SEC=(--rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml)
DER=derogations/lab.yml

# ---------------------------------------------------------------- C3 : dérogations (phase B3)
title "C3 : check (règles IPv6 + dérogation du lab) -> conforme, le lien r4-r5 en DÉROGATION"
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c3.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "conformité = CONFORME" || { ko "conformité inattendue"; echo "$out"; }
$NC_PY - "$JSON_DIR/c3.json" "$DER" <<'PY' && ok "JSON : 2 violations en DÉROGATION (r4 eth2, r5 eth1), 0 active, empreinte SHA-256 du fichier" || ko "JSON des dérogations inattendu"
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
d = data["derogations"]
covered = sorted((x["device"], x["object"], x["status"]) for x in d["derogated"])
sha = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
ok = (data["violations"] == [] and data["summary"]["derogated"] == 2 and d["file"]["sha256"] == sha
      and covered == [("r4", "eth2", "DÉROGATION"), ("r5", "eth1", "DÉROGATION")] and "coverage_notes" not in data)
sys.exit(0 if ok else 1)
PY
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2027-01-05 2>&1); code=$?
[[ "$code" == "2" ]] && echo "$out" | grep -q "expirée le 2027-01-04" \
  && ok "après la date d'expiration (--today 2027-01-05) : de nouveau code 2, « expirée le 2027-01-04 » dit" \
  || { ko "dérogation expirée mal gérée (code $code)"; echo "$out"; }


# ---------------------------------------------------------------- C3b : l'IPv6 n'est jamais un silence (phase B4)
title "C3b : security.yml SEUL sur ce lab en double pile -> information de couverture (« IPv6 configuré, aucune règle IPv6 chargée »)"
out=$($NC check --rules netcheck/rules/security.yml --json "$JSON_DIR/c3b.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0 (l'information ne change pas le verdict)" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | tr -s '[:space:]' ' ' | grep -q "aucune règle IPv6 chargée" \
  && ok "terminal : l'absence de règle IPv6 est dite" || { ko "terminal : information de couverture absente"; echo "$out"; }
$NC_PY - "$JSON_DIR/c3b.json" <<'PY' && ok "JSON : coverage_notes nomme r1 à r5, compté à part (summary.coverage_notes = 1)" || ko "JSON : information de couverture inattendue"
import json, sys
data = json.load(open(sys.argv[1]))
note = data["coverage_notes"][0]
sys.exit(0 if (note["kind"] == "ipv6-sans-regle" and note["devices"] == ["r1", "r2", "r3", "r4", "r5"]
               and data["summary"]["coverage_notes"] == 1 and data["violations"] == []) else 1)
PY

# ---------------------------------------------------------------- C4 : authentification OSPFv3 retirée (phase B3)
title "C4 : suppression de l'authentification OSPFv3 de r1 eth1 -> NON CONFORME (r1 eth1, hors dérogation), puis retour prouvé"
$NC snapshot c4_avant --force >/dev/null
vtconf r1 "conf t" "interface eth1" "no ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key lab-ospf-v3r1r2"
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c4.json" 2>&1); code=$?
vtconf r1 "conf t" "interface eth1" "ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key lab-ospf-v3r1r2"
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
$NC_PY - "$JSON_DIR/c4.json" <<'PY' && ok "violation ospf6-authentification sur r1 eth1, les 2 dérogations du lab intactes" || ko "violation attendue absente ou dérogations altérées"
import json, sys
data = json.load(open(sys.argv[1]))
v = [(x["rule_id"], x["device"], x["object"]) for x in data["violations"]]
sys.exit(0 if v == [("ospf6-authentification", "r1", "eth1")] and data["summary"]["derogated"] == 2 else 1)
PY
sleep 10
$NC snapshot c4_maintenant --force >/dev/null
out=$($NC diff c4_avant c4_maintenant 2>&1); code=$?
[[ "$code" == "0" ]] && echo "$out" | grep -q "Aucun constat" \
  && ok "preuve de retour : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || { ko "l'état actuel diffère de l'état d'avant (code $code)"; echo "$out"; }
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 2>&1); code=$?
[[ "$code" == "0" ]] && ok "check de nouveau conforme après le retour" || { ko "check non conforme après le retour"; echo "$out"; }

# ---------------------------------------------------------------- C5 : ::/0 et préfixe local autorisés en entrée (phase B3)
title "C5 : ::/0 puis 2001:db8:1::/48 ajoutés à PL6-EBGP-IN sur r3 -> NON CONFORME des deux règles IPv6, puis retour"
for item in "default:permit ::/0:ebgp-pas-de-route-par-defaut" "own:permit 2001:db8:1::/48:ebgp-pas-de-reinjection-de-prefixes-locaux"; do
  name=${item%%:*}; rest=${item#*:}; entry=${rest%:*}; rule_id=${rest##*:}
  vtconf r3 "conf t" "ipv6 prefix-list PL6-EBGP-IN seq 30 $entry"
  out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c5_$name.json" 2>&1); code=$?
  vtconf r3 "conf t" "no ipv6 prefix-list PL6-EBGP-IN seq 30 $entry"
  [[ "$code" == "2" ]] && ok "$name : code retour = 2" || { ko "$name : code retour = $code (attendu 2)"; echo "$out"; }
  $NC_PY - "$JSON_DIR/c5_$name.json" "$rule_id" <<'PY' && ok "$name : violation $rule_id sur r3, voisin 2001:db8:34::3" || ko "$name : violation $rule_id manquante"
import json, sys
data = json.load(open(sys.argv[1]))
v = [(x["rule_id"], x["device"], x["object"]) for x in data["violations"]]
sys.exit(0 if v == [(sys.argv[2], "r3", "2001:db8:34::3")] else 1)
PY
done
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 2>&1); code=$?
[[ "$code" == "0" ]] && ok "check de nouveau conforme après le retour" || { ko "check non conforme après le retour"; echo "$out"; }


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

# ---------------------------------------------------------------- A3 : coupure de l'IPv6 seul (phase B2)
title "A3 : eBGP IPv6 coupé sur r4 -> ÉCHEC en IPv6, l'IPv4 reste OK (assert)"
docker exec "$LAB-r4" vtysh -c "conf t" -c "router bgp 65002" -c "neighbor 2001:db8:34::2 shutdown" >/dev/null
sleep 15
out=$($NC assert --intent intents/lab.yml --json "$JSON_DIR/a3.json" 2>&1); code=$?
docker exec "$LAB-r4" vtysh -c "conf t" -c "router bgp 65002" -c "no neighbor 2001:db8:34::2 shutdown" >/dev/null
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"

[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
echo "$out" | grep -q "Verdict : ÉCHEC" && ok "verdict = ÉCHEC" || { ko "verdict inattendu"; echo "$out"; }
for id in bgp6-r3-vers-r4 chemin6-r1-vers-lan-r5; do
  $NC_PY - "$JSON_DIR/a3.json" "$id" ÉCHEC <<'PY' && ok "assertion IPv6 '$id' en ÉCHEC" || ko "assertion IPv6 '$id' pas en ÉCHEC"
import json, sys
results = {r["id"]: r["status"] for r in json.load(open(sys.argv[1]))["results"]}
sys.exit(0 if results.get(sys.argv[2]) == sys.argv[3] else 1)
PY
done
for id in bgp-r3-vers-r4 chemin-r1-vers-lan-r5 ospf6-r1-voisins vrf-demo-r2-route-rejet; do
  $NC_PY - "$JSON_DIR/a3.json" "$id" OK <<'PY' && ok "assertion '$id' toujours OK (IPv4, OSPFv3, VRF intacts)" || ko "assertion '$id' pas OK"
import json, sys
results = {r["id"]: r["status"] for r in json.load(open(sys.argv[1]))["results"]}
sys.exit(0 if results.get(sys.argv[2]) == sys.argv[3] else 1)
PY
done

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

# ---------------------------------------------------------------- D1 : changement prévu (--expect)
title "D1 : ip ospf cost 100 sur r1 eth2, avec son --expect -> OK (guard, puis rejeu hors ligne)"
out=$($NC guard --change "$JSON_DIR/guard_change.sh" --expect tests/expect/ospf-cost-r1.yml --yes --wait 30 \
  --json "$JSON_DIR/d1_guard.json" 2>&1); code=$?
docker exec "$LAB-r1" vtysh -c "conf t" -c "interface eth2" -c "no ip ospf cost 100" >/dev/null
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après restauration"

[[ "$code" == "0" ]] && ok "code retour = 0 (changement prévu, état attendu vérifié)" \
  || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "verdict = OK" || { ko "verdict inattendu"; echo "$out"; }
echo "$out" | grep -q "PRÉVU" && ok "constats affichés comme PRÉVUS" || ko "aucun constat PRÉVU affiché"
grep -q '"planned": true' "$JSON_DIR/d1_guard.json" && ! grep -q '"planned": false' "$JSON_DIR/d1_guard.json" \
  && ok "JSON : tous les constats sont prévus" || { ko "JSON : constat non prévu"; cat "$JSON_DIR/d1_guard.json"; }
grep -q '"status": "OK"' "$JSON_DIR/d1_guard.json" && ! grep -q '"status": "ÉCHEC"' "$JSON_DIR/d1_guard.json" \
  && ok "JSON : assertions 'after' toutes OK (dont le chemin r1 r2 r3 r4 r5)" \
  || { ko "JSON : assertion 'after' en échec"; cat "$JSON_DIR/d1_guard.json"; }

# Rejeu hors ligne des snapshots de S2 (même changement) : "diff --expect".
out=$($NC diff s2_avant s2_apres --expect tests/expect/ospf-cost-r1.yml 2>&1); code=$?
[[ "$code" == "0" ]] && ok "rejeu hors ligne (diff --expect) : code retour = 0" \
  || { ko "rejeu hors ligne : code retour = $code (attendu 0)"; echo "$out"; }

# Garde-fou : le fichier qui oublie l'effet de bord sur r2 ne masque PAS ce constat.
out=$($NC diff s2_avant s2_apres --expect tests/expect/ospf-cost-r1-sans-r2.yml --json "$JSON_DIR/d1_sans_r2.json" 2>&1); code=$?
[[ "$code" == "1" ]] && ok "effet de bord oublié (r2) : code retour = 1 (ATTENTION)" \
  || { ko "code retour = $code (attendu 1)"; echo "$out"; }
grep -q '"planned": false' "$JSON_DIR/d1_sans_r2.json" && grep -q '"device": "r2"' "$JSON_DIR/d1_sans_r2.json" \
  && ok "le constat de r2 reste NON prévu" || ko "constat r2 absent ou masqué"

# Garde-fou : un critère trop large est refusé avant toute action (code 3).
printf 'findings:\n  - id: tout\n    description: x\n    device: r1\n    category: next_hop\n    pattern: ".*"\n' \
  > "$JSON_DIR/expect_trop_large.yml"
out=$($NC diff s2_avant s2_apres --expect "$JSON_DIR/expect_trop_large.yml" 2>&1); code=$?
[[ "$code" == "3" ]] && echo "$out" | grep -q "trop large" && ok "motif '.*' refusé (code 3)" \
  || { ko "motif trop large non refusé (code $code)"; echo "$out"; }

# ---------------------------------------------------------------- D2 : retour arrière
# Scripts fournis par le test (guard n'exécute jamais que des scripts de l'utilisateur, C13).
cat > "$JSON_DIR/break_change.sh" <<'EOF'
#!/bin/bash
docker exec clab-frr-lab-r1 ip link set eth2 down
EOF
cat > "$JSON_DIR/rollback_ok.sh" <<'EOF'
#!/bin/bash
docker exec clab-frr-lab-r1 ip link set eth2 up
EOF
cat > "$JSON_DIR/rollback_noop.sh" <<'EOF'
#!/bin/bash
echo "annulation qui ne répare rien"
EOF
cat > "$JSON_DIR/change_fails.sh" <<'EOF'
#!/bin/bash
echo "le changement échoue" >&2
exit 7
EOF
cat > "$JSON_DIR/change_slow.sh" <<'EOF'
#!/bin/bash
sleep 60
EOF
printf '#!/bin/bash\ntouch %s\n' "$JSON_DIR/rollback_marker" > "$JSON_DIR/rollback_marker.sh"
# Journal de guard le plus récent (par date de modification), sans parser la sortie de ls.
latest_journal() {
  local f newest=""
  for f in reports/guard_*.json; do
    [[ -e "$f" ]] || continue
    [[ -z "$newest" || "$f" -nt "$newest" ]] && newest="$f"
  done
  echo "$newest"
}

title "D2a : coupure de r1 eth2 + rollback valide -> annulé avec succès (code 4), état initial prouvé"
out=$($NC guard --change "$JSON_DIR/break_change.sh" --rollback "$JSON_DIR/rollback_ok.sh" --yes --wait 40 2>&1); code=$?
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après guard"
[[ "$code" == "4" ]] && ok "code retour = 4 (échec annulé avec succès)" || { ko "code retour = $code (attendu 4)"; echo "$out"; }
echo "$out" | grep -q "ANNULÉ AVEC SUCCÈS" && ok "message final : annulé avec succès" || ko "message final absent"
journal=$(latest_journal)
grep -q '"final_state": "ROLLED_BACK"' "$journal" && grep -q '"clean": true' "$journal" \
  && ok "journal : ROLLED_BACK, preuve du retour propre ($journal)" || { ko "journal inattendu"; cat "$journal"; }
avant=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['snapshots']['avant'])" "$journal")
$NC snapshot d2a_maintenant --force >/dev/null
out=$($NC diff "$avant" d2a_maintenant 2>&1); code=$?
[[ "$code" == "0" ]] && echo "$out" | grep -q "Aucun constat" \
  && ok "preuve indépendante : l'état actuel est identique à l'« avant » de guard (aucun constat)" \
  || { ko "l'état actuel diffère de l'état initial (code $code)"; echo "$out"; }

title "D2b : coupure de r1 eth2 + rollback qui ne répare rien -> annulation échouée (code 5)"
out=$($NC guard --change "$JSON_DIR/break_change.sh" --rollback "$JSON_DIR/rollback_noop.sh" --yes --wait 15 2>&1); code=$?
docker exec "$LAB-r1" ip link set eth2 up   # le test remet lui-même le lab en état
wait_healthy && ok "retour à la normale (health.py, lien rétabli par le test)" || ko "health.py toujours KO"
[[ "$code" == "5" ]] && ok "code retour = 5 (annulation échouée)" || { ko "code retour = $code (attendu 5)"; echo "$out"; }
echo "$out" | grep -q "ANNULATION ÉCHOUÉE" && echo "$out" | grep -q "N'EST PAS DANS SON ÉTAT INITIAL" \
  && ok "message final très visible (annulation échouée, réseau pas dans son état initial)" \
  || { ko "message d'alarme absent"; echo "$out"; }
grep -q '"final_state": "ROLLBACK_FAILED"' "$(latest_journal)" && ok "journal : ROLLBACK_FAILED" \
  || ko "journal : état final inattendu"

title "D2c : script de changement en échec, sans --rollback -> code 2 (changement de comportement v0.3)"
out=$($NC guard --change "$JSON_DIR/change_fails.sh" --yes --wait 5 2>&1); code=$?
[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
grep -q '"final_state": "FAILED_NO_ROLLBACK"' "$(latest_journal)" && ok "journal : FAILED_NO_ROLLBACK" \
  || ko "journal : état final inattendu"

title "D2d : SIGTERM pendant le script de changement -> INTERROMPU (code 6), AUCUNE annulation lancée"
rm -f "$JSON_DIR/rollback_marker"
touch "$JSON_DIR/d2d_debut"
$NC guard --change "$JSON_DIR/change_slow.sh" --rollback "$JSON_DIR/rollback_marker.sh" --yes --wait 5 \
  > "$JSON_DIR/d2d.out" 2>&1 &
guard_pid=$!
for _ in $(seq 1 30); do   # attend que guard soit réellement DANS le script de changement
  journal=$(find reports -name 'guard_*.json' -newer "$JSON_DIR/d2d_debut" 2>/dev/null | head -1)
  [[ -n "$journal" ]] && grep -q '"current_step": "script_changement"' "$journal" && break
  sleep 1
done
kill -TERM "$guard_pid"; wait "$guard_pid"; code=$?
[[ "$code" == "6" ]] && ok "code retour = 6 (interrompu)" || { ko "code retour = $code (attendu 6)"; cat "$JSON_DIR/d2d.out"; }
grep -q "l'annulation n'a PAS été lancée" "$JSON_DIR/d2d.out" && ok "message : l'annulation n'a PAS été lancée" \
  || { ko "message d'interruption absent"; cat "$JSON_DIR/d2d.out"; }
[[ ! -e "$JSON_DIR/rollback_marker" ]] && ok "le script d'annulation n'a jamais tourné" \
  || ko "le script d'annulation a tourné malgré l'interruption"
grep -q '"final_state": "INTERRUPTED"' "$journal" && grep -q '"step": "script_changement"' "$journal" \
  && ok "journal : INTERRUPTED, étape script_changement" || { ko "journal inattendu"; cat "$journal"; }
wait_healthy && ok "réseau intact (le script bloqué n'a rien modifié)" || ko "health.py KO"

# ---------------------------------------------------------------- E1 : monitor + alertes (Phase E)
title "E1 : monitor -- panne -> UNE alerte, rien ensuite, réparation -> retour à la normale (serveur local)"
E_STATE="$JSON_DIR/e1_state.json"; E_LOG="$JSON_DIR/e1_messages.jsonl"; E_PORT="$JSON_DIR/e1_port"
E_OUT="$JSON_DIR/e1_all_output.txt"
rm -f "$E_STATE" "$E_STATE.lock" "$E_STATE.corrupt" "$E_PORT" "$E_OUT"
# La référence ne doit pas être prise PENDANT une reconvergence (le scénario précédent vient de
# rétablir un lien : health.py est vert dès que OSPF/BGP sont montés, avant que les routes aient
# fini de se recalculer). On attend donc un réseau STABLE : deux relevés espacés de 4 s sans constat.
wait_stable() {
  for _ in $(seq 1 15); do
    $NC snapshot e1_stable_a --force >/dev/null 2>&1; sleep 4
    $NC snapshot e1_stable_b --force >/dev/null 2>&1
    $NC diff e1_stable_a e1_stable_b >/dev/null 2>&1 && return 0
  done
  return 1
}
wait_stable && ok "réseau stable avant la référence (deux relevés identiques)" || ko "réseau jamais stable"
$NC snapshot e1_nominal --force >/dev/null
python3 tests/tools/webhook_recorder.py --port-file "$E_PORT" --log "$E_LOG" &
recorder_pid=$!
for _ in $(seq 1 50); do [[ -s "$E_PORT" ]] && break; sleep 0.2; done
[[ -s "$E_PORT" ]] && ok "récepteur de webhook local démarré (127.0.0.1, aucun appel externe)" \
  || ko "récepteur de webhook non démarré"
E_SECRET="SENTINEL-WEBHOOK-TOKEN-4f9c2a"
E_PORT_NUMBER=$(cat "$E_PORT")
export NETCHECK_WEBHOOK_URL="http://127.0.0.1:$E_PORT_NUMBER/hook/$E_SECRET"
mon() { $NC monitor --baseline e1_nominal --intent intents/lab.yml --state-file "$E_STATE" 2>&1; }
count_msgs() { wc -l < "$E_LOG" | tr -d ' '; }
msg_field() {   # msg_field N champ : champ du N-ième message reçu (corps JSON)
  python3 -c "import json,sys; print(json.loads(open(sys.argv[1]).read().splitlines()[int(sys.argv[2])-1])['body'][sys.argv[3]])" \
    "$E_LOG" "$1" "$2"
}

out=$(mon); code=$?; echo "$out" >> "$E_OUT"
[[ "$code" == "0" && "$(count_msgs)" == "0" ]] && ok "relevé sain : code 0, aucune alerte (première exécution OK)" \
  || { ko "relevé sain : code $code, $(count_msgs) message(s)"; echo "$out"; }

docker exec "$LAB-r1" ip link set eth2 down
sleep 5
out=$(mon); code=$?; echo "$out" >> "$E_OUT"
[[ "$code" == "2" ]] && ok "panne : code retour = 2" || { ko "panne : code $code (attendu 2)"; echo "$out"; }
[[ "$(count_msgs)" == "1" ]] && ok "panne : UNE alerte reçue" || { ko "panne : $(count_msgs) message(s) (attendu 1)"; echo "$out"; }
[[ "$(msg_field 1 status)" == "ECHEC" && "$(msg_field 1 previous_status)" == "OK" ]] \
  && ok "alerte : OK -> ÉCHEC" || ko "alerte : statuts inattendus"

out=$(mon); code=$?; echo "$out" >> "$E_OUT"
[[ "$code" == "2" && "$(count_msgs)" == "1" ]] && echo "$out" | grep -q "statut inchangé" \
  && ok "deuxième exécution sans changement : toujours 1 seul message (aucune alerte)" \
  || { ko "deuxième exécution : code $code, $(count_msgs) message(s)"; echo "$out"; }

# Verrou : une exécution en cours -> la nouvelle s'arrête proprement (code 4), sans alerte ni état modifié.
# Le détenteur est UN seul processus : un `flock ... sleep` laisserait le fils `sleep` hériter du
# verrou après la mort de `flock`, et il resterait tenu après notre kill.
python3 -c 'import fcntl, sys, time; f = open(sys.argv[1], "a"); fcntl.flock(f, fcntl.LOCK_EX); time.sleep(60)' \
  "$E_STATE.lock" &
locker_pid=$!
sleep 1
out=$(mon); code=$?; echo "$out" >> "$E_OUT"
kill "$locker_pid" 2>/dev/null; wait "$locker_pid" 2>/dev/null
[[ "$code" == "4" && "$(count_msgs)" == "1" ]] && echo "$out" | grep -q "encore en cours" \
  && ok "verrou tenu : code 4, aucune collecte ni alerte" || { ko "verrou : code $code"; echo "$out"; }

docker exec "$LAB-r1" ip link set eth2 up
wait_healthy && ok "retour à la normale (health.py)" || ko "health.py toujours KO après réparation"
# health.py est vert avant la fin du recalcul des routes : on attend que le réseau soit revenu à
# l'état de la RÉFÉRENCE (diff vide) avant de demander à monitor de conclure à « OK ». Un monitor
# lancé trop tôt dit la vérité (état transitoire) : c'est précisément ce que --confirm N amortit.
wait_nominal_again() {
  for _ in $(seq 1 30); do
    $NC snapshot e1_now --force >/dev/null 2>&1
    $NC diff e1_nominal e1_now >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}
wait_nominal_again && ok "réseau revenu à l'état de la référence (diff vide)" || ko "le réseau n'est jamais revenu à la référence"
out=$(mon); code=$?; echo "$out" >> "$E_OUT"
[[ "$code" == "0" ]] && ok "réparation : code retour = 0" || { ko "réparation : code $code (attendu 0)"; echo "$out"; }
[[ "$(count_msgs)" == "2" && "$(msg_field 2 event)" == "recovery" ]] \
  && ok "réparation : message de retour à la normale (ÉCHEC -> OK)" \
  || { ko "réparation : $(count_msgs) message(s)"; echo "$out"; }

# Enveloppe automation/monitor.sh : lit l'URL dans un fichier 0600 (sans l'exécuter), refuse un fichier ouvert.
E_ENV="$JSON_DIR/e1.env"
printf "NETCHECK_WEBHOOK_URL='%s'\n# commentaire\ntouch %s\n" "$NETCHECK_WEBHOOK_URL" "$JSON_DIR/e1_executed" > "$E_ENV"
chmod 600 "$E_ENV"
out=$(env -u NETCHECK_WEBHOOK_URL NETCHECK_ENV_FILE="$E_ENV" automation/monitor.sh \
  --baseline e1_nominal --state-file "$JSON_DIR/e1_sh_state.json" 2>&1); code=$?; echo "$out" >> "$E_OUT"
[[ "$code" == "0" && ! -e "$JSON_DIR/e1_executed" ]] \
  && ok "monitor.sh : fichier d'environnement 0600 lu comme du texte (rien d'exécuté), code 0" \
  || { ko "monitor.sh : code $code"; echo "$out"; }
chmod 644 "$E_ENV"
out=$(env -u NETCHECK_WEBHOOK_URL NETCHECK_ENV_FILE="$E_ENV" automation/monitor.sh --baseline e1_nominal 2>&1); code=$?
echo "$out" >> "$E_OUT"
[[ "$code" == "3" ]] && echo "$out" | grep -q "chmod 600" \
  && ok "monitor.sh : fichier lisible par d'autres -> refusé (code 3, message clair)" \
  || { ko "monitor.sh : code $code (attendu 3)"; echo "$out"; }

kill "$recorder_pid" 2>/dev/null; wait "$recorder_pid" 2>/dev/null
unset NETCHECK_WEBHOOK_URL
if grep -rq "$E_SECRET" "$E_OUT" "$E_STATE" reports/monitor_latest reports/monitor_2* "$JSON_DIR/e1_sh_state.json" 2>/dev/null; then
  ko "l'URL du webhook (secret) apparaît dans une sortie, un état ou un rapport"
else
  ok "l'URL du webhook n'apparaît dans aucune sortie, aucun état, aucun rapport"
fi

c1_hostkeys_scenarios frr automation/inventory.yml 172.20.20.11 172.20.20.12

# ---------------------------------------------------------------- Bilan
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Tous les scénarios netcheck sont conformes au cahier des charges." \
                || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
