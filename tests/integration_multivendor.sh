#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
#
# Scénarios d'intégration netcheck sur le lab multi-constructeurs (Phase E, SPEC_v2.md ;
# A1/A2 ajoutés en Phase C, SPEC_v3.md) : S1 (diff, aucun changement), coupure du lien
# r4 <-> r5 (FRR <-> SR Linux), C1 (conformité), A1/A2 (assert, état attendu, même coupure).
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
NC_PY="netcheck/.venv/bin/python"
INV=(-i automation/inventory-multivendor.yml)  # doit venir APRÈS la sous-commande (argparse)
JSON_DIR=/tmp/netcheck_integration_multivendor
mkdir -p "$JSON_DIR"

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
# shellcheck source=tests/lib_lab.sh
source "$(dirname "$0")/lib_lab.sh"
title() { echo; echo "=== $1 ==="; }

# Clés d'hôte (phase C1) : strict par défaut. Les clés du lab sont lues DANS les conteneurs et épinglées
# dans le known_hosts dédié (jamais le ~/.ssh/known_hosts) ; à refaire après chaque déploiement.
export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
# shellcheck source=tests/lib_hostkeys.sh
source "$(dirname "$0")/lib_hostkeys.sh"
# shellcheck source=tests/lib_bastion.sh
source "$(dirname "$0")/lib_bastion.sh"
lab_ready_lab 172.20.21 "integration-mixte" 240
bash lab-access/pin_hostkeys.sh multivendor >/dev/null || { echo "épinglage des clés d'hôte impossible (lab déployé ?)"; exit 1; }

# Voisins OSPF Full sur r4 (FRR, vtysh) et r5 (SR Linux, sr_cli) : deux commandes différentes,
# un seul critère de convergence -- comme wait_ospf() dans test_lab_multivendor.sh.
ospf_full_r4() { docker exec "$LAB-r4" vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c Full; }
# Instance OSPFv2 `main` seulement : l'instance `v3` (OSPFv3, double pile) tombe aussi avec le lien.
ospf_full_r5() { docker exec "$LAB-r5" sr_cli -- "show network-instance default protocols ospf instance main neighbor" 2>&1 | grep -ci full; }

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

# ---------------------------------------------------------------- A1 : état attendu, nominal
title "A1 : état attendu (assert) -> OK, en direct et hors ligne (FRR + SR Linux)"
out=$($NC assert --intent intents/lab-multivendor.yml --json "$JSON_DIR/a1_direct.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "en direct : code retour = 0" || { ko "en direct : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "en direct : verdict = OK" || { ko "verdict inattendu"; echo "$out"; }

$NC snapshot a1_hors_ligne --force "${INV[@]}" >/dev/null
out=$($NC assert --intent intents/lab-multivendor.yml --snapshot a1_hors_ligne --json "$JSON_DIR/a1_snapshot.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "hors ligne : code retour = 0" || { ko "hors ligne : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "hors ligne : verdict = OK" || { ko "verdict inattendu (hors ligne)"; echo "$out"; }

# ---------------------------------------------------------------- A2 : coupure du lien r4<->r5
title "A2 : ip link set eth2 down sur r4 (lien FRR <-> SR Linux) -> ÉCHEC (assert)"
docker exec "$LAB-r4" ip link set eth2 down
wait_link_down && ok "voisin OSPF perdu des deux côtés (poll actif)" \
  || ko "voisin OSPF encore présent d'au moins un côté après 60s"

out=$($NC assert --intent intents/lab-multivendor.yml --json "$JSON_DIR/a2.json" "${INV[@]}" 2>&1); code=$?

docker exec "$LAB-r4" ip link set eth2 up
wait_converged && ok "retour à la normale : OSPF Full des deux côtés" \
  || ko "OSPF non reconvergé après restauration du lien"

[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
echo "$out" | grep -q "Verdict : ÉCHEC" && ok "verdict = ÉCHEC" || { ko "verdict inattendu"; echo "$out"; }
grep -q '"id": "chemin-r1-vers-lan-r5"' "$JSON_DIR/a2.json" && grep -q "trou noir" "$JSON_DIR/a2.json" \
  && ok "assertion 'path' (traverse FRR et SR Linux) en ÉCHEC avec la raison 'trou noir'" \
  || { ko "constat 'path' attendu manquant"; cat "$JSON_DIR/a2.json"; }
grep -q '"id": "ospf-r5-voisin-srlinux"' "$JSON_DIR/a2.json" && ok "assertion OSPF côté SR Linux présente dans le rapport" \
  || ko "assertion OSPF côté SR Linux absente du rapport"

# ---------------------------------------------------------------- A3 : coupure r4<->r5 vue en IPv6 (phase B2)
title "A3 : ip link set eth2 down sur r4 -> OSPFv3 perdu des DEUX côtés (FRR et SR Linux), préfixe IPv6 de pc2 perdu"
# OSPFv3 Full de chaque côté : deux commandes différentes (instance `v3` de SR Linux), un seul critère.
ospf6_full_r4() { docker exec "$LAB-r4" vtysh -c "show ipv6 ospf6 neighbor" 2>/dev/null | grep -c Full; }
ospf6_full_r5() { docker exec "$LAB-r5" sr_cli -- "show network-instance default protocols ospf instance v3 neighbor" 2>&1 | grep -ci full; }
wait_ospf6() {   # $1 = nombre attendu des deux côtés
  for _ in $(seq 1 30); do
    [[ "$(ospf6_full_r4)" == "$1" && "$(ospf6_full_r5)" == "$1" ]] && return 0
    sleep 3
  done
  return 1
}
wait_identical() {   # preuve de retour : l'état est IDENTIQUE à l'état d'avant (zéro constat de toute gravité)
  for _ in $(seq 1 20); do
    sleep 4
    $NC snapshot "$1_maintenant" --force "${INV[@]}" >/dev/null 2>&1
    out=$($NC diff "$1_avant" "$1_maintenant" "${INV[@]}" 2>&1) && echo "$out" | grep -q "Aucun constat" && return 0
  done
  echo "$out"
  return 1
}
wait_converged && wait_ospf6 1 && ok "état nominal : OSPFv2 et OSPFv3 Full des deux côtés" || ko "lab non convergé avant A3"
# Les voisins OSPFv3 Full ne disent pas que les ROUTES IPv6 sont revenues (après A2, celles de SR Linux arrivent
# plus tard) : une référence prise trop tôt ferait diverger le retour prouvé, sans rapport avec ce qu'on teste.
wait_route6() {
  for _ in $(seq 1 30); do
    local n=0
    for r in r1 r2 r3 r4; do
      docker exec "$LAB-$r" vtysh -c "show ipv6 route 2001:db8:a2::/64" 2>/dev/null | grep -q "2001:db8:a2::/64" && n=$((n + 1))
    done
    docker exec "$LAB-r4" vtysh -c "show ipv6 route 2001:db8:2:ff::5/128" 2>/dev/null | grep -q "2001:db8:2:ff::5/128" && n=$((n + 1))
    [[ "$n" == "5" ]] && return 0
    sleep 3
  done
  return 1
}
wait_route6 && ok "routes IPv6 de SR Linux revenues sur r1 à r4 (référence stable)" || ko "routes IPv6 non revenues avant A3"
$NC snapshot a3_avant --force "${INV[@]}" >/dev/null
docker exec "$LAB-r4" ip link set eth2 down
wait_ospf6 0 && ok "voisin OSPFv3 perdu des deux côtés (r4 FRR et r5 SR Linux, poll actif)" \
  || ko "voisin OSPFv3 encore présent d'au moins un côté après 90 s"
sleep 5
$NC snapshot a3_apres --force "${INV[@]}" >/dev/null
out=$($NC diff a3_avant a3_apres --json "$JSON_DIR/a3_diff.json" "${INV[@]}" 2>&1); code=$?
out_a=$($NC assert --intent intents/lab-multivendor.yml --snapshot a3_apres --json "$JSON_DIR/a3.json" "${INV[@]}" 2>&1); code_a=$?
docker exec "$LAB-r4" ip link set eth2 up
wait_converged && wait_ospf6 1 && ok "retour à la normale : OSPFv2 et OSPFv3 Full des deux côtés" \
  || ko "OSPF non reconvergé après restauration du lien"

[[ "$code" == "2" ]] && ok "diff : code retour = 2" || { ko "diff : code retour = $code (attendu 2)"; echo "$out"; }
$NC_PY - "$JSON_DIR/a3_diff.json" <<'PY' && ok "diff : voisin OSPFv3 perdu vu des DEUX côtés (r4 FRR et r5 SR Linux)" || ko "diff : voisin OSPFv3 perdu manquant d'un côté"
import json, sys
findings = json.load(open(sys.argv[1]))["findings"]
seen = {f["device"] for f in findings if f["category"] == "ospf6_neighbor" and "voisin OSPFv3 perdu" in f["message"]}
sys.exit(0 if {"r4", "r5"} <= seen else 1)
PY
grep -q 'préfixe injoignable : 2001:db8:a2::/64' "$JSON_DIR/a3_diff.json" \
  && ok "diff : le préfixe IPv6 du LAN de pc2 (2001:db8:a2::/64) est perdu" || ko "diff : perte de 2001:db8:a2::/64 non signalée"
[[ "$code_a" == "2" ]] && ok "assert : code retour = 2" || { ko "assert : code retour = $code_a (attendu 2)"; echo "$out_a"; }
for id in ospf6-r5-voisin-srlinux route6-r5-vers-as65001 chemin6-r1-vers-lan-r5 chemin6-r5-vers-lan-r1; do
  $NC_PY - "$JSON_DIR/a3.json" "$id" <<'PY' && ok "assert IPv6 '$id' en ÉCHEC" || ko "assert IPv6 '$id' pas en ÉCHEC"
import json, sys
results = {r["id"]: r["status"] for r in json.load(open(sys.argv[1]))["results"]}
sys.exit(0 if results.get(sys.argv[2]) == "ÉCHEC" else 1)
PY
done
wait_identical a3 && ok "preuve de retour : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || ko "l'état actuel diffère de l'état d'avant la coupure"

# Les deux fichiers de règles et la dérogation du lab, à une date FIXE (--today) : le scénario ne dépend pas du
# calendrier (la dérogation du lab expire le 2027-01-04).
SEC=(--rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml)
DER=derogations/lab-multivendor.yml

# ---------------------------------------------------------------- C3 : dérogations (phase B3)
title "C3 : check (règles IPv6 + dérogation du lab) -> conforme, le lien r4-r5 en DÉROGATION des DEUX côtés"
out=$($NC check "${INV[@]}" "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c3.json" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "conformité = CONFORME" || { ko "conformité inattendue"; echo "$out"; }
$NC_PY - "$JSON_DIR/c3.json" "$DER" <<'PY' && ok "JSON : r4 ET r5 en DÉROGATION, 0 violation active, empreinte SHA-256 du fichier" || ko "JSON des dérogations inattendu"
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
d = data["derogations"]
sha = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
ok = (data["violations"] == [] and data["summary"]["derogated"] == 2 and d["file"]["sha256"] == sha
      and sorted(x["device"] for x in d["derogated"]) == ["r4", "r5"] and "coverage_notes" not in data)
sys.exit(0 if ok else 1)
PY
out=$($NC check "${INV[@]}" "${SEC[@]}" --derogations "$DER" --today 2027-01-05 2>&1); code=$?
[[ "$code" == "2" ]] && echo "$out" | grep -q "expirée le 2027-01-04" \
  && ok "après la date d'expiration (--today 2027-01-05) : de nouveau code 2, « expirée le 2027-01-04 » dit" \
  || { ko "dérogation expirée mal gérée (code $code)"; echo "$out"; }
out=$($NC check "${INV[@]}" "${SEC[@]}" 2>&1); code=$?
[[ "$code" == "2" ]] && echo "$out" | grep -q "ospf6" && ok "sans dérogation : le défaut OSPFv3 réel du lien r4-r5 est signalé (code 2)" \
  || { ko "défaut OSPFv3 non signalé sans dérogation (code $code)"; echo "$out"; }

# ---------------------------------------------------------------- C3b : l'IPv6 n'est jamais un silence (phase B4)
title "C3b : security.yml SEUL sur ce lab en double pile -> information de couverture (« IPv6 configuré, aucune règle IPv6 chargée »)"
out=$($NC check "${INV[@]}" --rules netcheck/rules/security.yml --json "$JSON_DIR/c3b.json" 2>&1); code=$?
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


# ---------------------------------------------------------------- M1 : monitor sur les deux drivers
title "M1 : monitor sur le lab mixte (FRR + SR Linux) -> OK, aucune alerte (lecture seule)"
M_STATE="$JSON_DIR/m1_state.json"
rm -f "$M_STATE" "$M_STATE.lock"
# La référence ne doit pas être prise PENDANT une reconvergence : A2 vient de rétablir le lien
# r4 <-> r5, et OSPF « Full » des deux côtés précède la fin du recalcul des routes. On attend un
# réseau STABLE : deux relevés espacés de 4 s sans le moindre constat.
wait_stable() {
  for _ in $(seq 1 15); do
    $NC snapshot m1_stable_a --force "${INV[@]}" >/dev/null 2>&1; sleep 4
    $NC snapshot m1_stable_b --force "${INV[@]}" >/dev/null 2>&1
    $NC diff m1_stable_a m1_stable_b "${INV[@]}" >/dev/null 2>&1 && return 0
  done
  return 1
}
wait_stable && ok "réseau stable avant la référence (deux relevés identiques)" || ko "réseau jamais stable"
$NC snapshot m1_nominal --force "${INV[@]}" >/dev/null
# monitor lit l'horloge (il n'a pas de --today) : la dérogation est une copie de celle du lab, validée aujourd'hui et
# valable 60 jours, calculée à l'exécution : aucune date n'est écrite en dur, rien ne dépend du calendrier.
DER_FRESH="$JSON_DIR/derogations_fraiches.yml"
sed -e "s/^\(    validated_on:\).*/\1 $(date +%F)/" -e "s/^\(    expires:\).*/\1 $(date -d '+60 days' +%F)/" "$DER" > "$DER_FRESH"
# shellcheck disable=SC2086  # $NC est volontairement découpé en mots (interpréteur + -m netcheck)
out=$(env -u NETCHECK_WEBHOOK_URL $NC monitor --baseline m1_nominal --intent intents/lab-multivendor.yml \
  "${SEC[@]}" --derogations "$DER_FRESH" --state-file "$M_STATE" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "netcheck monitor : OK (diff OK · assert OK · check OK)" \
  && ok "statut OK sur les trois composants (r5 SR Linux inclus)" || { ko "statut inattendu"; echo "$out"; }
grep -q '"status": "OK"' "$M_STATE" && ok "état enregistré (premier relevé OK, rien à annoncer)" \
  || ko "fichier d'état absent ou inattendu"

c1_hostkeys_scenarios multivendor automation/inventory-multivendor.yml 172.20.21.11 172.20.21.15
c4_bastion_scenarios multivendor automation/inventory-multivendor.yml 172.20.21 clab-frr-lab-multivendor non

# ---------------------------------------------------------------- Bilan
lab_diag_if_failed "integration-mixte"
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab multi-constructeurs est conforme au cahier des charges (netcheck)." \
                || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
