#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification du disable ci-dessus : ok()/ko() (définis plus bas) ne font qu'un echo et un
# incrément d'entier, ils ne peuvent pas échouer. Le motif "cond && ok ... || ko ..." utilisé
# partout dans ce fichier est donc sûr, même si ce n'est pas un vrai if/then/else.
#
# Scénarios d'intégration netcheck sur le lab Arista cEOS (Phase F, SPEC_v3.md) : snapshot, diff,
# check, assert, guard et monitor sur un réseau FRR + cEOS, avec des tests NÉGATIFS rejoués (mauvaise
# clé OSPF, API de gestion exposée, coupure d'interface annulée par guard). Le rôle de ce fichier
# est de prouver que netcheck fonctionne sur un TROISIÈME constructeur sans rien casser ailleurs.
#   bash tests/integration_ceos.sh
# Code retour : 0 si tous les scénarios passent, 1 sinon. Le lab est laissé démarré et dans son
# état nominal (chaque scénario annule son propre changement avant de rendre la main).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LAB=clab-frr-lab-ceos
NC="netcheck/.venv/bin/python -m netcheck"
NC_PY="netcheck/.venv/bin/python"
INV=(-i automation/inventory-ceos.yml)  # doit venir APRÈS la sous-commande (argparse)
# Les deux fichiers de règles (le second est IPv6) et la dérogation du lab, à une date FIXE (--today) : le scénario
# ne dépend pas du calendrier (la dérogation du lab expire le 2027-01-04).
SEC=(--rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml)
DER=derogations/lab-ceos.yml
JSON_DIR=/tmp/netcheck_integration_ceos
mkdir -p "$JSON_DIR"
# Les identifiants viennent de l'inventaire (valeurs par défaut du lab) : on neutralise un
# éventuel NETCHECK_USER/PASS de l'environnement, qui s'appliquerait à TOUS les routeurs.
unset NETCHECK_USER NETCHECK_PASS LAB_USER LAB_PASS NETCHECK_EOS_USER NETCHECK_EOS_PASS NETCHECK_WEBHOOK_URL

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }

# Voisins OSPF Full sur r4 (cEOS, Cli) et r5 (FRR, vtysh) : deux commandes différentes, un seul
# critère de convergence -- comme wait_ospf() dans test_lab_ceos.sh.
ospf_full_r4() { docker exec "$LAB-r4" Cli -p 15 -c "show ip ospf neighbor" 2>/dev/null | grep -c FULL; }
ospf_full_r5() { docker exec "$LAB-r5" vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c Full; }
eosconf() { docker exec -i "$LAB-r4" Cli -p 15 >/dev/null; }   # commandes de configuration sur stdin

wait_converged() {
  for _ in $(seq 1 30); do
    [[ "$(ospf_full_r4)" == "1" && "$(ospf_full_r5)" == "1" ]] && return 0
    sleep 3
  done
  return 1
}
wait_link_down() {   # dead interval OSPF = 40 s : jusqu'à 120 s
  for _ in $(seq 1 40); do
    [[ "$(ospf_full_r4)" == "0" && "$(ospf_full_r5)" == "0" ]] && return 0
    sleep 3
  done
  return 1
}
wait_bgp() {
  for _ in $(seq 1 30); do
    docker exec "$LAB-r4" Cli -p 15 -c "show ip bgp summary" 2>/dev/null | grep -q Estab && return 0
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

wait_converged && ok "lab nominal (OSPF Full des deux côtés de r4)" || { ko "lab non convergé au départ"; exit 1; }
wait_bgp && ok "lab nominal (BGP Established sur r4)" || { ko "BGP non établi au départ"; exit 1; }
sleep 5

# ---------------------------------------------------------------- S1 : aucun changement
title "S1 : aucun changement -> OK (FRR + cEOS)"
$NC snapshot s1_avant --force "${INV[@]}" >/dev/null
sleep 3
$NC snapshot s1_apres --force "${INV[@]}" >/dev/null
run_diff s1 0 OK ""

# ---------------------------------------------------------------- C1 : conformité nominale
title "C1 : conformité du lab nominal (default.yml, puis security.yml + security-ipv6.yml + dérogation du lab) -> conforme"
out=$($NC check --rules netcheck/rules/default.yml --json "$JSON_DIR/c1_default.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "default : code retour = 0" || { ko "default : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "default : conformité = CONFORME" \
  || { ko "default : conformité inattendue"; echo "$out"; }
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c1_security.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "security + security-ipv6 + dérogation : code retour = 0" \
  || { ko "security + security-ipv6 + dérogation : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Conformité : CONFORME" && ok "security + security-ipv6 + dérogation : conformité = CONFORME" \
  || { ko "security + security-ipv6 + dérogation : conformité inattendue"; echo "$out"; }
python3 - "$JSON_DIR/c1_security.json" <<'PY' && ok "règles EOS évaluées sur r4 (jamais « non applicables »), « non applicables » sur les FRR" \
  || ko "règles EOS mal réparties entre r4 et les routeurs FRR"
import json, sys
na = json.load(open(sys.argv[1]))["not_applicable"]
pairs = {(n["device"], n["rule_id"]) for n in na}
eos_rules = {"eos-ospf-authentification-message-digest", "eos-ebgp-authentification-tcp-md5",
             "eos-ebgp-gtsm-ttl-maximum-hops", "eos-ebgp-maximum-routes", "eos-api-gestion-exposee"}
assert not [p for p in pairs if p[0] == "r4" and p[1] in eos_rules], "règle EOS ignorée sur r4"
assert all(("r5", r) in pairs and ("r1", r) in pairs for r in eos_rules), "règle EOS appliquée à un routeur FRR"
assert ("r4", "ospf-authentification-message-digest") in pairs, "règle FRR appliquée à r4"
# Phase B4 : les deux règles de politique d'entrée sont évaluées sur r4 (EOS) comme sur r3 (FRR).
for rule in ("ebgp-pas-de-route-par-defaut", "ebgp-pas-de-reinjection-de-prefixes-locaux"):
    assert ("r4", rule) not in pairs and ("r3", rule) not in pairs, f"{rule} non évaluée sur r3 ou r4"
PY

title "C1b : security.yml SEUL sur ce lab en double pile -> information de couverture (« IPv6 configuré, aucune règle IPv6 chargée »)"
out=$($NC check --rules netcheck/rules/security.yml --json "$JSON_DIR/c1b.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "code retour = 0 (l'information ne change pas le verdict)" || { ko "code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | tr -s '[:space:]' ' ' | grep -q "aucune règle IPv6 chargée" \
  && ok "terminal : l'absence de règle IPv6 est dite" || { ko "terminal : information de couverture absente"; echo "$out"; }
$NC_PY - "$JSON_DIR/c1b.json" <<'PY' && ok "JSON : coverage_notes nomme r1 à r5, compté à part (summary.coverage_notes = 1)" || ko "JSON : information de couverture inattendue"
import json, sys
data = json.load(open(sys.argv[1]))
note = data["coverage_notes"][0]
sys.exit(0 if (note["kind"] == "ipv6-sans-regle" and note["devices"] == ["r1", "r2", "r3", "r4", "r5"]
               and data["summary"]["coverage_notes"] == 1 and data["violations"] == []) else 1)
PY

# ---------------------------------------------------------------- A1 : état attendu
title "A1 : état attendu (assert) -> OK, en direct et hors ligne (FRR + cEOS)"
out=$($NC assert --intent intents/lab-ceos.yml --json "$JSON_DIR/a1_direct.json" "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "en direct : code retour = 0" || { ko "en direct : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "en direct : verdict = OK" || { ko "verdict inattendu"; echo "$out"; }
$NC snapshot a1_hors_ligne --force "${INV[@]}" >/dev/null
out=$($NC assert --intent intents/lab-ceos.yml --snapshot a1_hors_ligne "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "hors ligne : code retour = 0" || { ko "hors ligne : code retour = $code (attendu 0)"; echo "$out"; }
echo "$out" | grep -q "Verdict : OK" && ok "hors ligne : verdict = OK" || { ko "verdict inattendu (hors ligne)"; echo "$out"; }

# ---------------------------------------------------------------- N1 : TEST NÉGATIF -- mauvaise clé OSPF
title "N1 : mauvaise clé OSPF sur r4 (cEOS) -> ÉCHEC des deux côtés (diff + assert), puis retour prouvé"
$NC snapshot n1_avant --force "${INV[@]}" >/dev/null
eosconf <<'EOF'
configure
interface Ethernet2
   ip ospf message-digest-key 1 md5 mauvaise-cle
end
EOF
wait_link_down && ok "adjacence OSPF perdue des deux côtés (r4 cEOS et r5 FRR, poll actif)" \
  || ko "adjacence OSPF encore présente d'un côté après 120 s"
$NC snapshot n1_apres --force "${INV[@]}" >/dev/null
out=$($NC assert --intent intents/lab-ceos.yml --snapshot n1_apres --json "$JSON_DIR/n1_assert.json" "${INV[@]}" 2>&1); code=$?
eosconf <<'EOF'
configure
interface Ethernet2
   ip ospf message-digest-key 1 md5 lab-ospf-r4r5
end
EOF
wait_converged && ok "retour à la normale : OSPF Full des deux côtés" || ko "OSPF non reconvergé après restauration de la clé"
run_diff n1 2 ÉCHEC 'voisin OSPF perdu'
grep -q '"device": "r4"' "$JSON_DIR/n1.json" && grep -q '"device": "r5"' "$JSON_DIR/n1.json" \
  && ok "constats localisés sur r4 (cEOS) ET r5 (FRR)" || ko "constat manquant sur r4 ou r5"
[[ "$code" == "2" ]] && ok "assert hors ligne : code retour = 2" || { ko "assert : code retour = $code (attendu 2)"; echo "$out"; }
grep -q '"id": "ospf-r4-voisin-frr"' "$JSON_DIR/n1_assert.json" && grep -q '"id": "chemin-r1-vers-lan-r5"' "$JSON_DIR/n1_assert.json" \
  && ok "assertions OSPF de r4 (cEOS) et chemin de bout en bout signalées" || ko "assertion attendue absente"
grep -q "trou noir" "$JSON_DIR/n1_assert.json" && ok "assertion 'path' en ÉCHEC avec la raison 'trou noir' (traverse cEOS)" \
  || ko "raison 'trou noir' absente"
# La clé restaurée redonne EXACTEMENT la même configuration (le hash « type 7 » est déterministe) :
# preuve indépendante du retour, zéro constat de toute gravité.
sleep 5
$NC snapshot n1_maintenant --force "${INV[@]}" >/dev/null
out=$($NC diff n1_avant n1_maintenant "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && echo "$out" | grep -q "Aucun constat" \
  && ok "preuve indépendante : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || { ko "l'état actuel diffère de l'état d'avant (code $code)"; echo "$out"; }
# Aucun hash « type 7 » (ni la clé erronée, ni la bonne) dans le rapport, alors que le diff de
# configuration les contient bruts : le masquage fonctionne sur le troisième constructeur.
hashes=$(python3 - <<'PY'
import json, re
for snap in ("n1_avant", "n1_apres"):
    cfg = json.load(open(f"snapshots/{snap}/r4.json"))["running_config"]
    for h in re.findall(r"(?:md5|password) 7 (\S+)", cfg):
        print(h)
PY
)
raw_has_hash=0; leaked=0
for h in $hashes; do
  grep -qF -- "$h" "snapshots/n1_apres/r4.json" && raw_has_hash=1
  grep -qF -- "$h" "$JSON_DIR/n1.json" && leaked=1
  $NC diff n1_avant n1_apres "${INV[@]}" 2>&1 | grep -qF -- "$h" && leaked=1
done
[[ -n "$hashes" && "$raw_has_hash" == "1" ]] && ok "le snapshot (brut, hors Git) contient bien les hashes type 7" || ko "hashes type 7 introuvables dans le snapshot"
[[ "$leaked" == "0" ]] && ok "AUCUN hash type 7 dans le rapport JSON ni dans la sortie terminal" || ko "FUITE : un hash type 7 apparaît dans un rapport"

# ---------------------------------------------------------------- N2 : TEST NÉGATIF -- API de gestion exposée
title "N2 : eAPI + gNMI + NETCONF activés sur r4 -> check NON CONFORME (eos-api-gestion-exposee), puis retour"
eosconf <<'EOF'
configure
management api http-commands
   no shutdown
management api gnmi
   transport grpc default
management api netconf
   transport ssh default
end
EOF
sleep 3
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/n2.json" "${INV[@]}" 2>&1); code=$?
eosconf <<'EOF'
configure
no management api http-commands
no management api gnmi
no management api netconf
end
EOF
[[ "$code" == "2" ]] && ok "code retour = 2" || { ko "code retour = $code (attendu 2)"; echo "$out"; }
echo "$out" | grep -q "NON CONFORME" && ok "conformité = NON CONFORME" || { ko "conformité inattendue"; echo "$out"; }
python3 - "$JSON_DIR/n2.json" <<'PY' && ok "règle 'eos-api-gestion-exposee' signalée sur r4, pour les trois API (eAPI, gNMI, NETCONF)" \
  || ko "violation attendue absente ou mal localisée"
import json, sys
v = [x for x in json.load(open(sys.argv[1]))["violations"] if x["rule_id"] == "eos-api-gestion-exposee"]
assert {x["device"] for x in v} == {"r4"} and len(v) == 3, v
text = " ".join(x["detail"] for x in v)
assert "eAPI" in text and "gNMI" in text and "NETCONF" in text
PY
out=$($NC check "${SEC[@]}" --derogations "$DER" --today 2026-10-05 "${INV[@]}" 2>&1); code=$?
[[ "$code" == "0" ]] && echo "$out" | grep -q "Conformité : CONFORME" \
  && ok "retour à la normale : conforme de nouveau (API retirées)" || { ko "toujours non conforme après le retrait des API"; echo "$out"; }

# ---------------------------------------------------------------- N3 : session eBGP IPv6 coupée côté EOS (phase B2)
title "N3 : neighbor 2001:db8:34::2 shutdown sur r4 (cEOS, IPv6 seul) -> vu des DEUX côtés par diff et assert, l'IPv4 reste OK"
bgp6_state() {   # $1 = r3 (FRR) ou r4 (cEOS) : la session IPv6 est-elle Established ? (sorties JSON : le texte de FRR n'écrit pas l'état)
  if [[ "$1" == "r3" ]]; then docker exec "$LAB-r3" vtysh -c "show bgp ipv6 unicast summary json" 2>/dev/null | grep -q '"state":"Established"'
  else docker exec "$LAB-r4" Cli -p 15 -c "show ipv6 bgp summary | json" 2>/dev/null | grep -q '"peerState": "Established"'; fi
}
wait_bgp6() {   # $1 = up | down, des deux côtés
  for _ in $(seq 1 40); do
    if [[ "$1" == "up" ]]; then bgp6_state r3 && bgp6_state r4 && return 0
    else ! bgp6_state r3 && ! bgp6_state r4 && return 0; fi
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
wait_bgp6 up && ok "état nominal : session eBGP IPv6 Established des deux côtés" || ko "session IPv6 non établie avant N3"
$NC snapshot n3_avant --force "${INV[@]}" >/dev/null
eosconf <<'EOF'
configure
router bgp 65002
   neighbor 2001:db8:34::2 shutdown
end
EOF
wait_bgp6 down && ok "session eBGP IPv6 tombée des deux côtés (r3 FRR et r4 cEOS, poll actif)" \
  || ko "session IPv6 encore établie d'un côté après 120 s"
sleep 5
$NC snapshot n3_apres --force "${INV[@]}" >/dev/null
out=$($NC diff n3_avant n3_apres --json "$JSON_DIR/n3_diff.json" "${INV[@]}" 2>&1); code=$?
out_a=$($NC assert --intent intents/lab-ceos.yml --snapshot n3_apres --json "$JSON_DIR/n3.json" "${INV[@]}" 2>&1); code_a=$?
eosconf <<'EOF'
configure
router bgp 65002
   no neighbor 2001:db8:34::2 shutdown
end
EOF
wait_bgp6 up && ok "retour à la normale : session eBGP IPv6 Established des deux côtés" \
  || ko "session IPv6 non rétablie après restauration"

[[ "$code" == "2" ]] && ok "diff : code retour = 2" || { ko "diff : code retour = $code (attendu 2)"; echo "$out"; }
$NC_PY - "$JSON_DIR/n3_diff.json" <<'PY' && ok "diff : session IPv6 perdue vue des DEUX côtés (r3 FRR et r4 cEOS)" || ko "diff : constat manquant d'un côté"
import json, sys
findings = json.load(open(sys.argv[1]))["findings"]
seen = {f["device"] for f in findings if f["category"] == "bgp_session" and "session BGP 2001:db8:34::" in f["message"]}
sys.exit(0 if {"r3", "r4"} <= seen else 1)
PY
grep -q 'session BGP 172.16.34' "$JSON_DIR/n3_diff.json" \
  && ko "diff : la session IPv4 est signalée alors que seule l'IPv6 est coupée" \
  || ok "diff : aucun constat sur la session IPv4 (la panne est propre à l'IPv6)"
[[ "$code_a" == "2" ]] && ok "assert : code retour = 2" || { ko "assert : code retour = $code_a (attendu 2)"; echo "$out_a"; }
for id in bgp6-r3-vers-r4 bgp6-r4-vers-r3; do
  $NC_PY - "$JSON_DIR/n3.json" "$id" ÉCHEC <<'PY' && ok "assert IPv6 '$id' (r3 FRR / r4 cEOS) en ÉCHEC" || ko "assert IPv6 '$id' pas en ÉCHEC"
import json, sys
results = {r["id"]: r["status"] for r in json.load(open(sys.argv[1]))["results"]}
sys.exit(0 if results.get(sys.argv[2]) == sys.argv[3] else 1)
PY
done
for id in bgp-r3-vers-r4 bgp-r4-vers-r3 ospf-r4-voisin-frr; do
  $NC_PY - "$JSON_DIR/n3.json" "$id" OK <<'PY' && ok "assert '$id' toujours OK (IPv4 et OSPF intacts)" || ko "assert '$id' pas OK"
import json, sys
results = {r["id"]: r["status"] for r in json.load(open(sys.argv[1]))["results"]}
sys.exit(0 if results.get(sys.argv[2]) == sys.argv[3] else 1)
PY
done
wait_identical n3 && ok "preuve de retour : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || ko "l'état actuel diffère de l'état d'avant la coupure"

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


# ---------------------------------------------------------------- C6 : politiques d'entrée EOS (phase B4)
bgp4_state() {   # $1 = r3 (FRR) ou r4 (cEOS) : la session eBGP IPv4 est-elle Established ?
  if [[ "$1" == "r3" ]]; then docker exec "$LAB-r3" vtysh -c "show bgp ipv4 unicast summary json" 2>/dev/null | grep -q '"state":"Established"'
  else docker exec "$LAB-r4" Cli -p 15 -c "show ip bgp summary | json" 2>/dev/null | grep -q '"peerState": "Established"'; fi
}
ospf6_full() {   # OSPFv3 Full des deux côtés du lien r4-r5 (r4 cEOS, r5 FRR)
  docker exec "$LAB-r4" Cli -p 15 -c "show ospfv3 neighbor" 2>/dev/null | grep -qi full \
    && docker exec "$LAB-r5" vtysh -c "show ipv6 ospf6 neighbor" 2>/dev/null | grep -qi full
}
adjacencies_ok() {   # OSPF, OSPFv3 et eBGP IPv4 + IPv6 en place (les règles de sécurité de la phase ne coupent rien)
  [[ "$(ospf_full_r4)" == "1" && "$(ospf_full_r5)" == "1" ]] && ospf6_full \
    && bgp4_state r3 && bgp4_state r4 && bgp6_state r3 && bgp6_state r4
}
title "C6 : route par défaut et préfixe local autorisés en entrée sur r4 (cEOS), IPv4 et IPv6 -> NON CONFORME, puis retour prouvé"
adjacencies_ok && ok "avant : OSPF, OSPFv3, eBGP IPv4 et IPv6 en place" || ko "adjacences incomplètes avant C6"
# Jamais de `write` : la configuration de démarrage de r4 vient des fichiers du dépôt, et son empreinte ne bouge pas.
startup_hash() { docker exec "$LAB-r4" Cli -p 15 -c "show startup-config" | sha256sum | cut -d' ' -f1; }
STARTUP_BEFORE=$(startup_hash)
$NC snapshot c6_avant --force "${INV[@]}" >/dev/null
eosconf <<'EOF'
configure
ip prefix-list PL-EBGP-IN seq 90 permit 0.0.0.0/0 le 32
ip prefix-list PL-EBGP-IN seq 91 permit 10.2.0.0/16
ipv6 prefix-list PL6-EBGP-IN
   seq 90 permit ::/0 le 128
   seq 91 permit 2001:db8:2::/48
end
EOF
sleep 4
adjacencies_ok && ok "pendant l'injection : OSPF, OSPFv3, eBGP IPv4 et IPv6 toujours en place" || ko "une adjacence a lâché pendant l'injection"
docker exec "$LAB-r4" Cli -p 15 -c "show running-config" > "$JSON_DIR/c6_listes_r4.txt"   # lecture seule : fixture du gel
out=$($NC check "${INV[@]}" "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c6_listes.json" 2>&1); code=$?
eosconf <<'EOF'
configure
no ip prefix-list PL-EBGP-IN seq 90
no ip prefix-list PL-EBGP-IN seq 91
ipv6 prefix-list PL6-EBGP-IN
   no seq 90
   no seq 91
end
EOF
[[ "$code" == "2" ]] && ok "listes : code retour = 2" || { ko "listes : code retour = $code (attendu 2)"; echo "$out"; }
$NC_PY - "$JSON_DIR/c6_listes.json" <<'PY' && ok "listes : 4 violations sur r4 (défaut et réinjection, IPv4 et IPv6), les 2 dérogations du lab intactes" || ko "listes : violations inattendues"
import json, sys
data = json.load(open(sys.argv[1]))
v = sorted((x["rule_id"], x["device"], x["object"]) for x in data["violations"])
expected = sorted([("ebgp-pas-de-route-par-defaut", "r4", "172.16.34.1"),
                   ("ebgp-pas-de-route-par-defaut", "r4", "2001:db8:34::2"),
                   ("ebgp-pas-de-reinjection-de-prefixes-locaux", "r4", "172.16.34.1"),
                   ("ebgp-pas-de-reinjection-de-prefixes-locaux", "r4", "2001:db8:34::2")])
sys.exit(0 if v == expected and data["summary"]["derogated"] == 2 else 1)
PY
wait_identical c6 && ok "preuve de retour (listes) : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || ko "l'état actuel diffère de l'état d'avant (listes)"

# Peer group : la route-map d'entrée du GROUPE laisse passer la route par défaut et un préfixe local ; le membre
# fictif (192.0.2.0/24, jamais routé) hérite de la politique de son groupe : c'est lui qu'il faut voir.
eosconf <<'EOF'
configure
ip prefix-list PL-TEST-IN seq 10 permit 0.0.0.0/0 le 32
ip prefix-list PL-TEST-IN seq 20 permit 192.168.2.0/24
route-map RM-TEST-IN permit 10
   match ip address prefix-list PL-TEST-IN
router bgp 65002
   neighbor PG-TEST peer group
   neighbor PG-TEST remote-as 65099
   neighbor PG-TEST route-map RM-TEST-IN in
   neighbor 192.0.2.77 peer group PG-TEST
end
EOF
sleep 4
adjacencies_ok && ok "pendant l'injection (peer group) : OSPF, OSPFv3, eBGP IPv4 et IPv6 toujours en place" || ko "une adjacence a lâché pendant l'injection (peer group)"
docker exec "$LAB-r4" Cli -p 15 -c "show running-config" > "$JSON_DIR/c6_groupe_r4.txt"   # lecture seule : fixture du gel
out=$($NC check "${INV[@]}" "${SEC[@]}" --derogations "$DER" --today 2026-10-05 --json "$JSON_DIR/c6_groupe.json" 2>&1); code=$?
eosconf <<'EOF'
configure
router bgp 65002
   no neighbor 192.0.2.77 peer group PG-TEST
   no neighbor PG-TEST peer group
exit
no route-map RM-TEST-IN
no ip prefix-list PL-TEST-IN
end
EOF
[[ "$code" == "2" ]] && ok "peer group : code retour = 2" || { ko "peer group : code retour = $code (attendu 2)"; echo "$out"; }
$NC_PY - "$JSON_DIR/c6_groupe.json" <<'PY' && ok "peer group : le membre 192.0.2.77 est signalé pour la route par défaut ET pour le préfixe local, avec son groupe" || ko "peer group : violations du membre inattendues"
import json, sys
data = json.load(open(sys.argv[1]))
rows = {(x["rule_id"], x["object"]): x["detail"] for x in data["violations"] if x["device"] == "r4"}
d = rows.get(("ebgp-pas-de-route-par-defaut", "192.0.2.77"), "")
o = rows.get(("ebgp-pas-de-reinjection-de-prefixes-locaux", "192.0.2.77"), "")
ok = "voisin eBGP 192.0.2.77 (peer group PG-TEST)" in d and "autorise 0.0.0.0/0" in d \
     and "voisin eBGP 192.0.2.77 (peer group PG-TEST)" in o and "autorise 192.168.2.0/24" in o \
     and not any("PG-TEST)" in v and "voisin eBGP PG-TEST" in v for v in rows.values())
sys.exit(0 if ok else 1)
PY
wait_identical c6 && ok "preuve de retour (peer group) : l'état actuel est identique à l'état d'avant (aucun constat)" \
  || ko "l'état actuel diffère de l'état d'avant (peer group)"
adjacencies_ok && ok "après : OSPF, OSPFv3, eBGP IPv4 et IPv6 en place" || ko "adjacences incomplètes après C6"
out=$($NC check "${INV[@]}" "${SEC[@]}" --derogations "$DER" --today 2026-10-05 2>&1); code=$?
[[ "$code" == "0" ]] && ok "check de nouveau conforme après le retour" || { ko "check non conforme après le retour"; echo "$out"; }
[[ "$(docker exec "$LAB-r4" Cli -p 15 -c "show configuration sessions" | awk '/^ *---- /{t=1; next} t && NF' | wc -l)" == "0" ]] \
  && ok "aucune session de configuration en attente sur r4" || ko "session de configuration en attente sur r4"
[[ "$(startup_hash)" == "$STARTUP_BEFORE" ]] && ok "la configuration de démarrage de r4 n'a pas bougé (empreinte identique, aucun write)" \
  || ko "la configuration de démarrage de r4 a changé"

# ---------------------------------------------------------------- G1 : guard + rollback sur cEOS
title "G1 : guard encadre une coupure d'interface cEOS (shutdown Ethernet2) + rollback valide -> code 4, retour prouvé"
cat > "$JSON_DIR/g1_change.sh" <<EOF
#!/bin/bash
printf 'configure\ninterface Ethernet2\n   shutdown\nend\n' | docker exec -i $LAB-r4 Cli -p 15
EOF
cat > "$JSON_DIR/g1_rollback.sh" <<EOF
#!/bin/bash
printf 'configure\ninterface Ethernet2\n   no shutdown\nend\n' | docker exec -i $LAB-r4 Cli -p 15
EOF
out=$($NC guard --change "$JSON_DIR/g1_change.sh" --rollback "$JSON_DIR/g1_rollback.sh" --yes --wait 60 "${INV[@]}" 2>&1); code=$?
wait_converged && ok "retour à la normale : OSPF Full des deux côtés" || ko "OSPF non reconvergé après guard"
[[ "$code" == "4" ]] && ok "code retour = 4 (échec annulé avec succès)" || { ko "code retour = $code (attendu 4)"; echo "$out"; }
echo "$out" | grep -q "ANNULÉ AVEC SUCCÈS" && ok "message final : annulé avec succès" || ko "message final absent"
journal=""
for f in reports/guard_*.json; do [[ -e "$f" ]] && { [[ -z "$journal" || "$f" -nt "$journal" ]] && journal="$f"; }; done
grep -q '"final_state": "ROLLED_BACK"' "$journal" && grep -q '"clean": true' "$journal" \
  && ok "journal : ROLLED_BACK, preuve du retour propre ($journal)" || { ko "journal inattendu"; cat "$journal"; }

# ---------------------------------------------------------------- M1 : monitor
title "M1 : monitor sur le lab cEOS (FRR + cEOS) -> OK, puis panne -> alerte unique"
M_STATE="$JSON_DIR/m1_state.json"; M_LOG="$JSON_DIR/m1_messages.jsonl"; M_PORT="$JSON_DIR/m1_port"
rm -f "$M_STATE" "$M_STATE.lock" "$M_PORT"
# Référence prise sur un réseau STABLE (deux relevés espacés de 4 s sans constat), jamais pendant
# une reconvergence : OSPF « Full » précède la fin du recalcul des routes.
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
python3 tests/tools/webhook_recorder.py --port-file "$M_PORT" --log "$M_LOG" &
recorder_pid=$!
for _ in $(seq 1 50); do [[ -s "$M_PORT" ]] && break; sleep 0.2; done
M_PORT_NUMBER=$(cat "$M_PORT")
export NETCHECK_WEBHOOK_URL="http://127.0.0.1:$M_PORT_NUMBER/hook/SENTINEL-WEBHOOK-TOKEN-ceos"
# monitor lit l'horloge (il n'a pas de --today) : la dérogation est une copie de celle du lab, validée aujourd'hui et
# valable 60 jours, calculée à l'exécution : aucune date n'est écrite en dur, rien ne dépend du calendrier.
DER_FRESH="$JSON_DIR/derogations_fraiches.yml"
sed -e "s/^\(    validated_on:\).*/\1 $(date +%F)/" -e "s/^\(    expires:\).*/\1 $(date -d '+60 days' +%F)/" "$DER" > "$DER_FRESH"
mon() { $NC monitor --baseline m1_nominal --intent intents/lab-ceos.yml "${SEC[@]}" --derogations "$DER_FRESH" \
  --state-file "$M_STATE" "${INV[@]}" 2>&1; }
out=$(mon); code=$?
[[ "$code" == "0" ]] && echo "$out" | grep -q "netcheck monitor : OK (diff OK · assert OK · check OK)" \
  && ok "statut OK sur les trois composants (r4 cEOS inclus), aucune alerte" || { ko "statut inattendu (code $code)"; echo "$out"; }
eosconf <<'EOF'
configure
interface Ethernet2
   shutdown
end
EOF
wait_link_down >/dev/null
out=$(mon); code=$?
eosconf <<'EOF'
configure
interface Ethernet2
   no shutdown
end
EOF
[[ "$code" == "2" ]] && ok "panne : code retour = 2" || { ko "panne : code $code (attendu 2)"; echo "$out"; }
[[ "$(wc -l < "$M_LOG" | tr -d ' ')" == "1" ]] && ok "panne : UNE alerte reçue" || ko "panne : nombre de messages inattendu"
kill "$recorder_pid" 2>/dev/null; wait "$recorder_pid" 2>/dev/null
unset NETCHECK_WEBHOOK_URL
wait_converged && ok "retour à la normale : OSPF Full des deux côtés" || ko "OSPF non reconvergé après la panne simulée"
sleep 5

# ---------------------------------------------------------------- Bilan
echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Le lab cEOS est conforme au cahier des charges (netcheck)." \
                || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
