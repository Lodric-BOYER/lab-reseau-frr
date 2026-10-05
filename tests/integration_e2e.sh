#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénario de BOUT EN BOUT (phase C7) sur UN lab déployé à froid :
#   clés d'hôte STRICTES + bastion + compte netcheck-ro (clé) + inventaire alimenté par NetBox
#   -> snapshot, check, assert, guard, monitor ; puis les identifiants lus dans Vault ; puis la couverture et la
#   fraîcheur d'un snapshot lu hors ligne ; enfin « violations en direct == violations de --config-dir ».
#   bash tests/integration_e2e.sh frr|multivendor|ceos
# Prérequis : le lab déployé (test_lab*.sh), NetBox démarré (lab-access/netbox/netbox_lab.sh up) avec les trois labs
# chargés, l'image du bastion construite. Vault de développement créé puis détruit par ce script.
# Aucun routeur n'est modifié par netcheck : `guard` n'exécute qu'un script qui ne touche à rien (un témoin local).
# Les comptes netcheck-ro et le bastion sont posés par les scripts de lab-access/ (état courant, jamais write).
# Le snapshot complet `c7-ref-<lab>` est GARDÉ (référence locale, hors Git) ; tout le reste est retiré.
# Code retour : 0 si tout passe, 1 sinon.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

KIND="${1:-}"
case "$KIND" in
  frr)         INV=automation/inventory.yml;             NET=172.20.20; INTENT=intents/lab.yml
               DIRS=(configs);                           DEROG=derogations/lab.yml;             REF=c7-ref-frr
               FRR_NODES="r1 r2 r3 r4 r5" ;;
  multivendor) INV=automation/inventory-multivendor.yml; NET=172.20.21; INTENT=intents/lab-multivendor.yml
               DIRS=(configs configs-multivendor);       DEROG=derogations/lab-multivendor.yml; REF=c7-ref-mixte
               FRR_NODES="r1 r2 r3 r4" ;;
  ceos)        INV=automation/inventory-ceos.yml;        NET=172.20.22; INTENT=intents/lab-ceos.yml
               DIRS=(configs configs-ceos);              DEROG=derogations/lab-ceos.yml;        REF=c7-ref-ceos
               FRR_NODES="r1 r2 r3 r5" ;;
  *) echo "usage : $0 frr|multivendor|ceos" >&2; exit 2 ;;
esac
NC="netcheck/.venv/bin/python -m netcheck"
NC_PY="netcheck/.venv/bin/python"
RULES=(--rules netcheck/rules/default.yml --rules netcheck/rules/security.yml --rules netcheck/rules/security-ipv6.yml)
JSON_DIR="/tmp/netcheck_e2e_$KIND"
rm -rf "$JSON_DIR"; mkdir -p "$JSON_DIR"
PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }
log() { echo "$1" >> "$JSON_DIR/all.out"; }
# shellcheck source=tests/lib_lab.sh
source "$(dirname "$0")/lib_lab.sh"
# Le terminal replie les cellules à 80 colonnes hors terminal : on cherche dans le texte aux espaces normalisés.
flat() { tr '\n' ' ' | tr -s ' '; }
snaps_now() { find snapshots -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort; }
journals_now() { find reports -maxdepth 1 -type f 2>/dev/null | sort; }

# Aucun identifiant ni option de clés d'hôte hérités de l'environnement : STRICT, et rien d'implicite.
unset NETCHECK_USER NETCHECK_PASS NETCHECK_USER_FILE NETCHECK_PASS_FILE LAB_USER LAB_PASS NETCHECK_NETBOX_TOKEN
unset NETCHECK_FRR_USER NETCHECK_FRR_PASS NETCHECK_FRR_USER_FILE NETCHECK_FRR_PASS_FILE NETCHECK_HOST_KEYS
unset NETCHECK_VAULT_ADDR NETCHECK_VAULT_ROLE_ID NETCHECK_VAULT_SECRET_ID_FILE NETCHECK_VAULT_PATH
export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
export NETCHECK_NETBOX_TOKEN_FILE="$HOME/.config/netcheck/netbox-ro.token"
snaps_before=$(snaps_now); journals_before=$(journals_now)

# ------------------------------------------------------------------------------------------------------------------
title "E0. Lab prêt, NetBox prêt, bastion, comptes en lecture seule, clés d'hôte épinglées"
lab_ready_lab "$NET" "e2e-$KIND" 240
if ! bash lab-access/netbox/netbox_lab.sh status >/dev/null 2>&1; then
  bash lab-access/netbox/netbox_lab.sh up >/dev/null 2>&1 || { ko "NetBox n'a pas démarré"; exit 1; }
fi
PYTHONPATH="$PWD/lab-access/netbox/.pylib" $NC_PY lab-access/netbox/load_lab.py >/dev/null 2>&1 \
  && ok "NetBox sain, équipements des trois labs chargés" || ko "chargement de NetBox"
bash lab-access/bastion_lab.sh keys >/dev/null 2>&1
bash lab-access/bastion_lab.sh provision "$KIND" >"$JSON_DIR/bastion.txt" 2>&1 \
  && ok "bastion provisionné (relais limité aux 5 routeurs, port 22)" || { ko "bastion"; tail -3 "$JSON_DIR/bastion.txt"; }
bash lab-access/accounts_lab.sh "$KIND" provision >"$JSON_DIR/accounts.txt" 2>&1 \
  && ok "comptes netcheck-ro posés et vérifiés (clé, rôle, politique Pathz pour SR Linux)" \
  || { ko "comptes en lecture seule"; tail -5 "$JSON_DIR/accounts.txt"; }
bash lab-access/pin_hostkeys.sh "$KIND" >"$JSON_DIR/pin.txt" 2>&1 && grep -q "^$NET.2 ssh-ed25519 " "$NETCHECK_KNOWN_HOSTS" \
  && ok "clés d'hôte des routeurs ET du bastion épinglées (lues dans les conteneurs)" || ko "épinglage des clés d'hôte"

# L'inventaire du scénario : la LISTE des équipements vient de NetBox ; compte netcheck-ro par clé ; doas pour FRR ; bastion.
$NC_PY lab-access/netbox/make_inventory.py "$KIND" --out "$JSON_DIR/inv_netbox.yml"
$NC_PY - "$JSON_DIR/inv_netbox.yml" "$JSON_DIR/inv_e2e.yml" "$PWD/lab-access/.keys/netcheck_ro" \
  "$PWD/lab-access/.keys/netcheck_bastion" "$NET.2" "$FRR_NODES" <<'PY'
import sys

import yaml

src, dst, ro_key, bastion_key, bastion_host, frr_nodes = sys.argv[1:7]
inv = yaml.safe_load(open(src, encoding="utf-8"))
defaults = inv.setdefault("defaults", {})
defaults.pop("password", None)
defaults["username"], defaults["key_file"] = "netcheck-ro", ro_key
for name, router in inv["routers"].items():
    for field in ("password", "username", "key_file"):
        router.pop(field, None)
    if name in frr_nodes.split():
        router["privilege_wrapper"] = "doas"
inv["bastion"] = {"host": bastion_host, "username": "jump", "key_file": bastion_key}
yaml.safe_dump(inv, open(dst, "w", encoding="utf-8"), sort_keys=False)
PY
[[ -s "$JSON_DIR/inv_e2e.yml" ]] && ok "inventaire du scénario : NetBox + netcheck-ro par clé + bastion (aucun mot de passe)" || ko "inventaire non produit"
INVE="$JSON_DIR/inv_e2e.yml"

# ------------------------------------------------------------------------------------------------------------------
title "E1. snapshot : clés d'hôte strictes, bastion, netcheck-ro, NetBox"
out=$($NC snapshot "$REF" --force -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "snapshot des 5 équipements : code 0" || { ko "snapshot : code $code"; echo "$out" | tail -8; }
echo "$out" | flat | grep -q "Inventaire NetBox : http://127.0.0.1:8000" && ok "la liste des équipements vient de NetBox (annoncé)" || ko "NetBox non annoncé"
echo "$out" | flat | grep -q "bastion : jump@$NET.2" && ok "passage par le bastion (annoncé)" || ko "bastion non annoncé"
echo "$out" | flat | grep -qi "accept-new" && ko "clés d'hôte : accept-new utilisé" || ok "clés d'hôte STRICTES : aucun accept-new"
$NC_PY - "snapshots/$REF/meta.json" "$KIND" <<'PY' && ok "meta.json v0.4 : scope = inventaire complet (5 équipements), aucun périmètre demandé" || ko "meta.json sans scope complet"
import json
import sys

meta = json.load(open(sys.argv[1], encoding="utf-8"))
scope = meta.get("scope") or {}
assert sorted(scope.get("inventory", [])) == ["r1", "r2", "r3", "r4", "r5"], scope
assert scope.get("requested") is None, scope
assert meta["timestamp"] and meta["netcheck_version"]
assert all(json.load(open(f"{sys.argv[1].rsplit('/', 1)[0]}/{n}.json"))["reachable"] for n in scope["inventory"])
PY

# ------------------------------------------------------------------------------------------------------------------
title "E2. check, assert, guard, monitor avec le même inventaire (live)"
out=$($NC check "${RULES[@]}" --derogations "$DEROG" --json "$JSON_DIR/check_live_d.json" -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "check en direct avec les dérogations du lab : code 0" || { ko "check live : code $code"; echo "$out" | tail -6; }
out=$($NC assert --intent "$INTENT" --json "$JSON_DIR/assert_live.json" -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "assert en direct : code 0" || { ko "assert live : code $code"; echo "$out" | tail -6; }
MARK="$JSON_DIR/change_executed"; printf 'touch %s\n' "$MARK" > "$JSON_DIR/change.sh"
out=$($NC guard --change "$JSON_DIR/change.sh" --yes --wait 60 -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "guard (changement inoffensif, convergence attendue) : code 0" || { ko "guard : code $code"; echo "$out" | tail -8; }
[[ -e "$MARK" ]] && ok "le script de changement a bien été exécuté par guard (jamais par netcheck)" || ko "script de changement non exécuté"
out=$($NC monitor --baseline "$REF" --intent "$INTENT" "${RULES[@]}" --derogations "$DEROG" \
  --state-file "$JSON_DIR/monitor_state.json" -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "monitor : statut OK, code 0" || { ko "monitor : code $code"; echo "$out" | tail -8; }

# ------------------------------------------------------------------------------------------------------------------
title "E3. Violations en direct == violations de --config-dir (règle, équipement, objet), avec et sans dérogations"
CFG=(); for d in "${DIRS[@]}"; do CFG+=(--config-dir "$d"); done
$NC check "${RULES[@]}" --json "$JSON_DIR/check_live.json" -i "$INVE" >/dev/null 2>&1; live_code=$?
$NC check "${RULES[@]}" "${CFG[@]}" --json "$JSON_DIR/check_cfg.json" -i "$INV" >/dev/null 2>&1; cfg_code=$?
$NC check "${RULES[@]}" "${CFG[@]}" --derogations "$DEROG" --json "$JSON_DIR/check_cfg_d.json" -i "$INV" >/dev/null 2>&1; cfg_d_code=$?
[[ "$live_code" == "$cfg_code" && "$live_code" == "2" ]] && ok "sans dérogations : même code en direct et hors ligne (2, les liens OSPFv3 sans authentification)" \
  || ko "codes sans dérogations : direct $live_code, hors ligne $cfg_code"
[[ "$cfg_d_code" == "0" ]] && ok "hors ligne avec les dérogations : code 0, comme en direct" || ko "hors ligne avec dérogations : code $cfg_d_code"
$NC_PY - "$JSON_DIR" <<'PY' && ok "ensembles (règle, équipement, objet) IDENTIQUES, non vides sans dérogation ; dérogations identiques" || ko "ensembles différents"
import json
import sys

d = sys.argv[1]
load = lambda name: json.load(open(f"{d}/{name}.json", encoding="utf-8"))
key = lambda items: {(v["rule_id"], v["device"], v["object"]) for v in items}
live, cfg, live_d, cfg_d = load("check_live"), load("check_cfg"), load("check_live_d"), load("check_cfg_d")
# Les règles déclarées hors périmètre hors ligne (sources: [live, snapshot]) ne sont évaluées qu'en direct.
scoped = {g["rule_id"] for g in cfg["out_of_scope"] if "source" in g["scope"]}
live_set = {k for k in key(live["violations"]) if k[0] not in scoped}
cfg_set = key(cfg["violations"])
assert live_set == cfg_set and cfg_set, (sorted(live_set), sorted(cfg_set))
assert not [v for v in live["violations"] if v["rule_id"] in scoped], "une règle live-seulement viole"
assert key(live_d["violations"]) == key(cfg_d["violations"]) == set()
derogated = lambda r: key(r["derogations"]["derogated"])
assert derogated(live_d) == derogated(cfg_d) == cfg_set, (derogated(live_d), derogated(cfg_d))
PY

# ------------------------------------------------------------------------------------------------------------------
title "E4. Couverture et fraîcheur d'un snapshot lu hors ligne, sur de vraies données"
out=$($NC check "${RULES[@]}" --derogations "$DEROG" --snapshot "$REF" --max-age 1 --json "$JSON_DIR/snap_ok.json" -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "snapshot complet et frais (--max-age 1) : code 0" || { ko "snapshot complet : code $code"; echo "$out" | tail -6; }
echo "$out" | flat | grep -q "périmètre du snapshot : r1, r2, r3, r4, r5 (5/5 de l'inventaire)" && ok "périmètre affiché : 5/5" || ko "périmètre non affiché"
VERSION=$($NC_PY -c 'import netcheck; print(netcheck.__version__)')
echo "$out" | flat | grep -qE "pris le [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC avec netcheck ${VERSION//./\\.}, âge" \
  && ok "date, version de netcheck ($VERSION, celle qui a pris le snapshot) et âge affichés" || ko "date et version non affichées"
rm -rf "snapshots/e2e_cut"; cp -r "snapshots/$REF" "snapshots/e2e_cut"; rm -f "snapshots/e2e_cut/r3.json"
out=$($NC check "${RULES[@]}" --derogations "$DEROG" --snapshot e2e_cut -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "1" ]] && echo "$out" | flat | grep -q "absents du snapshot sans avoir été exclus volontairement (-d) : r3" \
  && ok "snapshot amputé de r3 : ANALYSE INCOMPLÈTE (code 1), r3 nommé" || { ko "snapshot amputé : code $code"; echo "$out" | tail -6; }
out=$($NC assert --intent "$INTENT" --snapshot e2e_cut -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "1" ]] && ok "assert sur le snapshot amputé : ATTENTION (code 1)" || ko "assert sur snapshot amputé : code $code"
out=$($NC check "${RULES[@]}" --derogations "$DEROG" --snapshot "$REF" --max-age 0.00001 -i "$INVE" 2>&1); code=$?; log "$out"
[[ "$code" == "1" ]] && echo "$out" | flat | grep -q "snapshot trop ancien" && ok "--max-age 0.00001 : snapshot trop ancien (code 1), âge affiché" \
  || { ko "--max-age : code $code"; echo "$out" | tail -4; }
out=$($NC check "${RULES[@]}" --snapshot "$REF" --max-age abc -i "$INVE" 2>&1); code=$?
[[ "$code" == "3" ]] && ok "--max-age invalide : code 3" || ko "--max-age invalide : code $code"

# ------------------------------------------------------------------------------------------------------------------
title "E5. Identifiants lus dans Vault (clés d'hôte strictes, bastion, NetBox), équipements FRR du lab"
if ENGINE=vault bash lab-access/vault_lab.sh up >"$JSON_DIR/vault_up.txt" 2>&1 \
   && ENGINE=vault bash lab-access/vault_lab.sh provision >>"$JSON_DIR/vault_up.txt" 2>&1; then
  ok "Vault de développement prêt (AppRole durci, secret des identifiants du lab)"
  $NC_PY - "$INVE" "$JSON_DIR/inv_vault.yml" <<'PY'
import sys

import yaml

inv = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
for field in ("username", "password", "key_file"):
    inv["defaults"].pop(field, None)
for router in inv["routers"].values():
    router.pop("privilege_wrapper", None)
yaml.safe_dump(inv, open(sys.argv[2], "w", encoding="utf-8"), sort_keys=False)
PY
  ENGINE=vault bash lab-access/vault_lab.sh secret-id >/dev/null 2>&1
  # shellcheck disable=SC2086
  out=$( eval "$(ENGINE=vault bash lab-access/vault_lab.sh env)"; $NC snapshot e2e_vault --force -d $FRR_NODES -i "$JSON_DIR/inv_vault.yml" 2>&1 ); code=$?
  log "$out"
  [[ "$code" == "0" ]] && ok "snapshot des routeurs FRR avec les identifiants de Vault : code 0" || { ko "snapshot Vault : code $code"; echo "$out" | tail -6; }
  echo "$out" | flat | grep -q "Vault (secret/netcheck/lab)" && ok "source affichée : Vault (secret/netcheck/lab), jamais une valeur" || ko "source Vault non affichée"
  out=$($NC check "${RULES[@]}" --derogations "$DEROG" --snapshot e2e_vault -i "$INVE" 2>&1); code=$?; log "$out"
  [[ "$code" == "0" ]] && echo "$out" | flat | grep -q "information : périmètre demandé (-d) : " \
    && ok "snapshot partiel demandé (-d) : périmètre dit, aucun effet sur le code (0)" || { ko "snapshot -d : code $code"; echo "$out" | tail -5; }
  ENGINE=vault bash lab-access/vault_lab.sh down >/dev/null 2>&1
else
  ko "Vault n'a pas démarré"; tail -5 "$JSON_DIR/vault_up.txt"
fi

# ------------------------------------------------------------------------------------------------------------------
title "E6. Aucun secret dans aucune sortie ni aucun fichier produit"
out=$($NC_PY - "$JSON_DIR" "snapshots/$REF" snapshots/e2e_cut snapshots/e2e_vault <<'PY'
import pathlib
import sys

secrets = {}
for label, path in (("clé netcheck-ro", "lab-access/.keys/netcheck_ro"), ("clé du bastion", "lab-access/.keys/netcheck_bastion"),
                    ("clé des routeurs", "lab-access/.keys/netcheck_router")):
    p = pathlib.Path(path)
    if p.is_file():
        body = [ln for ln in p.read_text().splitlines() if ln and not ln.startswith("-----")]
        secrets[label] = body[0][:40] if body else None
token = pathlib.Path.home().joinpath(".config/netcheck/netbox-ro.token").read_text().strip()
secrets["jeton NetBox"] = token.split(".", 1)[1]
hits, files = [], 0
for root in sys.argv[1:]:
    for path in pathlib.Path(root).rglob("*"):
        if path.is_file():
            files += 1
            data = path.read_bytes().decode("utf-8", errors="replace")
            hits += [f"{label} dans {path}" for label, secret in secrets.items() if secret and secret in data]
print(f"{files} fichier(s) examiné(s)")
print("OK" if not hits else "KO " + "; ".join(hits[:4]))
PY
)
[[ "$(echo "$out" | tail -1)" == "OK" ]] && ok "clés SSH et jeton NetBox absents de $(echo "$out" | head -1) (sorties, snapshots)" || ko "secret trouvé : $out"

# ------------------------------------------------------------------------------------------------------------------
title "Nettoyage : seul c7-ref-* est gardé ; les routeurs n'ont jamais été modifiés par netcheck"
for dir in $(comm -13 <(echo "$snaps_before") <(snaps_now)); do
  [[ "$(basename "$dir")" == "$REF" ]] || rm -rf "$dir"
done
for file in $(comm -13 <(echo "$journals_before") <(journals_now)); do rm -f "$file"; done
[[ -d "snapshots/$REF" ]] && ok "référence complète et fraîche gardée : snapshots/$REF (locale, hors Git)" || ko "référence absente"

echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 Bout en bout sur $KIND : strict + bastion + netcheck-ro + NetBox + Vault." || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
