#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénarios NetBox RÉELS (phase C6.2) : netcheck lit la LISTE des équipements d'un lab dans NOTRE NetBox de lab.
#   bash tests/integration_netbox.sh frr|multivendor|ceos
# Prérequis : le lab déployé et NetBox démarré (lab-access/netbox/netbox_lab.sh up ; démarré ici s'il manque). Les
# équipements des trois labs sont chargés (idempotent) par lab-access/netbox/load_lab.py. Les routeurs ne sont JAMAIS
# modifiés : seuls des snapshots sont pris, et `guard` n'exécute qu'un script qui ne touche à rien (`touch` d'un témoin).
# Ce script n'écrit que dans NOTRE NetBox de lab (un équipement « de NetBox seulement » ajouté puis retiré).
# Code retour : 0 si tout passe, 1 sinon.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

KIND="${1:-}"
case "$KIND" in
  frr)         INV=automation/inventory.yml;              SITE=lab-frr;         NET=172.20.20; INTENT=intents/lab.yml ;;
  multivendor) INV=automation/inventory-multivendor.yml;  SITE=lab-multivendor; NET=172.20.21; INTENT=intents/lab-multivendor.yml ;;
  ceos)        INV=automation/inventory-ceos.yml;         SITE=lab-ceos;        NET=172.20.22; INTENT=intents/lab-ceos.yml ;;
  *) echo "usage : $0 frr|multivendor|ceos" >&2; exit 2 ;;
esac
NC="netcheck/.venv/bin/python -m netcheck"
NC_PY="netcheck/.venv/bin/python"
PYLIB="$PWD/lab-access/netbox/.pylib"
JSON_DIR="/tmp/netcheck_netbox_integration_$KIND"
rm -rf "$JSON_DIR"; mkdir -p "$JSON_DIR"
TOKEN_FILE="$HOME/.config/netcheck/netbox-ro.token"
PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }
# shellcheck source=tests/lib_lab.sh
source "$(dirname "$0")/lib_lab.sh"

nbpy() { PYTHONPATH="$PYLIB" $NC_PY "$@"; }
mkinv() { $NC_PY lab-access/netbox/make_inventory.py "$KIND" "$@"; }
log() { echo "$1" >> "$JSON_DIR/all.out"; }                 # tout ce que netcheck a écrit, pour la recherche du jeton
snaps_now() { find snapshots -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort; }
journals_now() { find reports -maxdepth 1 -name 'guard_*.json' 2>/dev/null | sort; }

unset NETCHECK_USER NETCHECK_PASS NETCHECK_USER_FILE NETCHECK_PASS_FILE LAB_USER LAB_PASS NETCHECK_NETBOX_TOKEN
export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
export NETCHECK_NETBOX_TOKEN_FILE="$TOKEN_FILE"
lab_ready_lab "$NET" "integration-netbox-$KIND" 240
bash lab-access/pin_hostkeys.sh "$KIND" >/dev/null || { echo "épinglage des clés d'hôte impossible (lab déployé ?)"; exit 1; }
snaps_before=$(snaps_now); journals_before=$(journals_now)

# ------------------------------------------------------------------------------------------------------------------
title "N0. NetBox de lab prêt, équipements chargés, jeton en lecture seule"
if ! bash lab-access/netbox/netbox_lab.sh status >/dev/null 2>&1; then
  echo "  … NetBox absent : démarrage (deux temps, limite 20 min)"
  bash lab-access/netbox/netbox_lab.sh up || { ko "NetBox n'a pas démarré"; exit 1; }
fi
bash lab-access/netbox/netbox_lab.sh status >/dev/null 2>&1 && ok "NetBox sain (netbox et worker), écoute en 127.0.0.1" || ko "NetBox n'est pas sain"
out=$(nbpy lab-access/netbox/load_lab.py 2>&1); code=$?
[[ "$code" == "0" ]] && ok "chargement des équipements des trois labs (idempotent) : $(echo "$out" | head -1)" || { ko "load_lab.py : code $code"; echo "$out" | tail -5; }
[[ "$(stat -c %a "$TOKEN_FILE")" == "600" ]] && ok "jeton en lecture seule : fichier 0600 hors dépôt" || ko "droits du fichier de jeton : $(stat -c %a "$TOKEN_FILE")"
git check-ignore -q "$TOKEN_FILE" 2>/dev/null; [[ -z "$(git ls-files --error-unmatch "$TOKEN_FILE" 2>/dev/null)" ]] && ok "le fichier de jeton n'est pas suivi par Git" || ko "le jeton est suivi par Git"
initial_devices=$(nbpy lab-access/netbox/netbox_admin.py devices --site "$SITE")
info_count=$(echo "$initial_devices" | wc -w)
[[ "$info_count" == "5" ]] && ok "le site $SITE contient 5 équipements : $initial_devices" || ko "site $SITE : $initial_devices"

# ------------------------------------------------------------------------------------------------------------------
title "N1. Forme RÉELLE de la réponse de NetBox (ce que netcheck lit)"
out=$($NC_PY - "$TOKEN_FILE" "$SITE" <<'PY'
import json, sys, urllib.request
token = open(sys.argv[1]).read().strip()
def get(path):
    request = urllib.request.Request("http://127.0.0.1:8000" + path,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=15))
page = get(f"/api/dcim/devices/?site={sys.argv[2]}&limit=100")
problems = []
for d in page["results"]:
    ip = d.get("primary_ip") or {}
    if "/" not in str(ip.get("address", "")) or not (d.get("platform") or {}).get("slug") or (d.get("status") or {}).get("value") != "active":
        problems.append(d.get("name"))
first = page["results"][0]
print("OK" if not problems and page["count"] == len(page["results"]) else "KO " + ",".join(map(str, problems)))
print("primary_ip : clés", sorted(first["primary_ip"]), "; adresse de la forme", first["primary_ip"]["address"].rsplit(".", 1)[0] + ".x/NN")
print("platform.slug =", first["platform"]["slug"], "; status.value =", first["status"]["value"], "; count =", page["count"], "; next =", page["next"])
PY
)
log "$out"
[[ "$(echo "$out" | head -1)" == "OK" ]] && ok "primary_ip.address (avec masque), platform.slug et status.value présents sur chaque équipement" || ko "forme inattendue : $(echo "$out" | head -1)"
echo "$out" | tail -2 | sed 's/^/     /'

# ------------------------------------------------------------------------------------------------------------------
title "N2. Inventaire alimenté par NetBox = inventaire YAML (mêmes équipements, mêmes relevés)"
$NC snapshot nbi_yaml -i "$INV" >/dev/null 2>&1; code_yaml=$?
mkinv --out "$JSON_DIR/inv_nb.yml"
out=$($NC snapshot nbi_nb -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?; log "$out"
[[ "$code_yaml" == "$code" && "$code" == "0" ]] && ok "snapshot : code 0 avec l'inventaire YAML et avec l'inventaire NetBox" || ko "snapshot : YAML $code_yaml, NetBox $code"
echo "$out" | grep -q "Inventaire NetBox : http://127.0.0.1:8000 (NetBox 4\." && ok "la source est annoncée avec l'adresse et la version de NetBox" || ko "annonce de la source absente"
echo "$out" | grep -q "jeton : fichier $TOKEN_FILE (droits 0600 vérifiés)" && ok "la source du jeton est affichée (fichier, droits vérifiés), jamais sa valeur" || ko "source du jeton non affichée"
echo "$out" | grep -q "5 équipement(s) en 1 page(s) de 100 au plus (5 aussi dans l'inventaire local, 0 de NetBox seulement)" \
  && ok "5 équipements, tous aussi dans l'inventaire local" || ko "décompte des équipements inattendu"
echo "$out" | grep -q "NetBox en http://" && ok "http:// en bouclage sur un inventaire lab: true : annoncé" || ko "l'usage de http:// n'est pas annoncé"
[[ "$(find snapshots/nbi_yaml -name '*.json' | wc -l)" == "$(find snapshots/nbi_nb -name '*.json' | wc -l)" ]] && ok "mêmes équipements dans les deux snapshots" || ko "équipements différents"
out=$($NC diff nbi_yaml nbi_nb -i "$INV" 2>&1); code=$?; log "$out"
[[ "$code" == "0" && "$out" == *"Verdict : OK"* ]] && ok "diff YAML <-> NetBox : aucun constat (code 0)" || { ko "diff : code $code"; echo "$out" | tail -5; }

# ------------------------------------------------------------------------------------------------------------------
title "N3. Les verdicts sont les mêmes avec l'inventaire NetBox (check et assert)"
$NC check --rules netcheck/rules/default.yml --json "$JSON_DIR/check_yaml.json" -i "$INV" >/dev/null 2>&1; c1=$?
out=$($NC check --rules netcheck/rules/default.yml --json "$JSON_DIR/check_nb.json" -i "$JSON_DIR/inv_nb.yml" 2>&1); c2=$?; log "$out"
same=$($NC_PY - "$JSON_DIR/check_yaml.json" "$JSON_DIR/check_nb.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
print("OK" if (a["status"], len(a["violations"])) == (b["status"], len(b["violations"])) else "KO")
PY
)
[[ "$c1" == "$c2" && "$same" == "OK" ]] && ok "check : même code ($c1), même statut, même nombre de violations" || ko "check : YAML $c1, NetBox $c2 ($same)"
$NC assert --intent "$INTENT" --json "$JSON_DIR/assert_yaml.json" -i "$INV" >/dev/null 2>&1; a1=$?
out=$($NC assert --intent "$INTENT" --json "$JSON_DIR/assert_nb.json" -i "$JSON_DIR/inv_nb.yml" 2>&1); a2=$?; log "$out"
same=$($NC_PY - "$JSON_DIR/assert_yaml.json" "$JSON_DIR/assert_nb.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
key = lambda d: (d["verdict"], sorted((r["id"], r["device"], r["status"]) for r in d["results"]))
print("OK" if key(a) == key(b) else "KO")
PY
)
[[ "$a1" == "$a2" && "$same" == "OK" ]] && ok "assert : même code ($a1), même verdict, mêmes résultats avec les deux inventaires" || ko "assert : YAML $a1, NetBox $a2 ($same)"

# ------------------------------------------------------------------------------------------------------------------
title "N4. Pagination RÉELLE (page_size 2 : cinq équipements en trois pages)"
mkinv --page-size 2 --out "$JSON_DIR/inv_p2.yml"
out=$($NC snapshot nbi_p2 -i "$JSON_DIR/inv_p2.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "snapshot avec page_size 2 : code 0" || { ko "page_size 2 : code $code"; echo "$out" | tail -4; }
echo "$out" | grep -q "5 équipement(s) en 3 page(s) de 2 au plus" && ok "NetBox a bien rendu trois pages, liens next contrôlés et suivis" || ko "pagination non constatée"
out=$($NC diff nbi_yaml nbi_p2 -i "$INV" 2>&1); code=$?
[[ "$code" == "0" ]] && ok "le résultat paginé est identique (diff : aucun constat)" || ko "diff du résultat paginé : code $code"

# ------------------------------------------------------------------------------------------------------------------
title "N5. localhost et 127.0.0.1 : NetBox construit le lien next depuis l'en-tête Host"
for host in localhost 127.0.0.1; do
  mkinv --url "http://$host:8000" --page-size 2 --out "$JSON_DIR/inv_$host.yml"
  out=$($NC snapshot "nbi_$host" -i "$JSON_DIR/inv_$host.yml" 2>&1); code=$?; log "$out"
  [[ "$code" == "0" && "$out" == *"3 page(s) de 2"* && "$out" == *"http://$host:8000"* ]] \
    && ok "url http://$host:8000 : trois pages suivies, code 0" || { ko "url http://$host:8000 : code $code"; echo "$out" | tail -3; }
done

# ------------------------------------------------------------------------------------------------------------------
title "N6. Un lien next refusé (autre hôte, autre port) : refus clair, jamais une boucle ni un résultat partiel"
$NC_PY tests/tools/hostproxy.py --listen 18000 --target 127.0.0.1:8000 --host localhost:8000 --count-file "$JSON_DIR/proxy.count" >/dev/null 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null' EXIT
for _ in $(seq 1 25); do (exec 3<>/dev/tcp/127.0.0.1/18000) 2>/dev/null && break; sleep 0.2; done
mkinv --url http://127.0.0.1:18000 --page-size 2 --out "$JSON_DIR/inv_proxy.yml"
start=$SECONDS
out=$($NC snapshot nbi_next -i "$JSON_DIR/inv_proxy.yml" 2>&1); code=$?; log "$out"; elapsed=$((SECONDS - start))
[[ "$code" == "3" ]] && ok "snapshot : code 3 (erreur d'usage), pas un code 0 ni 1" || ko "snapshot derrière le proxy : code $code"
lines=$(echo "$out" | grep -c "^Erreur")
[[ "$lines" == "1" && "$out" == *"lien de pagination hors du NetBox configuré (refusé, jeton non envoyé)"* ]] \
  && ok "une seule ligne d'erreur, claire : lien hors du NetBox configuré, jeton non envoyé" || { ko "message du refus inattendu"; echo "$out" | tail -4; }
[[ "$elapsed" -lt 20 ]] && ok "refus immédiat (${elapsed} s) : aucune boucle" || ko "refus après ${elapsed} s"
[[ "$(wc -l < "$JSON_DIR/proxy.count")" == "2" ]] && ok "NetBox n'a reçu que 2 requêtes : /api/status/ et la première page, rien de plus" \
  || ko "requêtes reçues : $(wc -l < "$JSON_DIR/proxy.count")"
[[ ! -d snapshots/nbi_next ]] && ok "aucun snapshot écrit : aucun résultat partiel" || ko "un snapshot partiel existe"
kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; trap - EXIT

# ------------------------------------------------------------------------------------------------------------------
title "N7. NetBox injoignable ou jeton révoqué : code 3, jamais un repli sur le fichier local"
mkinv --url http://127.0.0.1:18999 --out "$JSON_DIR/inv_closed.yml"
out=$($NC snapshot nbi_closed -i "$JSON_DIR/inv_closed.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "3" && "$out" == *"inventaire NetBox indisponible (127.0.0.1:18999 : injoignable)"* && ! -d snapshots/nbi_closed ]] \
  && ok "port fermé : code 3, « injoignable », aucun snapshot (le YAML n'est pas utilisé en repli)" || { ko "port fermé : code $code"; echo "$out" | tail -3; }
while IFS= read -r line; do
  log "$line"
  case "$line" in OK\ *) ok "${line#OK }" ;; KO\ *) ko "${line#KO }" ;; *) ko "sortie inattendue : $line" ;; esac
done < <(nbpy lab-access/netbox/prove_readonly.py --revoked-token-out "$JSON_DIR/revoked.token" 2>&1)
out=$(NETCHECK_NETBOX_TOKEN_FILE="$JSON_DIR/revoked.token" $NC snapshot nbi_rev -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "3" && "$out" == *"jeton refusé, HTTP 40"* && ! -d snapshots/nbi_rev ]] \
  && ok "jeton révoqué : netcheck sort en code 3 « jeton refusé », aucun snapshot" || { ko "jeton révoqué : code $code"; echo "$out" | tail -3; }

# ------------------------------------------------------------------------------------------------------------------
title "N8. Hors ligne, NetBox n'est JAMAIS contacté (même avec une adresse de NetBox injoignable)"
out=$($NC diff nbi_yaml nbi_nb -i "$JSON_DIR/inv_closed.yml" 2>&1); code=$?
[[ "$code" == "0" && "$out" != *"NetBox"* ]] && ok "diff avec un inventaire dont NetBox est injoignable : code 0, aucun appel" || { ko "diff hors ligne : code $code"; echo "$out" | tail -3; }
out=$($NC check --snapshot nbi_nb --rules netcheck/rules/security.yml -i "$JSON_DIR/inv_closed.yml" 2>&1); code=$?
[[ "$code" != "3" && "$out" != *"NetBox"* ]] && ok "check --snapshot : aucun appel à NetBox (code $code)" || ko "check --snapshot : code $code"
out=$($NC assert --intent "$INTENT" --snapshot nbi_nb -i "$JSON_DIR/inv_closed.yml" 2>&1); code=$?
[[ "$code" != "3" && "$out" != *"NetBox"* ]] && ok "assert --snapshot : aucun appel à NetBox (code $code)" || ko "assert --snapshot : code $code"

# ------------------------------------------------------------------------------------------------------------------
title "N9. Un équipement ajouté dans NetBox SEUL : guard refuse (option C), puis opt-in nominatif"
nbpy lab-access/netbox/netbox_admin.py add-device --site "$SITE" --name r9 --ip "$NET.11" --driver frr --vrf lab-dup >/dev/null 2>&1 \
  && ok "r9 ajouté dans NetBox seulement (IP de r1 dans une VRF à part : NetBox refuse deux fois la même adresse hors VRF)" || ko "ajout de r9 impossible"
printf 'touch %s\n' "$JSON_DIR/change_executed" > "$JSON_DIR/change.sh"
snaps_a=$(snaps_now); journals_a=$(journals_now)
out=$($NC guard --change "$JSON_DIR/change.sh" --yes --wait 5 -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "3" ]] && ok "guard refuse (code 3) un périmètre dont un équipement n'a aucun attendu local" || ko "guard sans opt-in : code $code"
echo "$out" | tr '\n' ' ' | tr -s ' ' | grep -q "1 équipement(s) du périmètre sans attendus locaux (ospf_neighbors, ospf6_neighbors, bgp_peers, bgp6_peers) : r9\." \
  && ok "le message liste r9 et nomme les quatre attendus" || ko "message du refus inattendu"
[[ ! -e "$JSON_DIR/change_executed" ]] && ok "le script de changement n'a PAS été exécuté" || ko "le script a été exécuté malgré le refus"
[[ "$(snaps_now)" == "$snaps_a" && "$(journals_now)" == "$journals_a" ]] \
  && ok "aucun snapshot, aucun journal : le refus précède tout" || ko "guard a laissé des traces malgré le refus"
out=$($NC guard --change "$JSON_DIR/change.sh" --yes --wait 5 --accept-unverified r9 -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "1" ]] && ok "avec --accept-unverified r9 : le verdict final est ATTENTION (code 1), jamais 0" || { ko "guard avec opt-in : code $code"; echo "$out" | tail -6; }
[[ -e "$JSON_DIR/change_executed" ]] && ok "le changement (inoffensif) a été exécuté" || ko "le changement n'a pas été exécuté avec l'opt-in"
echo "$out" | tr '\n' ' ' | tr -s ' ' | grep -q "Équipements acceptés SANS vérification de convergence (--accept-unverified) : r9" \
  && ok "r9 est annoncé AVANT l'exécution" || ko "annonce avant exécution absente"
echo "$out" | tr '\n' ' ' | tr -s ' ' | grep -q "convergence NON vérifiée (--accept-unverified) pour : r9" \
  && ok "r9 est annoncé dans le message final" || ko "message final sans r9"
out=$($NC guard --change "$JSON_DIR/change.sh" --yes --accept-unverified all -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?
[[ "$code" == "3" && "$out" == *"pas de joker, pas de « all »"* ]] && ok "« all » est refusé" || ko "--accept-unverified all : code $code"
nbpy lab-access/netbox/netbox_admin.py remove-device --site "$SITE" --name r9 --vrf lab-dup >/dev/null 2>&1 \
  && ok "r9 retiré de NetBox" || ko "retrait de r9 impossible"
[[ "$(nbpy lab-access/netbox/netbox_admin.py devices --site "$SITE")" == "$initial_devices" ]] \
  && ok "NetBox revenu à son état initial (mêmes équipements dans $SITE)" || ko "NetBox n'est pas revenu à son état initial"
out=$($NC guard --change "$JSON_DIR/change.sh" --yes --wait 5 -i "$JSON_DIR/inv_nb.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "0" ]] && ok "r9 retiré : guard repart sans option, verdict OK (code 0)" || { ko "guard après retrait : code $code"; echo "$out" | tail -4; }

# ------------------------------------------------------------------------------------------------------------------
title "N10. Un routeur du fichier local absent de NetBox : erreur, jamais ignoré"
mkinv --local-only r8 --out "$JSON_DIR/inv_r8.yml"
out=$($NC snapshot nbi_r8 -i "$JSON_DIR/inv_r8.yml" 2>&1); code=$?; log "$out"
[[ "$code" == "3" && "$out" == *"absent(s) de NetBox"* && "$out" == *"r8"* && ! -d snapshots/nbi_r8 ]] \
  && ok "code 3, r8 nommé, aucun snapshot" || { ko "routeur local absent de NetBox : code $code"; echo "$out" | tail -3; }

# ------------------------------------------------------------------------------------------------------------------
title "N11. Le jeton n'apparaît dans AUCUNE sortie ni AUCUN fichier produit"
out=$($NC_PY - "$TOKEN_FILE" "$JSON_DIR" snapshots reports <<'PY'
import pathlib, sys
token = open(sys.argv[1]).read().strip()
parts = {token, token.removeprefix("nbt_").split(".", 1)[0], token.split(".", 1)[1]}
hits = []
files = 0
for root in sys.argv[2:]:
    for path in pathlib.Path(root).rglob("*"):
        if path.is_file() and path.name != "revoked.token" and path.stat().st_size < 50_000_000:
            files += 1
            data = path.read_bytes().decode("utf-8", errors="replace")
            hits += [str(path) for part in parts if part and part in data]
print(f"{files} fichier(s) examiné(s)")
print("OK" if not hits else "KO " + ", ".join(sorted(set(hits))[:5]))
PY
)
[[ "$(echo "$out" | tail -1)" == "OK" ]] && ok "jeton (entier, clé, secret) absent de $(echo "$out" | head -1) (sorties, snapshots, rapports)" || ko "le jeton est apparu : $out"

# ------------------------------------------------------------------------------------------------------------------
title "Nettoyage : snapshots de ce scénario retirés, routeurs jamais modifiés"
for dir in $(comm -13 <(echo "$snaps_before") <(snaps_now)); do rm -rf "$dir"; done
for file in $(comm -13 <(echo "$journals_before") <(journals_now)); do rm -f "$file"; done
[[ "$(snaps_now)" == "$snaps_before" ]] && ok "les snapshots du dépôt sont revenus à leur état d'avant" || ko "des snapshots restent"
[[ "$(nbpy lab-access/netbox/netbox_admin.py devices --site "$SITE")" == "$initial_devices" ]] && ok "NetBox : état initial" || ko "NetBox modifié"

echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
(( FAIL == 0 )) && echo "🎉 netcheck lit la liste des équipements de $KIND dans NetBox, sans repli ni faux OK." || echo "⚠️  Voir les lignes ❌ ci-dessus."
exit $(( FAIL > 0 ))
