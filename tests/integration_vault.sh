#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénarios Vault (phase C3) : netcheck lit les identifiants du lab FRR dans Vault, puis dans OpenBao.
#   bash tests/integration_vault.sh
# Prérequis : le lab FRR déployé (lecture seule : seuls des snapshots sont pris), docker, hvac dans le venv.
# Le conteneur Vault de développement est créé puis détruit par le script (lab-access/vault_lab.sh).
# Code retour : 0 si tout passe, 1 sinon. Aucun routeur n'est modifié.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

NC="netcheck/.venv/bin/python -m netcheck"
NC_PY="netcheck/.venv/bin/python"
JSON_DIR=/tmp/netcheck_vault_integration
mkdir -p "$JSON_DIR"
rm -f "$JSON_DIR"/*

PASS=0; FAIL=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
ko() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
title() { echo; echo "=== $1 ==="; }
skip() { echo "  ⏭  $1"; }

# Aucun identifiant hérité de l'environnement : seul Vault (ou l'inventaire) peut les fournir.
unset NETCHECK_USER NETCHECK_PASS NETCHECK_USER_FILE NETCHECK_PASS_FILE LAB_USER LAB_PASS
unset NETCHECK_FRR_USER NETCHECK_FRR_PASS NETCHECK_FRR_USER_FILE NETCHECK_FRR_PASS_FILE
export NETCHECK_KNOWN_HOSTS="$PWD/lab-access/.keys/known_hosts"
bash lab-access/pin_hostkeys.sh frr >/dev/null || { echo "épinglage des clés d'hôte impossible (lab FRR déployé ?)"; exit 1; }

# Un inventaire dont le mot de passe est FAUX : seule une valeur venue de Vault peut ouvrir les sessions SSH.
WRONG_INV="$JSON_DIR/inventory_wrong_password.yml"
sed 's/password: netops/password: "not-the-password-0000"/' automation/inventory.yml > "$WRONG_INV"
grep -q 'not-the-password-0000' "$WRONG_INV" || { echo "inventaire de test non produit"; exit 1; }

# http_status METHOD URL [fichier-jeton] [corps-json] : n'affiche que le code HTTP (jamais le jeton ni le corps).
http_status() {
  "$NC_PY" - "$@" <<'EOF'
import json, sys, urllib.error, urllib.request
method, url = sys.argv[1], sys.argv[2]
token = open(sys.argv[3]).read().strip() if len(sys.argv) > 3 and sys.argv[3] else None
body = sys.argv[4].encode() if len(sys.argv) > 4 else None
request = urllib.request.Request(url, data=body, method=method)
if token:
    request.add_header("X-Vault-Token", token)
try:
    print(urllib.request.urlopen(request, timeout=5).status)
except urllib.error.HTTPError as error:
    print(error.code)
EOF
}

vault_scenarios() {
  local engine="$1" container port
  case "$engine" in vault) container=netcheck-vault; port=18200 ;; openbao) container=netcheck-openbao; port=18201 ;; esac
  local base="http://127.0.0.1:$port"
  local label="$engine"
  local lab=(env "ENGINE=$engine" bash lab-access/vault_lab.sh)

  title "V1 ($label) : le conteneur de développement et le provisionnement"
  "${lab[@]}" up >"$JSON_DIR/$engine.up" 2>&1 && ok "conteneur démarré ($(docker ps --filter "name=^$container\$" --format '{{.Image}}'))" \
    || { ko "démarrage impossible"; cat "$JSON_DIR/$engine.up"; return; }
  "${lab[@]}" provision >"$JSON_DIR/$engine.prov" 2>&1 && ok "AppRole + politique en lecture seule + secret du lab" \
    || { ko "provisionnement impossible"; cat "$JSON_DIR/$engine.prov"; return; }
  eval "$("${lab[@]}" env)"
  # Journal d'audit du serveur : disponible sur Vault ; OpenBao 2.7 ne l'active pas par l'API.
  local audit_on=0 audit_offset=0
  docker exec "$container" test -f /tmp/audit.log && audit_on=1
  audit_count() { docker exec "$container" cat /tmp/audit.log | wc -l; }
  ((audit_on)) && audit_offset=$(audit_count)

  title "V2 ($label) : netcheck lit les identifiants dans Vault (inventaire à mot de passe FAUX, lab FRR réel)"
  local out code
  out=$($NC snapshot "vault_v2_$engine" --force -i "$WRONG_INV" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "snapshot des 5 routeurs : code 0 (les sessions SSH ont été ouvertes avec le mot de passe de Vault)" \
    || { ko "snapshot : code $code"; echo "$out"; }
  grep -q "mot de passe : Vault (secret/netcheck/lab) (r1, r2, r3, r4, r5)" <<<"$out" \
    && ok "source affichée : « Vault (secret/netcheck/lab) », pour les 5 routeurs" \
    || { ko "source Vault non affichée"; echo "$out"; }
  grep -q "remarque : expurgation par valeur inactive pour ce secret (moins de 8 caractères)" <<<"$out" \
    && ok "note d'information (mot de passe de lab de moins de 8 caractères), sans effet sur le code retour" \
    || ko "note de mot de passe court absente"
  grep -q "netops" "snapshots/vault_v2_$engine/meta.json" \
    && ko "meta.json contient une valeur secrète" || ok "meta.json : la source, jamais la valeur"
  grep -q '"mot de passe": {' "snapshots/vault_v2_$engine/meta.json" \
    && grep -q 'Vault (secret/netcheck/lab)' "snapshots/vault_v2_$engine/meta.json" \
    && ok "meta.json : credential_sources cite Vault" || ko "meta.json : source Vault absente"

  title "V3 ($label) : exactement deux appels reçus par Vault (journal d'audit du serveur)"
  local calls
  if ((audit_on)); then
  calls=$(docker exec "$container" cat /tmp/audit.log | tail -n +$((audit_offset + 1)) | "$NC_PY" -c '
import json, sys
for line in sys.stdin:
    entry = json.loads(line)
    if entry.get("type") == "request":
        print(entry["request"]["operation"], entry["request"]["path"])')
  [[ "$calls" == $'update auth/approle/login\nread secret/data/netcheck/lab' ]] \
    && ok "journal d'audit : « update auth/approle/login » puis « read secret/data/netcheck/lab », rien d'autre" \
    || { ko "appels inattendus"; echo "$calls"; }
  else
    skip "journal d'audit indisponible sur $engine : contrôle réservé à Vault"
  fi

  title "V4 ($label) : preuve négative par le serveur : le rôle ne peut ni écrire ni lire ailleurs (appels HTTP directs, pas netcheck)"
  local token_file="$JSON_DIR/$engine.token" role_id
  role_id=$(cat "lab-access/.keys/$container.role_id")
  ( umask 077
    "$NC_PY" - "$base" "$role_id" "lab-access/.keys/$container.secret_id" > "$token_file" <<'EOF'
import json, sys, urllib.request
base, role_id, secret_id_file = sys.argv[1:4]
body = json.dumps({"role_id": role_id, "secret_id": open(secret_id_file).read().strip()}).encode()
reply = json.load(urllib.request.urlopen(urllib.request.Request(base + "/v1/auth/approle/login", data=body), timeout=5))
sys.stdout.write(reply["auth"]["client_token"])
EOF
  )
  [[ -s "$token_file" ]] || { ko "ouverture de session AppRole impossible"; return; }
  local status
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "200" ]] && ok "lecture de secret/data/netcheck/lab : 200 (autorisée)" || ko "lecture autorisée : $status"
  local pol='{"policy":"path \"*\" {capabilities = [\"sudo\"]}"}'
  local -a denied=(
    "PUT|$base/v1/secret/data/netcheck/lab|{\"data\":{\"password\":\"x\"}}|écriture du secret"
    "POST|$base/v1/secret/data/netcheck/lab|{\"data\":{\"password\":\"x\"}}|écriture (POST) du secret"
    "DELETE|$base/v1/secret/data/netcheck/lab||suppression du secret"
    "GET|$base/v1/secret/data/autre-chemin||lecture d'un autre chemin"
    "GET|$base/v1/secret/data/netcheck||lecture du dossier parent"
    "LIST|$base/v1/secret/metadata/||liste des secrets"
    "GET|$base/v1/sys/mounts||sys/mounts"
    "PUT|$base/v1/sys/policies/acl/netcheck-ro|$pol|modification de sa propre politique"
    "POST|$base/v1/auth/approle/role/netcheck-ro/secret-id||création d'un secret_id"
  )
  local item method url body what
  for item in "${denied[@]}"; do
    IFS='|' read -r method url body what <<<"$item"
    if [[ -n "$body" ]]; then status=$(http_status "$method" "$url" "$token_file" "$body"); else status=$(http_status "$method" "$url" "$token_file"); fi
    [[ "$status" == "403" ]] && ok "$what : 403 refusé" || ko "$what : $status (attendu 403)"
  done
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab")
  [[ "$status" == "403" ]] && ok "lecture sans jeton : 403" || ko "lecture sans jeton : $status"
  rm -f "$token_file"

  title "V5 ($label) : liste blanche du client : tout autre appel est refusé AVANT envoi"
  local before after
  ((audit_on)) && before=$(audit_count)
  out=$("$NC_PY" - <<'EOF'
from netcheck import vault
import os
config = vault.from_environment(dict(os.environ))
client = vault.build_client(config)
client.token = "x"
refused = 0
for call in (lambda: client.write("secret/data/netcheck/lab", a="b"),
             lambda: client.delete("secret/data/netcheck/lab"),
             lambda: client.read("secret/data/autre"),
             lambda: client.sys.read_health_status(method="GET"),
             lambda: client.auth.token.lookup_self()):
    try:
        call()
    except vault.VaultCallRefused:
        refused += 1
print(refused)
EOF
)
  if ((audit_on)); then
    after=$(audit_count)
    [[ "$out" == "5" && "$before" == "$after" ]] \
      && ok "5 appels interdits refusés par le client, et le serveur n'a rien reçu (journal d'audit inchangé)" \
      || ko "liste blanche : $out refus, journal $before -> $after"
  else
    [[ "$out" == "5" ]] && ok "5 appels interdits refusés par le client (côté serveur : journal d'audit indisponible)" \
      || ko "liste blanche : $out refus sur 5"
  fi

  title "V6 ($label) : ordre de priorité sur le lab réel"
  out=$(LAB_PASS="wrong-lab-pass-0000" $NC snapshot "vault_v6a_$engine" --force -i "$WRONG_INV" 2>&1); code=$?
  [[ "$code" == "0" ]] && grep -q "mot de passe : Vault" <<<"$out" \
    && ok "LAB_PASS (faux) ne masque pas Vault : snapshot OK, source Vault" || { ko "LAB_PASS a masqué Vault (code $code)"; echo "$out"; }
  ((audit_on)) && before=$(audit_count)
  out=$(NETCHECK_USER=netops NETCHECK_PASS="wrong-variable-0000" $NC snapshot "vault_v6b_$engine" --force -i "$WRONG_INV" 2>&1); code=$?
  ((audit_on)) && after=$(audit_count)
  [[ "$code" == "1" ]] && grep -q "mot de passe : variable NETCHECK_PASS" <<<"$out" \
    && grep -q "utilisateur : variable NETCHECK_USER" <<<"$out" \
    && ok "NETCHECK_USER et NETCHECK_PASS passent avant Vault (sessions refusées par les routeurs, code 1)" \
    || { ko "NETCHECK_USER/PASS devaient passer avant Vault (code $code)"; echo "$out" | head -5; }
  if ((audit_on)); then
    [[ "$before" == "$after" ]] && ok "Vault n'est même pas contacté (journal d'audit inchangé)" \
      || ko "Vault a été contacté malgré les variables (journal $before -> $after)"
  fi

  title "V7 ($label) : aucune panne de Vault ne retombe sur LAB_PASS ni sur l'inventaire"
  local secret_id_file="lab-access/.keys/$container.secret_id" saved="$JSON_DIR/$engine.secret_id.saved"
  cp -p "$secret_id_file" "$saved"
  ( umask 077; printf 'autre-secret-id-000000\n' > "$secret_id_file" )
  out=$(LAB_PASS=netops $NC snapshot "vault_v7a_$engine" --force 2>&1); code=$?
  [[ "$code" == "3" && "$(grep -c . <<<"$out")" == "1" ]] && grep -q "authentification AppRole" <<<"$out" \
    && ok "secret_id invalide : code 3, une ligne, malgré un LAB_PASS et un inventaire valides" \
    || { ko "secret_id invalide : code $code"; echo "$out"; }
  [[ ! -d "snapshots/vault_v7a_$engine" ]] && ok "aucune connexion aux routeurs, aucun snapshot écrit" \
    || ko "un snapshot a été écrit malgré le refus de Vault"
  cp -p "$saved" "$secret_id_file"; rm -f "$saved"
  chmod 644 "$secret_id_file"
  out=$(LAB_PASS=netops $NC snapshot "vault_v7b_$engine" --force 2>&1); code=$?
  [[ "$code" == "3" ]] && grep -q "droits 644" <<<"$out" && ok "secret_id en 0644 : refusé (code 3), mêmes règles que C2" \
    || { ko "secret_id 0644 : code $code"; echo "$out"; }
  chmod 600 "$secret_id_file"
  docker rm -f "$container" >/dev/null 2>&1
  out=$(LAB_PASS=netops $NC snapshot "vault_v7c_$engine" --force 2>&1); code=$?
  [[ "$code" == "3" && "$(grep -c . <<<"$out")" == "1" ]] && grep -q "Vault injoignable" <<<"$out" \
    && ok "Vault arrêté : « Vault injoignable », code 3, pas de repli sur LAB_PASS ni sur l'inventaire" \
    || { ko "Vault arrêté : code $code"; echo "$out"; }
  "${lab[@]}" down >/dev/null
  [[ ! -e "lab-access/.keys/$container.secret_id" ]] && ok "fichiers de clés supprimés" || ko "fichiers de clés restants"
}

vault_scenarios vault
vault_scenarios openbao

echo
echo "=== Bilan : $PASS contrôles réussis, $FAIL échec(s) ==="
[[ "$FAIL" == "0" ]]
