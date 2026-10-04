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
info() { echo "  ℹ️  $1"; }

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

# approle_login BASE FICHIER-ROLE_ID FICHIER-SECRET_ID [FICHIER-JETON] : code HTTP ; le jeton (si 200) va dans le
# fichier 0600, jamais à l'écran.
approle_login() {
  ( umask 077; "$NC_PY" - "$@" <<'EOF'
import json, sys, urllib.error, urllib.request
base, role_file, sid_file = sys.argv[1:4]
out = sys.argv[4] if len(sys.argv) > 4 else None
body = json.dumps({"role_id": open(role_file).read().strip(), "secret_id": open(sid_file).read().strip()}).encode()
try:
    reply = json.load(urllib.request.urlopen(urllib.request.Request(base + "/v1/auth/approle/login", data=body), timeout=5))
    if out:
        open(out, "w").write(reply["auth"]["client_token"])
    print(200)
except urllib.error.HTTPError as error:
    print(error.code)
EOF
  )
}

vault_scenarios() {
  local engine="$1" container port
  case "$engine" in vault) container=netcheck-vault; port=18200 ;; openbao) container=netcheck-openbao; port=18201 ;; esac
  local base="http://127.0.0.1:$port"
  local label="$engine"
  local lab=(env "ENGINE=$engine" bash lab-access/vault_lab.sh)
  local role_file="lab-access/.keys/$container.role_id" sid_file="lab-access/.keys/$container.secret_id"
  fresh() { "${lab[@]}" secret-id; }   # le rôle n'accepte QU'UN usage de secret_id : un nouveau avant chaque exécution
  # probe_role NOM PARAMETRES... : rôle de sonde (même politique), role_id et secret_id dans $JSON_DIR/NOM.{role,sid}
  probe_role() {
    local name="$1"; shift
    "${lab[@]}" admin write "auth/approle/role/$name" token_policies=netcheck-ro "$@" >/dev/null
    ( umask 077
      "${lab[@]}" admin read -field=role_id "auth/approle/role/$name/role-id" > "$JSON_DIR/$name.role"
      "${lab[@]}" admin write -f -field=secret_id "auth/approle/role/$name/secret-id" > "$JSON_DIR/$name.sid" )
  }

  title "V1 ($label) : le conteneur de développement et le provisionnement"
  "${lab[@]}" up >"$JSON_DIR/$engine.up" 2>&1 && ok "conteneur démarré en réseau hôte, écoute 127.0.0.1 ($(docker ps --filter "name=^$container\$" --format '{{.Image}}'))" \
    || { ko "démarrage impossible"; cat "$JSON_DIR/$engine.up"; return; }
  "${lab[@]}" provision >"$JSON_DIR/$engine.prov" 2>&1 && ok "AppRole durci + politique en lecture seule + secret du lab" \
    || { ko "provisionnement impossible"; cat "$JSON_DIR/$engine.prov"; return; }
  eval "$("${lab[@]}" env)"
  # Le rôle tel que le serveur l'a enregistré : chaque réglage de durcissement.
  local roleconf
  roleconf=$("${lab[@]}" admin read -format=json auth/approle/role/netcheck-ro | "$NC_PY" -c '
import ipaddress, json, sys
d = json.load(sys.stdin)["data"]
# Le serveur normalise : « ::1/128 » est rendu « ::1 » pour le jeton ; ip_network les égalise.
norm = lambda cidrs: sorted(str(ipaddress.ip_network(c)) for c in cidrs)
cidr = norm(["127.0.0.0/8", "::1/128"])
checks = {
    "token_num_uses": d["token_num_uses"] == 1,
    "token_ttl": d["token_ttl"] == 60,
    "token_max_ttl": d["token_max_ttl"] == 120,
    "secret_id_num_uses": d["secret_id_num_uses"] == 1,
    "secret_id_ttl": d["secret_id_ttl"] == 900,
    "token_bound_cidrs": norm(d["token_bound_cidrs"]) == cidr,
    "secret_id_bound_cidrs": norm(d["secret_id_bound_cidrs"]) == cidr,
    "bind_secret_id": d["bind_secret_id"] is True,
    "token_policies": d["token_policies"] == ["netcheck-ro"],
}
print(" ".join(k for k, v in checks.items() if not v) or "OK")')
  [[ "$roleconf" == "OK" ]] \
    && ok "rôle enregistré : jeton à 1 usage, 60 s (max 120 s) ; secret_id à 1 usage, 15 min ; CIDR = bouclage (jeton et secret_id)" \
    || ko "réglages du rôle différents de l'attendu : $roleconf"
  [[ "$(stat -c %a "$sid_file" "$role_file" | sort -u | tr '\n' ' ')" == "600 " ]] \
    && ok "role_id et secret_id : fichiers 0600" || ko "droits des fichiers de clés"
  # Mesure de RAM (C24), conteneur provisionné au repos.
  local ram_idle
  ram_idle=$(docker stats --no-stream --format '{{.MemUsage}}' "$container" | awk '{print $1}')
  info "RAM de $container au repos, provisionné : $ram_idle (image $(docker image ls --format '{{.Size}}' "$(docker ps --filter "name=^$container\$" --format '{{.Image}}')" | head -1))"
  echo "$engine ram_idle=$ram_idle" >> "$JSON_DIR/ram.txt"
  # Journal d'audit du serveur : disponible sur Vault ; OpenBao 2.7 ne l'active pas par l'API.
  local audit_on=0 audit_offset=0
  docker exec "$container" test -f /tmp/audit.log && audit_on=1
  audit_count() { docker exec "$container" cat /tmp/audit.log | wc -l; }

  title "V2 ($label) : netcheck lit les identifiants dans Vault (inventaire à mot de passe FAUX, lab FRR réel)"
  local out code
  fresh
  ((audit_on)) && audit_offset=$(audit_count)
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
        print(entry["request"]["operation"], entry["request"]["path"], entry["request"].get("remote_address"))')
    [[ "$calls" == $'update auth/approle/login 127.0.0.1\nread secret/data/netcheck/lab 127.0.0.1' ]] \
      && ok "journal d'audit : « update auth/approle/login » puis « read secret/data/netcheck/lab », depuis 127.0.0.1, rien d'autre" \
      || { ko "appels inattendus"; echo "$calls"; }
  else
    skip "journal d'audit indisponible sur $engine : contrôle réservé à Vault"
  fi

  title "V4 ($label) : preuve négative par le serveur : la politique ne permet ni d'écrire ni de lire ailleurs (rôle de sonde à usages illimités : le refus vient de la POLITIQUE, pas d'un jeton épuisé)"
  probe_role probe-policy token_ttl=5m token_num_uses=0 "token_bound_cidrs=127.0.0.0/8,::1/128" \
    secret_id_ttl=10m secret_id_num_uses=0 "secret_id_bound_cidrs=127.0.0.0/8,::1/128"
  local token_file="$JSON_DIR/$engine.token"
  [[ "$(approle_login "$base" "$JSON_DIR/probe-policy.role" "$JSON_DIR/probe-policy.sid" "$token_file")" == "200" && -s "$token_file" ]] \
    || { ko "ouverture de session AppRole (sonde) impossible"; return; }
  local status
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "200" ]] && ok "lecture de secret/data/netcheck/lab : 200 (autorisée)" || ko "lecture autorisée : $status"
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "200" ]] && ok "le même jeton relit : 200 (la sonde n'a pas d'usage limité : les refus qui suivent sont ceux de la politique)" \
    || ko "relecture avec la sonde : $status"
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
  fresh
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

  title "V8 ($label) : durcissement du rôle : usages uniques et bouclage, prouvés par le serveur"
  # (a) le jeton du rôle réel ne sert qu'une fois.
  fresh
  [[ "$(approle_login "$base" "$role_file" "$sid_file" "$token_file")" == "200" ]] || ko "ouverture de session impossible"
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "200" ]] && ok "jeton du rôle : 1re lecture : 200" || ko "1re lecture : $status"
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "403" ]] && ok "jeton du rôle : 2e lecture : 403 (jeton à 1 usage, révoqué)" || ko "2e lecture : $status (attendu 403)"
  rm -f "$token_file"
  # (b) un secret_id ne sert qu'une fois.
  fresh
  [[ "$(approle_login "$base" "$role_file" "$sid_file")" == "200" ]] && ok "secret_id neuf : ouverture de session 200" || ko "secret_id neuf refusé"
  status=$(approle_login "$base" "$role_file" "$sid_file")
  [[ "$status" == "400" || "$status" == "403" ]] && ok "même secret_id réutilisé : $status refusé (secret_id à 1 usage)" \
    || ko "secret_id réutilisé : $status (attendu 400 ou 403)"
  # (c) netcheck : la 2e exécution avec le même secret_id est refusée, sans repli.
  fresh
  out=$($NC snapshot "vault_v8c1_$engine" --force -i "$WRONG_INV" -d r1 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "netcheck, 1re exécution avec un secret_id neuf : code 0" || { ko "1re exécution : code $code"; echo "$out"; }
  out=$(LAB_PASS=netops $NC snapshot "vault_v8c2_$engine" --force -i "$WRONG_INV" -d r1 2>&1); code=$?
  [[ "$code" == "3" && "$(grep -c . <<<"$out")" == "1" ]] && grep -q "authentification AppRole" <<<"$out" \
    && ok "netcheck, 2e exécution avec le même secret_id : code 3 (« consommé »), pas de repli sur LAB_PASS" \
    || { ko "2e exécution : code $code"; echo "$out"; }
  # (d) CIDR : ce que le serveur refuse quand l'adresse source n'est pas dans la liste (rôles de sonde).
  probe_role probe-cidr-secret secret_id_ttl=10m secret_id_num_uses=0 "secret_id_bound_cidrs=192.0.2.0/24"
  status=$(approle_login "$base" "$JSON_DIR/probe-cidr-secret.role" "$JSON_DIR/probe-cidr-secret.sid")
  [[ "$status" == "400" || "$status" == "403" ]] && ok "secret_id lié à 192.0.2.0/24, présenté depuis 127.0.0.1 : $status refusé" \
    || ko "secret_id_bound_cidrs sans effet : $status"
  probe_role probe-cidr-token token_ttl=5m token_num_uses=0 "token_bound_cidrs=192.0.2.0/24" \
    secret_id_ttl=10m secret_id_num_uses=0 "secret_id_bound_cidrs=127.0.0.0/8,::1/128"
  [[ "$(approle_login "$base" "$JSON_DIR/probe-cidr-token.role" "$JSON_DIR/probe-cidr-token.sid" "$token_file")" == "200" ]] \
    || ko "sonde token CIDR : ouverture de session impossible"
  status=$(http_status GET "$base/v1/secret/data/netcheck/lab" "$token_file")
  [[ "$status" == "403" ]] && ok "jeton lié à 192.0.2.0/24, utilisé depuis 127.0.0.1 : 403 refusé" || ko "token_bound_cidrs sans effet : $status"
  rm -f "$token_file"
  info "RAM de $container après ces scénarios : $(docker stats --no-stream --format '{{.MemUsage}}' "$container" | awk '{print $1}')"

  title "V7 ($label) : aucune panne de Vault ne retombe sur LAB_PASS ni sur l'inventaire"
  local secret_id_file="$sid_file" saved="$JSON_DIR/$engine.secret_id.saved"
  fresh
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
echo "RAM mesurée :"; sed 's/^/  /' "$JSON_DIR/ram.txt" 2>/dev/null
[[ "$FAIL" == "0" ]]
