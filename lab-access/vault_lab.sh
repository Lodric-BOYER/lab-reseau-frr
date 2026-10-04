#!/usr/bin/env bash
# Vault (ou OpenBao) de LAB pour netcheck, phase C3. Conteneur de développement : en mémoire, scellé jamais, lié à
# 127.0.0.1 seulement, perdu à l'arrêt. JAMAIS pour autre chose que ce lab.
#
#   lab-access/vault_lab.sh up         démarre le conteneur (ENGINE=vault|openbao, défaut vault)
#   lab-access/vault_lab.sh provision  AppRole + politique en lecture seule + secret des identifiants du lab
#   lab-access/vault_lab.sh env        affiche les export NETCHECK_VAULT_* (aucun secret : des chemins)
#   lab-access/vault_lab.sh status     état du conteneur
#   lab-access/vault_lab.sh down       arrête le conteneur et supprime ses fichiers de clés
#
# Les secrets (jeton racine du mode développement, secret_id) sont écrits dans lab-access/.keys/ (dossier 0700,
# fichiers 0600, ignoré par Git), jamais dans le dépôt, jamais sur une ligne de commande, jamais affichés.
set -euo pipefail

ENGINE="${ENGINE:-vault}"
case "$ENGINE" in
  vault)
    IMAGE="${VAULT_IMAGE:-hashicorp/vault:2.1.1}"; CLI=vault; CONTAINER=netcheck-vault; PORT=18200; PFX=VAULT ;;
  openbao)
    IMAGE="${OPENBAO_IMAGE:-openbao/openbao:2.7.1}"; CLI=bao; CONTAINER=netcheck-openbao; PORT=18201; PFX=BAO ;;
  *) echo "ENGINE inconnu : $ENGINE (vault ou openbao)" >&2; exit 3 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS="$HERE/.keys"
ROOT_ENV="$KEYS/$CONTAINER.env"          # VAULT_DEV_ROOT_TOKEN_ID=... (0600) : ne passe pas par `ps`
CLIENT_ENV="$KEYS/$CONTAINER.client.env" # VAULT_TOKEN=... (0600), pour le client dans le conteneur : Vault range
                                         # lui-même le jeton dans ~/.vault-token en mode dev, OpenBao non
ROLE_ID_FILE="$KEYS/$CONTAINER.role_id"
SECRET_ID_FILE="$KEYS/$CONTAINER.secret_id"
POLICY="$HERE/vault/netcheck-ro.hcl"

# Valeurs par défaut des images de lab (publiques : README, automation/inventory.yml). Le secret du lab FRR.
LAB_USERNAME="${LAB_VAULT_USERNAME:-netops}"
LAB_PASSWORD="${LAB_VAULT_PASSWORD:-netops}"

make_client_env() {
  ( umask 077; sed -n "s/^${PFX}_DEV_ROOT_TOKEN_ID=/${PFX}_TOKEN=/p" "$ROOT_ENV" > "$CLIENT_ENV" )
}

in_container() {   # exécute le client du moteur dans le conteneur, jeton racine par fichier d'environnement
  docker exec -i --env-file "$CLIENT_ENV" -e "${PFX}_ADDR=http://127.0.0.1:8200" "$CONTAINER" "$CLI" "$@"
}

cmd_up() {
  command -v docker >/dev/null || { echo "docker introuvable" >&2; exit 3; }
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then echo "$CONTAINER tourne déjà"; return; fi
  mkdir -p "$KEYS"; chmod 700 "$KEYS"
  if [ ! -s "$ROOT_ENV" ]; then
    ( umask 077
      printf '%s_DEV_ROOT_TOKEN_ID=%s\n%s_DEV_LISTEN_ADDRESS=0.0.0.0:8200\n' \
        "$PFX" "$(head -c 24 /dev/urandom | base64 | tr -d '+/=')" "$PFX" > "$ROOT_ENV" )
  fi
  make_client_env
  docker run -d --rm --name "$CONTAINER" --cap-add=IPC_LOCK -p "127.0.0.1:$PORT:8200" \
    --env-file "$ROOT_ENV" "$IMAGE" >/dev/null
  for _ in $(seq 1 40); do
    if in_container status >/dev/null 2>&1; then echo "$CONTAINER prêt sur http://127.0.0.1:$PORT ($IMAGE)"; return; fi
    sleep 0.5
  done
  echo "$CONTAINER ne répond pas" >&2; docker logs "$CONTAINER" 2>&1 | tail -5 >&2; exit 1
}

cmd_provision() {
  [ -s "$POLICY" ] || { echo "politique absente : $POLICY" >&2; exit 3; }
  [ -s "$CLIENT_ENV" ] || make_client_env
  in_container auth enable approle >/dev/null
  in_container policy write netcheck-ro - < "$POLICY" >/dev/null
  # Jeton court (5 minutes), un seul usage de session par appel ; secret_id réutilisable pour le lab.
  in_container write auth/approle/role/netcheck-ro token_policies=netcheck-ro token_ttl=5m token_max_ttl=5m \
    secret_id_ttl=24h secret_id_num_uses=0 >/dev/null
  printf '{"username":"%s","password":"%s"}' "$LAB_USERNAME" "$LAB_PASSWORD" \
    | in_container kv put -mount=secret netcheck/lab - >/dev/null
  # Journal d'audit : preuve des appels reçus (chemins et opérations ; les valeurs y sont hachées).
  # (OpenBao 2.7 refuse l'activation par l'API : audit déclaratif seulement ; sans effet sur le reste.)
  in_container audit enable file file_path=/tmp/audit.log >/dev/null 2>&1 \
    || echo "journal d'audit non activable par l'API sur $ENGINE : les preuves par journal sont réservées à Vault"
  ( umask 077
    in_container read -field=role_id auth/approle/role/netcheck-ro/role-id > "$ROLE_ID_FILE"
    in_container write -f -field=secret_id auth/approle/role/netcheck-ro/secret-id > "$SECRET_ID_FILE" )
  chmod 600 "$ROLE_ID_FILE" "$SECRET_ID_FILE"
  echo "provisionné : rôle netcheck-ro (politique en lecture seule sur secret/data/netcheck/lab)"
}

cmd_env() {
  printf 'export NETCHECK_VAULT_ADDR=http://127.0.0.1:%s\n' "$PORT"
  printf 'export NETCHECK_VAULT_ROLE_ID=%s\n' "$(cat "$ROLE_ID_FILE")"
  printf 'export NETCHECK_VAULT_SECRET_ID_FILE=%s\n' "$SECRET_ID_FILE"
  printf 'export NETCHECK_VAULT_PATH=netcheck/lab\n'
}

cmd_status() { docker ps --filter "name=^$CONTAINER\$" --format '{{.Names}} {{.Image}} {{.Status}}'; }

cmd_down() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -f "$ROOT_ENV" "$CLIENT_ENV" "$ROLE_ID_FILE" "$SECRET_ID_FILE"
  echo "$CONTAINER arrêté, fichiers de clés supprimés"
}

case "${1:-}" in
  up) cmd_up ;; provision) cmd_provision ;; env) cmd_env ;; status) cmd_status ;; down) cmd_down ;;
  *) sed -n '2,13p' "$0" >&2; exit 3 ;;
esac
