#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/fail() ne font qu'un echo et une affectation, le motif « cond && ok || fail » est sûr.
# NetBox de LAB (phase C6.2) : démarrage en DEUX temps avec attente de santé EXPLICITE, volumes conservés.
#
#   bash lab-access/netbox/netbox_lab.sh up                          démarre (netbox puis worker), attend, prouve l'écoute
#   bash lab-access/netbox/netbox_lab.sh status                      état, santé, page de connexion, adresse d'écoute
#   bash lab-access/netbox/netbox_lab.sh stop                        arrête SANS supprimer les volumes
#   bash lab-access/netbox/netbox_lab.sh destroy --yes-destroy-volumes   supprime conteneurs ET volumes (explicite)
#
# Pourquoi deux temps : `docker compose up -d` attend la santé de netbox avant de lancer le worker et ABANDONNE au bout
# de quelques minutes ; or le PREMIER démarrage applique ~340 migrations (mesuré : ~12 min). Ici on attend nous-mêmes,
# jusqu'à NETBOX_START_TIMEOUT secondes (défaut 1200 = 20 min), avec un message toutes les 30 s et, en cas d'échec,
# la fin des journaux. Les volumes sont CONSERVÉS entre deux essais : les démarrages suivants prennent ~1 min.
#
# Prérequis : un clone de netbox-docker au tag 5.1.1 (commit 7689fec7…) HORS du dépôt, par défaut ~/netbox-docker
# (variable NETBOX_DOCKER_DIR) ; les trois images sont tirées par digest (lab-access/netbox/docker-compose.override.yml).
# Le fichier .env (secrets générés, 0600) est créé dans ce clone s'il manque ; il n'est jamais écrasé ni affiché.
# Code retour : 0 si tout est en place, 1 sinon (message clair), 2 pour une erreur d'usage.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ND="${NETBOX_DOCKER_DIR:-$HOME/netbox-docker}"
PINNED_COMMIT=7689fec7a70717f7e72feecb383e7a3f55538b5f
TIMEOUT="${NETBOX_START_TIMEOUT:-1200}"          # netbox : 20 minutes au plus
WORKER_TIMEOUT="${NETBOX_WORKER_TIMEOUT:-180}"   # worker : 3 minutes au plus
PROGRESS_EVERY=30
PORT=8000
PROJECT=netbox-docker
ok()   { echo "  ✅ $*"; }
fail() { echo "  ❌ $*" >&2; }

compose() {
  docker compose --project-directory "$ND" --project-name "$PROJECT" \
    -f "$ND/docker-compose.yml" -f "$REPO/lab-access/netbox/docker-compose.override.yml" --env-file "$ND/.env" "$@"
}

check_clone() {
  [[ -d "$ND/.git" ]] || { fail "pas de clone de netbox-docker dans $ND : git clone --branch 5.1.1 https://github.com/netbox-community/netbox-docker $ND"; return 1; }
  local head; head="$(git -C "$ND" rev-parse HEAD 2>/dev/null)"
  [[ "$head" == "$PINNED_COMMIT" ]] \
    || { fail "le clone $ND est au commit ${head:0:12}, pas au commit épinglé ${PINNED_COMMIT:0:12} (tag 5.1.1)"; return 1; }
}

ensure_env() {
  if [[ -e "$ND/.env" ]]; then
    [[ "$(stat -c %a "$ND/.env")" == "600" ]] || { fail "$ND/.env doit être en 0600 (droits actuels : $(stat -c %a "$ND/.env"))"; return 1; }
    return 0
  fi
  ( umask 077; python3 - "$ND/.env" <<'PY'
import secrets, string, sys
alphabet = string.ascii_letters + string.digits
def token(n):
    return "".join(secrets.choice(alphabet) for _ in range(n))
values = {
    "NB_SECRET_KEY": token(64), "NB_TOKEN_PEPPER": token(64), "NB_DB_PASSWORD": token(32),
    "NB_REDIS_PASSWORD": token(32), "NB_REDIS_CACHE_PASSWORD": token(32),
    "NB_SUPERUSER_NAME": "lab-admin", "NB_SUPERUSER_EMAIL": "lab-admin@lab.invalid", "NB_SUPERUSER_PASSWORD": token(32),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.writelines(f"{key}={value}\n" for key, value in values.items())
PY
  ) || { fail "génération de $ND/.env impossible"; return 1; }
  chmod 600 "$ND/.env"
  ok ".env créé (0600, valeurs aléatoires, non affichées) : $ND/.env"
}

health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$PROJECT-$1-1" 2>/dev/null || echo absent; }
running() { [[ "$(docker inspect -f '{{.State.Running}}' "$PROJECT-$1-1" 2>/dev/null)" == "true" ]]; }

# wait_healthy <service> <limite en secondes> : attend la santé, un message toutes les 30 s, échec explicite.
wait_healthy() {
  local service="$1" limit="$2" start now elapsed state migrations next=0
  start=$(date +%s)
  while :; do
    now=$(date +%s); elapsed=$((now - start)); state="$(health "$service")"
    [[ "$state" == "healthy" ]] && { ok "$service sain après ${elapsed} s"; return 0; }
    if ! running "$service"; then
      fail "$service s'est arrêté (état « $state ») après ${elapsed} s ; fin de ses journaux :"
      docker logs --tail 20 "$PROJECT-$service-1" 2>&1 | sed 's/^/      /' >&2
      return 1
    fi
    if (( elapsed >= limit )); then
      fail "$service n'est pas sain après ${limit} s (limite NETBOX_START_TIMEOUT / NETBOX_WORKER_TIMEOUT ; état « $state ») ; fin de ses journaux :"
      docker logs --tail 20 "$PROJECT-$service-1" 2>&1 | sed 's/^/      /' >&2
      return 1
    fi
    if (( elapsed >= next )); then
      migrations=$(docker logs "$PROJECT-$service-1" 2>&1 | grep -c "Applying" || true)
      echo "  … $service : ${elapsed} s sur ${limit} s, état « $state », migrations appliquées : ${migrations}"
      next=$((elapsed + PROGRESS_EVERY))
    fi
    sleep 5
  done
}

listening_on_loopback_only() {
  local lines; lines="$(ss -ltn 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $4}')"
  [[ -n "$lines" ]] && ! grep -qv '^127\.0\.0\.1:' <<<"$lines"
}

login_code() { curl -s -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/login/" 2>/dev/null || true; }

cmd_up() {
  check_clone || return 1
  ensure_env || return 1
  echo "NetBox de lab : temps 1 sur 2 (postgres, redis, redis-cache, netbox) ; limite ${TIMEOUT} s"
  compose up -d --no-deps postgres redis redis-cache netbox >/dev/null 2>&1 \
    || { fail "docker compose up (temps 1) a échoué : docker compose ... config pour voir la configuration"; return 1; }
  wait_healthy netbox "$TIMEOUT" || return 1
  echo "NetBox de lab : temps 2 sur 2 (worker) ; limite ${WORKER_TIMEOUT} s"
  compose up -d --no-deps netbox-worker >/dev/null 2>&1 || { fail "docker compose up (temps 2) a échoué"; return 1; }
  wait_healthy netbox-worker "$WORKER_TIMEOUT" || return 1
  local code; code="$(login_code)"
  [[ "$code" == "200" ]] && ok "page de connexion : HTTP 200 sur http://127.0.0.1:$PORT" \
    || { fail "page de connexion : HTTP ${code:-000} (attendu 200)"; return 1; }
  listening_on_loopback_only && ok "écoute : 127.0.0.1:$PORT seulement" \
    || { fail "NetBox écoute ailleurs que sur 127.0.0.1:$PORT : $(ss -ltn | awk -v p=":$PORT" '$4 ~ p"$" {print $4}' | tr '\n' ' ')"; return 1; }
}

cmd_status() {
  local status=0 service
  for service in postgres redis redis-cache netbox netbox-worker; do
    echo "  $service : $(health "$service")"
  done
  echo "  page de connexion : HTTP $(login_code)"
  echo "  écoute : $(ss -ltn 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $4}' | tr '\n' ' ')"
  for service in netbox netbox-worker; do [[ "$(health "$service")" == "healthy" ]] || status=1; done
  return $status
}

case "${1:-}" in
  up)      cmd_up ;;
  status)  cmd_status ;;
  stop)    check_clone && ensure_env && compose stop >/dev/null 2>&1 && ok "NetBox arrêté, volumes conservés" ;;
  destroy)
    [[ "${2:-}" == "--yes-destroy-volumes" ]] || { echo "destroy supprime les VOLUMES (base NetBox) : ajoutez --yes-destroy-volumes" >&2; exit 2; }
    check_clone && ensure_env && compose down -v >/dev/null 2>&1 && ok "conteneurs ET volumes supprimés" ;;
  *) echo "usage : $0 up | status | stop | destroy --yes-destroy-volumes" >&2; exit 2 ;;
esac
