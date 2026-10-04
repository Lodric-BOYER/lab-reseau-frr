#!/usr/bin/env bash
# shellcheck disable=SC2016
# Justification : dans les bash -c '...' ci-dessous, $0 et $1 sont ceux du bash interne (hôte et port passés en
# arguments), volontairement non développés par le shell appelant.
# Barrière « lab prêt » et diagnostic en cas d'échec, partagés par test_lab*.sh et tests/integration*.sh (`source`).
#
#   lab_ready <étiquette> <délai-max-s> <nom=hôte[:port]>...   0 si chaque nœud répond (port joignable ET bannière
#                                                               SSH reçue), sinon 1 et « lab non prêt : rX ... »
#   lab_ready_lab <réseau> <étiquette> [délai-max-s]            idem pour r1..r5 (<réseau>.11 à .15) et le bastion
#                                                               (<réseau>.2) ; en cas d'échec : diagnostic + exit 20
#   lab_diagnostics <préfixe-conteneurs> <étiquette>            écrit reports/diagnostics/<étiquette>-<date>.txt
#
# « lab non prêt » (code 20) n'est PAS un échec de netcheck : c'est l'environnement qui n'est pas là. Les deux
# sont donc annoncés et comptés à part (un contrôle ❌ « lab non prêt », puis arrêt avec le code 20).
# Le diagnostic ne contient aucun secret : champs d'inspection choisis un à un (jamais l'environnement des
# conteneurs), clés d'hôte listées par `ls -l` (droits et taille, jamais le contenu), journaux filtrés.

LAB_NOT_READY_CODE=20

# Bannière SSH d'un hôte (vide si le port est fermé ou si rien n'est annoncé en 3 s).
_ssh_banner() {
  timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1" && read -r -t 3 -u 3 line && printf "%s" "$line"' "$1" "$2" 2>/dev/null
}

_port_open() { timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null; }

lab_ready() {
  local label="$1" limit="$2"; shift 2
  local deadline=$((SECONDS + limit)) spec name hostport host port pending banner
  local -a todo=("$@")
  while :; do
    pending=()
    for spec in "${todo[@]}"; do
      hostport="${spec#*=}"; host="${hostport%%:*}"; port=22
      [[ "$hostport" == *:* ]] && port="${hostport##*:}"
      banner=$(_ssh_banner "$host" "$port")
      [[ "$banner" == SSH-2.0-* ]] || pending+=("$spec")
    done
    todo=("${pending[@]}")
    (( ${#todo[@]} == 0 )) && return 0
    (( SECONDS >= deadline )) && break
    sleep 3
  done
  for spec in "${todo[@]}"; do
    name="${spec%%=*}"; hostport="${spec#*=}"; host="${hostport%%:*}"; port=22
    [[ "$hostport" == *:* ]] && port="${hostport##*:}"
    if _port_open "$host" "$port"; then
      echo "lab non prêt : $name ($host:$port) : port ouvert mais aucune bannière SSH reçue (${limit} s)"
    else
      echo "lab non prêt : $name ($host:$port) : port fermé ou injoignable (${limit} s)"
    fi
  done
  return 1
}

# Sections de diagnostic d'un conteneur ; chaque commande est tolérante (un conteneur arrêté n'en répond aucune).
_diag_container() {
  local c="$1"
  echo "--- $c"
  docker inspect -f 'état={{.State.Status}} code_sortie={{.State.ExitCode}} OOM={{.State.OOMKilled}} santé={{if .State.Health}}{{.State.Health.Status}}{{else}}aucune{{end}} redémarrages={{.RestartCount}} démarré={{.State.StartedAt}}' "$c" 2>&1
  echo "# journal du conteneur (60 dernières lignes)"
  docker logs --tail 60 "$c" 2>&1
  echo "# processus, ports à l'écoute, clés d'hôte (droits et taille seulement), charge"
  docker exec "$c" sh -c 'ps 2>&1 | head -40; echo; ss -ltn 2>&1; echo; ls -l /etc/ssh/ssh_host_* /persist/secure/ssh/* 2>&1; echo; cat /proc/loadavg' 2>&1
}

lab_diagnostics() {
  local prefix="$1" label="$2" dir out c ts
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reports/diagnostics"
  ts=$(date +%Y%m%d-%H%M%S)
  ( umask 077; mkdir -p "$dir" )
  out="$dir/${label}-${ts}.txt"
  (
    umask 077
    {
      echo "# Diagnostic de lab : $label ($ts), préfixe $prefix"
      echo "# hôte"; date; uptime; free -m; df -h / 2>&1 | head -3
      echo "# docker stats (instantané)"; docker stats --no-stream 2>&1 | head -20
      echo "# noyau : OOM éventuel"; { dmesg 2>/dev/null | grep -i -E 'out of memory|oom-kill|killed process' | tail -5; } || true
      echo "# conteneurs du lab (y compris arrêtés)"
      docker ps -a --format '{{.Names}}\t{{.Status}}' 2>&1 | grep -E "^${prefix}-" || true
      for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E "^${prefix}-(r[0-9]+|bastion)$"); do
        _diag_container "$c"
      done
    } 2>&1 | sed -E 's/((pass(word)?|passwd|secret|token)[=:] *)[^ ]+/\1***/Ig' > "$out"
  )
  echo "  diagnostic écrit dans $out"
}

lab_ready_lab() {
  local net="$1" label="$2" limit="${3:-240}" i out port="${LAB_READY_PORT:-22}"   # LAB_READY_PORT : tests seulement
  local -a nodes=()
  for i in 1 2 3 4 5; do nodes+=("r$i=$net.1$i:$port"); done
  nodes+=("bastion=$net.2:$port")
  if declare -F title >/dev/null; then title "Lab prêt : port 22 et bannière SSH sur chaque nœud, avant tout contrôle"; fi
  echo "  … barrière « lab prêt » : port 22 et bannière SSH sur r1 à r5 et le bastion (jusqu'à ${limit} s)"
  if out=$(lab_ready "$label" "$limit" "${nodes[@]}"); then
    ok "lab prêt : port 22 joignable et bannière SSH reçue sur r1 à r5 et le bastion"
    return 0
  fi
  echo "$out" | while IFS= read -r line; do ko "$line"; done
  lab_diagnostics "${LAB:-clab-frr-lab}" "${label}-lab-non-pret"
  echo
  echo "=== Lab non prêt : arrêt avant tout contrôle (code $LAB_NOT_READY_CODE, ce n'est pas un échec de netcheck) ==="
  exit "$LAB_NOT_READY_CODE"
}

# À appeler au bilan d'un script si FAIL > 0 : le lab est encore là, on capture avant toute destruction.
lab_diag_if_failed() {
  local label="$1"
  (( FAIL > 0 )) && lab_diagnostics "$LAB" "${label}-echec"
  return 0
}
