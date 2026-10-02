#!/usr/bin/env bash
# Enveloppe de planification de `netcheck monitor` (cron ou timer systemd) -- Phase E.
#
# Elle ne fait qu'une chose en plus du lancement : fournir NETCHECK_WEBHOOK_URL à monitor, depuis
# ~/.config/netcheck/env (ou $NETCHECK_ENV_FILE), SANS jamais exécuter ce fichier :
#   - le fichier est LU COMME DU TEXTE ; seule la ligne NETCHECK_WEBHOOK_URL=... est retenue,
#     toute autre ligne est ignorée (pas de `source` : ce serait exécuter du code toutes les
#     5 minutes) ;
#   - il doit appartenir à l'utilisateur courant, être un fichier régulier (pas un lien) et n'être
#     lisible que par lui (0600, ou 0400) : sinon refus avec un message clair (code 3) ;
#   - une NETCHECK_WEBHOOK_URL déjà présente dans l'environnement l'emporte sur le fichier.
# L'URL n'est jamais affichée (c'est un secret : quiconque la connaît peut poster dans le salon).
#
# Usage : automation/monitor.sh --baseline nominal [--intent ...] [--rules ...] [--confirm 2] ...
# NETCHECK_PYTHON (optionnel) force l'interpréteur ; sinon netcheck/.venv, puis .venv, puis python3.
set -euo pipefail

ENV_FILE="${NETCHECK_ENV_FILE:-$HOME/.config/netcheck/env}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="NETCHECK_WEBHOOK_URL"

die() {
    echo "monitor.sh : $*" >&2
    exit 3
}

# Affiche la valeur de la première ligne KEY=... du fichier, ou rien. N'exécute rien.
read_webhook_url() {
    local file=$1 line value owner mode
    if [ -L "$file" ]; then
        die "$file est un lien symbolique : refusé (remplace-le par un vrai fichier, droits 600)"
    fi
    [ -e "$file" ] || return 0   # absent : alertes désactivées, monitor le signale lui-même
    [ -f "$file" ] || die "$file n'est pas un fichier régulier"
    owner=$(stat -c '%u' -- "$file")
    mode=$(stat -c '%a' -- "$file")
    [ "$owner" = "$(id -u)" ] || die "$file n'appartient pas à l'utilisateur courant : refusé"
    case "$mode" in
        600 | 400) ;;
        *) die "$file a les droits $mode, attendu 600 (lisible par toi seul) : chmod 600 '$file'" ;;
    esac
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in
            "$KEY="*)
                value=${line#"$KEY="}
                case $value in
                    \'*\') value=${value#\'}; value=${value%\'} ;;
                    \"*\") value=${value#\"}; value=${value%\"} ;;
                esac
                printf '%s' "$value"
                return 0
                ;;
        esac
    done <"$file"
}

if [ -z "${NETCHECK_WEBHOOK_URL:-}" ]; then
    url=$(read_webhook_url "$ENV_FILE")
    if [ -n "$url" ]; then
        export NETCHECK_WEBHOOK_URL="$url"
    fi
fi

PYTHON="${NETCHECK_PYTHON:-}"
if [ -z "$PYTHON" ]; then
    for candidate in "$REPO_ROOT/netcheck/.venv/bin/python" "$REPO_ROOT/.venv/bin/python"; do
        if [ -x "$candidate" ]; then
            PYTHON=$candidate
            break
        fi
    done
fi
PYTHON="${PYTHON:-python3}"

cd "$REPO_ROOT"
exec "$PYTHON" -m netcheck monitor "$@"
