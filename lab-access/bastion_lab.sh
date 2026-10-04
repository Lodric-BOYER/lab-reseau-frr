#!/usr/bin/env bash
# Provisionnement du bastion de lab (phase C4), APRÈS le déploiement du lab (le bastion est le nœud « bastion » des
# trois topologies, image netcheck-bastion:1 : docker build -t netcheck-bastion:1 docker/bastion/).
#
#   bash lab-access/bastion_lab.sh keys                    crée les paires de clés de lab (si absentes)
#   bash lab-access/bastion_lab.sh provision frr|multivendor|ceos
#   bash lab-access/bastion_lab.sh unprovision frr|multivendor|ceos
#
# provision :
#   - clé publique netcheck -> bastion dans /etc/ssh/authorized_keys/jump (fichier de ROOT : le compte ne peut pas
#     l'élargir), avec  restrict,port-forwarding,permitopen="<routeur>:22",...,command="/bin/false"  : seul le relais
#     de port local vers les adresses de gestion des 5 routeurs, port 22, aucune commande, aucun agent, aucun X11 ;
#   - PermitOpen identique dans la configuration sshd du bastion (deuxième barrière), puis rechargement (SIGHUP) ;
#   - lab FRR seulement : clé publique netcheck -> routeurs dans ~netops/.ssh/authorized_keys de chaque routeur
#     (fichier du conteneur, pas une configuration FRR) pour l'authentification par clé des routeurs. Les labs
#     SR Linux et cEOS demandent un compte dans la configuration de l'équipement : c'est la phase C5.
# Les clés privées restent dans lab-access/.keys/ (dossier 0700, fichiers 0600, ignoré par Git).
# Après un redéploiement : relancer provision, puis bash lab-access/pin_hostkeys.sh (clé d'hôte du bastion).
set -euo pipefail
cd "$(dirname "$0")/.."

KEYS=lab-access/.keys
BASTION_KEY="$KEYS/netcheck_bastion"
ROUTER_KEY="$KEYS/netcheck_router"

lab_params() {
  case "${1:-}" in
    frr)         PREFIX=clab-frr-lab;             SUBNET=172.20.20 ;;
    multivendor) PREFIX=clab-frr-lab-multivendor; SUBNET=172.20.21 ;;
    ceos)        PREFIX=clab-frr-lab-ceos;        SUBNET=172.20.22 ;;
    *) echo "usage : $0 keys | provision|unprovision frr|multivendor|ceos" >&2; exit 2 ;;
  esac
  BASTION="$PREFIX-bastion"
  ROUTERS=(11 12 13 14 15)
}

cmd_keys() {
  mkdir -p "$KEYS" && chmod 700 "$KEYS"
  for key in "$BASTION_KEY" "$ROUTER_KEY"; do
    if [ ! -s "$key" ]; then
      ssh-keygen -q -t ed25519 -N "" -C "netcheck-lab $(basename "$key")" -f "$key"
      echo "clé créée : $key (privée 0600, sans phrase secrète : clé de lab)"
    fi
    chmod 600 "$key"
  done
}

reload_sshd() { docker exec "$1" sh -c 'kill -HUP "$(cat /run/sshd.pid)"'; }

cmd_provision() {
  lab_params "$1"
  docker inspect "$BASTION" >/dev/null 2>&1 || { echo "conteneur $BASTION absent (lab déployé avec le nœud bastion ?)" >&2; exit 1; }
  cmd_keys
  local opens=() options="restrict,port-forwarding" n
  for n in "${ROUTERS[@]}"; do opens+=("$SUBNET.$n:22"); options+=",permitopen=\"$SUBNET.$n:22\""; done
  options+=',command="/bin/false"'
  printf '%s %s\n' "$options" "$(cat "$BASTION_KEY.pub")" \
    | docker exec -i "$BASTION" sh -c 'cat > /etc/ssh/authorized_keys/jump && chown root:root /etc/ssh/authorized_keys/jump && chmod 644 /etc/ssh/authorized_keys/jump'
  printf 'PermitOpen %s\n' "${opens[*]}" \
    | docker exec -i "$BASTION" sh -c 'cat > /etc/ssh/sshd_config.d/10-permitopen.conf && chmod 644 /etc/ssh/sshd_config.d/10-permitopen.conf'
  reload_sshd "$BASTION"
  echo "bastion $BASTION ($SUBNET.2) : clé installée, PermitOpen ${opens[*]}"
  if [ "$1" = frr ]; then
    for n in "${ROUTERS[@]}"; do
      docker exec -i "$PREFIX-r${n#1}" sh -c 'umask 077; mkdir -p /home/netops/.ssh && cat > /home/netops/.ssh/authorized_keys \
        && chown -R netops:netops /home/netops/.ssh && chmod 700 /home/netops/.ssh' <"$ROUTER_KEY.pub"
    done
    echo "routeurs FRR : clé publique netcheck_router installée pour netops (authentification par clé)"
  fi
}

cmd_unprovision() {
  lab_params "$1"
  if docker inspect "$BASTION" >/dev/null 2>&1; then
    docker exec "$BASTION" sh -c ': > /etc/ssh/authorized_keys/jump; echo "PermitOpen none" > /etc/ssh/sshd_config.d/10-permitopen.conf'
    reload_sshd "$BASTION"
  fi
  if [ "$1" = frr ]; then
    local n
    for n in "${ROUTERS[@]}"; do
      docker exec "$PREFIX-r${n#1}" rm -f /home/netops/.ssh/authorized_keys 2>/dev/null || true
    done
  fi
  echo "bastion et clés de routeurs retirés ($1)"
}

case "${1:-}" in
  keys) cmd_keys ;;
  provision) cmd_provision "${2:-}" ;;
  unprovision) cmd_unprovision "${2:-}" ;;
  *) sed -n '2,18p' "$0" >&2; exit 2 ;;
esac
