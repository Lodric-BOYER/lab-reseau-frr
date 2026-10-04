#!/usr/bin/env bash
# Épingle les clés d'hôte SSH d'un lab déployé dans le fichier known_hosts DÉDIÉ de netcheck (phase C1).
#   bash lab-access/pin_hostkeys.sh frr|multivendor|ceos
# À rejouer après CHAQUE déploiement : les clés sont (re)générées au démarrage des conteneurs.
#
# Canal de confiance : les clés sont lues DANS les conteneurs par `docker exec` (le démon Docker local),
# jamais par le réseau : l'épinglage ne dépend pas d'une première connexion non vérifiée.
# Refuse (code 1) si deux routeurs du lab annoncent la même clé : une clé partagée empêcherait
# l'épinglage de distinguer un routeur d'un autre.
#
# Le bastion du lab (phase C4, <préfixe>-bastion, adresse <réseau>.2) est épinglé aussi, s'il est déployé.
#
# Fichier : $NETCHECK_KNOWN_HOSTS, sinon lab-access/.keys/known_hosts (ignoré par Git, droits 0600).
# Les entrées des adresses de CE lab sont remplacées ; les autres lignes sont conservées.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

case "${1:-}" in
  frr)         PREFIX=clab-frr-lab;              NET=clab-mgmt;              SUBNET=172.20.20 ;;
  multivendor) PREFIX=clab-frr-lab-multivendor;  NET=clab-mgmt-multivendor;  SUBNET=172.20.21 ;;
  ceos)        PREFIX=clab-frr-lab-ceos;         NET=clab-mgmt-ceos;         SUBNET=172.20.22 ;;
  *) echo "usage : $0 frr|multivendor|ceos" >&2; exit 2 ;;
esac
ROUTERS="r1 r2 r3 r4 r5"
KNOWN="${NETCHECK_KNOWN_HOSTS:-lab-access/.keys/known_hosts}"

# Clé publique ed25519 de l'hôte, lue dans le conteneur ($1 = conteneur, $2 = image).
read_hostkey() {
  local container="$1" image="$2"
  case "$image" in
    # cEOS garde ses clés dans /persist/secure (relevé sur 4.34.8M : ssh-keyscan annonce la même empreinte).
    *ceos*)    docker exec "$container" cat /persist/secure/ssh_host_ed25519_key.pub ;;
    # FRR (Alpine) et SR Linux 26.7.2 : /etc/ssh (SR Linux : même empreinte que celle annoncée par ssh-keyscan).
    *) docker exec "$container" cat /etc/ssh/ssh_host_ed25519_key.pub ;;
  esac
}

mkdir -p "$(dirname "$KNOWN")" && chmod 700 "$(dirname "$KNOWN")"
NEW="$(mktemp "$(dirname "$KNOWN")/.known_hosts.XXXXXX")"
trap 'rm -f "$NEW"' EXIT
chmod 600 "$NEW"

declare -A SEEN=()
STATUS=0
echo "Clés d'hôte du lab $1 (lues dans les conteneurs) :"
for r in $ROUTERS; do
  container="$PREFIX-$r"
  if ! docker inspect "$container" >/dev/null 2>&1; then
    echo "  $r : conteneur $container absent (lab non déployé ?)" >&2; STATUS=1; continue
  fi
  image="$(docker inspect -f '{{.Config.Image}}' "$container")"
  ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$container")"
  if [ "$ip" != "$SUBNET.1${r#r}" ]; then
    echo "  $r : adresse $ip inattendue (attendue $SUBNET.1${r#r})" >&2; STATUS=1; continue
  fi
  if ! pub="$(read_hostkey "$container" "$image")" || [ -z "$pub" ]; then
    echo "  $r : clé d'hôte illisible" >&2; STATUS=1; continue
  fi
  read -r type blob _ <<<"$pub"
  fp="$(ssh-keygen -lf /dev/stdin <<<"$type $blob" | awk '{print $2}')"
  if [ -n "${SEEN[$fp]:-}" ]; then
    echo "  $r : clé IDENTIQUE à celle de ${SEEN[$fp]} ($fp) : refusé (clé d'hôte partagée)" >&2; STATUS=1; continue
  fi
  SEEN[$fp]="$r"
  printf '%s %s %s\n' "$ip" "$type" "$blob" >>"$NEW"
  echo "  $r $ip $fp"
done
# Bastion (phase C4), s'il est déployé : sa clé est épinglée dans le MÊME fichier, avec la même exigence
# d'unicité. Absent (lab déployé avant la phase C4) : simple remarque, pas une erreur.
bastion="$PREFIX-bastion"
BASTION_PINNED=0
if docker inspect "$bastion" >/dev/null 2>&1; then
  b_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$bastion")"
  if [ "$b_ip" != "$SUBNET.2" ]; then
    echo "  bastion : adresse $b_ip inattendue (attendue $SUBNET.2)" >&2; STATUS=1
  elif ! pub="$(docker exec "$bastion" cat /etc/ssh/ssh_host_ed25519_key.pub)" || [ -z "$pub" ]; then
    echo "  bastion : clé d'hôte illisible" >&2; STATUS=1
  else
    read -r type blob _ <<<"$pub"
    fp="$(ssh-keygen -lf /dev/stdin <<<"$type $blob" | awk '{print $2}')"
    if [ -n "${SEEN[$fp]:-}" ]; then
      echo "  bastion : clé IDENTIQUE à celle de ${SEEN[$fp]} ($fp) : refusé" >&2; STATUS=1
    else
      printf '%s %s %s\n' "$b_ip" "$type" "$blob" >>"$NEW"
      echo "  bastion $b_ip $fp"; BASTION_PINNED=1
    fi
  fi
else
  echo "  (pas de bastion dans ce déploiement)"
fi
[ "$STATUS" -eq 0 ] || { echo "Épinglage annulé : $KNOWN inchangé." >&2; exit 1; }

# Fusion : on garde les lignes des autres adresses, on remplace celles de ce lab.
if [ -f "$KNOWN" ]; then
  grep -v -E "^$SUBNET\.(1[1-5]|2) " "$KNOWN" >>"$NEW" || true
fi
mv "$NEW" "$KNOWN"; trap - EXIT
chmod 600 "$KNOWN"
echo "Épinglé dans $KNOWN ($(grep -c -E "^$SUBNET\.1[1-5] " "$KNOWN") entrées pour ce lab, bastion : $([ "$BASTION_PINNED" = 1 ] && echo oui || echo non))."
