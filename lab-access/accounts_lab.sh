#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/fail() ne font qu'un echo et une affectation, le motif « cond && ok || fail » est sûr.
# Comptes en LECTURE SEULE « netcheck-ro » d'un lab déployé (phase C5) : clé de lab, comptes, politique Pathz.
#   bash lab-access/accounts_lab.sh frr|multivendor|ceos [provision|unprovision|status]
# À rejouer après CHAQUE déploiement, comme pin_hostkeys.sh : les comptes et la politique Pathz vivent dans l'état des
# équipements, pas dans leur configuration de démarrage (qui ne porte que les RÔLES, versionnés dans configs*/).
#
#   FRR      compte déjà dans l'image (docker/Dockerfile : doas, règles à arguments exacts) ; ce script installe la CLÉ
#            PUBLIQUE de netcheck-ro (fichier appartenant à root) sur chaque routeur FRR du lab.
#   EOS      le rôle `netcheck-ro` et les deux lignes aaa viennent de configs-ceos/r4/startup-config ; ce script ajoute le
#            compte (sans mot de passe) et sa clé, dans la configuration COURANTE : jamais write ni copy startup-config.
#   SR Linux le rôle vient de configs-multivendor/r5/config.cli ; ce script ajoute l'utilisateur et sa clé (configuration
#            courante, jamais save), puis pousse la politique Pathz lab-access/pathz/netcheck-ro.json (lab-access/pathz_lab.py :
#            sans elle, un rôle non superutilisateur ne voit aucune donnée) et RELIT l'équipement pour prouver qu'elle est
#            effective (sinon code 1). Outil de lab épinglé sur SR Linux 26.7.2 ; TLS non vérifié seulement parce que
#            l'inventaire du lab déclare `lab: true`, et annoncé. `status` rejoue la vérification sans rien envoyer.
#
# Clé : lab-access/.keys/netcheck_ro (ed25519, 0600, ignorée par Git), créée si absente. Aucun mot de passe de netcheck-ro
# n'existe nulle part : ni dans l'image, ni dans les configurations, ni dans ce script.
# Code retour : 0 si tout est en place, 1 sinon (message clair), 2 pour une erreur d'usage.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

KIND="${1:-}"; ACTION="${2:-provision}"
case "$KIND" in
  frr)         PREFIX=clab-frr-lab;             SUBNET=172.20.20; FRR_NODES="r1 r2 r3 r4 r5"; OTHER="" ;;
  multivendor) PREFIX=clab-frr-lab-multivendor; SUBNET=172.20.21; FRR_NODES="r1 r2 r3 r4";    OTHER=srlinux ;;
  ceos)        PREFIX=clab-frr-lab-ceos;        SUBNET=172.20.22; FRR_NODES="r1 r2 r3 r5";    OTHER=eos ;;
  *) echo "usage : $0 frr|multivendor|ceos [provision|unprovision|status]" >&2; exit 2 ;;
esac
case "$ACTION" in provision|unprovision|status) ;; *) echo "action inconnue : $ACTION" >&2; exit 2 ;; esac

KEY=lab-access/.keys/netcheck_ro
PYTHON=netcheck/.venv/bin/python
PATHZ_POLICY=lab-access/pathz/netcheck-ro.json
LAB_INVENTORY=automation/inventory-multivendor.yml   # `lab: true` : seul cas où pathz_lab.py accepte --insecure
STATUS=0
fail() { echo "  ❌ $*" >&2; STATUS=1; }
ok()   { echo "  ✅ $*"; }

ensure_key() {
  mkdir -p lab-access/.keys && chmod 700 lab-access/.keys
  if [[ ! -f "$KEY" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C "netcheck-ro (lab)" -f "$KEY" >/dev/null || { echo "ssh-keygen a échoué" >&2; exit 1; }
  fi
  chmod 600 "$KEY"; chmod 644 "$KEY.pub"
}
PUB() { cut -d' ' -f1,2 "$KEY.pub"; }

running() { docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true; }

# --- FRR : la clé publique, dans un fichier appartenant à root (StrictModes) ---------------------------------------
frr_node() {
  local c="$PREFIX-$1"
  running "$c" || { fail "$c : conteneur absent"; return; }
  if ! docker exec "$c" test -f /etc/doas.conf 2>/dev/null; then
    fail "$c : image sans compte netcheck-ro (reconstruire frr-ssh:10.2.1 : docker build docker/)"; return
  fi
  case "$ACTION" in
    provision)
      docker exec -i "$c" sh -c 'cat > /home/netcheck-ro/.ssh/authorized_keys && chmod 644 /home/netcheck-ro/.ssh/authorized_keys \
        && chown root:root /home/netcheck-ro/.ssh/authorized_keys' < "$KEY.pub" \
        && ok "$1 (FRR) : clé publique installée" || fail "$1 (FRR) : installation de la clé impossible" ;;
    unprovision)
      docker exec "$c" sh -c ': > /home/netcheck-ro/.ssh/authorized_keys' && ok "$1 (FRR) : clé retirée" \
        || fail "$1 (FRR) : retrait impossible" ;;
    status)
      if docker exec "$c" grep -q "$(PUB | cut -d' ' -f2)" /home/netcheck-ro/.ssh/authorized_keys 2>/dev/null; then
        ok "$1 (FRR) : clé installée"; else fail "$1 (FRR) : clé absente"; fi ;;
  esac
}

# --- EOS ------------------------------------------------------------------------------------------------------------
eos_node() {
  local c="$PREFIX-r4"
  running "$c" || { fail "$c : conteneur absent"; return; }
  case "$ACTION" in
    provision)
      if ! docker exec "$c" Cli -p 15 -c "show running-config section ^role" 2>/dev/null | grep -q "^role netcheck-ro"; then
        fail "r4 (EOS) : le rôle netcheck-ro manque (configs-ceos/r4/startup-config non chargée ?)"; return
      fi
      printf 'configure\nusername netcheck-ro privilege 15 role netcheck-ro nopassword\nusername netcheck-ro ssh-key %s\nend\n' "$(PUB)" \
        | docker exec -i "$c" Cli -p 15 2>&1 | grep -E "^%|Invalid" && { fail "r4 (EOS) : configuration refusée"; return; }
      ok "r4 (EOS) : compte netcheck-ro et clé ajoutés (configuration courante)" ;;
    unprovision)
      printf 'configure\nno username netcheck-ro\nend\n' | docker exec -i "$c" Cli -p 15 >/dev/null 2>&1 \
        && ok "r4 (EOS) : compte retiré" || fail "r4 (EOS) : retrait impossible" ;;
    status)
      if docker exec "$c" Cli -p 15 -c "show running-config section ^username" 2>/dev/null | grep -q "^username netcheck-ro .*role netcheck-ro"; then
        ok "r4 (EOS) : compte présent"; else fail "r4 (EOS) : compte absent"; fi ;;
  esac
}

# --- SR Linux ---------------------------------------------------------------------------------------------------------
srl_admin_password_file() {   # fichier 0600 temporaire : le mot de passe d'admin (lab) ne passe jamais en argument
  local f; f="$(mktemp)"; chmod 600 "$f"
  "$PYTHON" -c 'import yaml; i = yaml.safe_load(open("automation/inventory-multivendor.yml")); r = i["routers"]["r5"]
print(r.get("password") or i["defaults"]["password"])' > "$f"
  echo "$f"
}
srl_node() {
  local c="$PREFIX-r5"
  running "$c" || { fail "$c : conteneur absent"; return; }
  case "$ACTION" in
    provision)
      if ! docker exec "$c" sr_cli -- "info from running system aaa authorization" 2>/dev/null | grep -q "role netcheck-ro"; then
        fail "r5 (SR Linux) : le rôle netcheck-ro manque (configs-multivendor/r5/config.cli non chargée ?)"; return
      fi
      printf 'enter candidate\nset / system aaa authentication user netcheck-ro role [ netcheck-ro ]\nset / system aaa authentication user netcheck-ro ssh-key [ "%s" ]\ncommit now\n' "$(PUB)" \
        | docker exec -i "$c" sr_cli 2>&1 | grep -q "All changes have been committed" \
        || { fail "r5 (SR Linux) : utilisateur netcheck-ro non créé"; return; }
      # push RELIT l'équipement (version active + sondes) : « en place » veut dire « effective », jamais « envoyée »
      local pw; pw="$(srl_admin_password_file)"
      "$PYTHON" lab-access/pathz_lab.py push "$PATHZ_POLICY" --target "$SUBNET.15" --user admin --password-file "$pw" \
        --insecure --lab-inventory "$LAB_INVENTORY"
      local code=$?; rm -f "$pw"
      [[ $code == 0 ]] && ok "r5 (SR Linux) : utilisateur et clé en place, politique Pathz poussée ET vérifiée (effective)" \
        || fail "r5 (SR Linux) : politique Pathz NON effective (code $code, détail ci-dessus)" ;;
    unprovision)
      printf 'enter candidate\ndelete / system aaa authentication user netcheck-ro\ncommit now\n' | docker exec -i "$c" sr_cli 2>&1 \
        | grep -q "All changes have been committed" && ok "r5 (SR Linux) : utilisateur retiré (la politique Pathz reste jusqu'au redéploiement)" \
        || fail "r5 (SR Linux) : retrait impossible" ;;
    status)
      if docker exec "$c" sr_cli -- "info from running system aaa authentication user netcheck-ro" 2>/dev/null | grep -q "netcheck-ro"; then
        ok "r5 (SR Linux) : utilisateur présent"; else fail "r5 (SR Linux) : utilisateur absent"; fi
      local pw; pw="$(srl_admin_password_file)"
      "$PYTHON" lab-access/pathz_lab.py verify "$PATHZ_POLICY" --target "$SUBNET.15" --user admin --password-file "$pw" \
        --insecure --lab-inventory "$LAB_INVENTORY"
      local code=$?; rm -f "$pw"
      [[ $code == 0 ]] && ok "r5 (SR Linux) : politique Pathz effective (relue sur l'équipement)" \
        || fail "r5 (SR Linux) : politique Pathz NON effective (code $code, détail ci-dessus)" ;;
  esac
}

[[ "$ACTION" == "provision" ]] && ensure_key
[[ -f "$KEY.pub" ]] || { echo "pas de clé de lab ($KEY) : lancez d'abord « $0 $KIND provision »" >&2; exit 1; }
echo "Comptes netcheck-ro du lab $KIND ($ACTION) :"
for n in $FRR_NODES; do frr_node "$n"; done
case "$OTHER" in eos) eos_node ;; srlinux) srl_node ;; esac
exit $STATUS
