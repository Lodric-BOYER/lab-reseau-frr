#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénarios C5 (comptes en LECTURE SEULE « netcheck-ro »), partagés par les trois integration*.sh (`source`).
# Prérequis du script appelant : ok, ko, title, $NC, $JSON_DIR, $NETCHECK_KNOWN_HOSTS (fichier épinglé).
#
#   c5_ro_scenarios <lab: frr|multivendor|ceos> <inventaire.yml> <réseau, ex. 172.20.20> <préfixe des conteneurs>
#
# Les preuves négatives sont des sessions écrites à la main (ssh, docker exec, tests/tools/ro_probe.py), JAMAIS
# netcheck, qui ne tente que sa liste blanche. Jamais write ni copy running-config startup-config : la famille
# « écriture » est représentée par des écritures dans /tmp du conteneur, et le retour est prouvé par diff.

C5_KEY="$PWD/lab-access/.keys/netcheck_ro"

# Inventaire « lecture seule » dérivé de l'inventaire du lab : même équipements, compte netcheck-ro, clé, aucun mot de
# passe, option doas pour les routeurs FRR.
c5_make_ro_inventory() {   # $1 = inventaire source, $2 = destination
  netcheck/.venv/bin/python - "$1" "$2" "$C5_KEY" <<'PY'
import sys
import yaml
src, dst, key = sys.argv[1:4]
inv = yaml.safe_load(open(src, encoding="utf-8"))
defaults = inv.setdefault("defaults", {})
defaults.pop("password", None)
defaults["username"], defaults["key_file"] = "netcheck-ro", key
for router in inv["routers"].values():
    for field in ("password", "username", "key_file"):
        router.pop(field, None)
    if router.get("driver", defaults.get("driver", "frr")) == "frr":
        router["privilege_wrapper"] = "doas"
yaml.safe_dump(inv, open(dst, "w", encoding="utf-8"), sort_keys=False)
PY
}

c5_hash() { sha256sum | cut -c1-16; }

# --- FRR : preuves négatives sur r3 (les dix commandes passent par la collecte, plus bas) -------------------------
c5_frr_proofs() {   # $1 = préfixe, $2 = adresse de r3
  local c="$1-r3" ip="$2" out before after
  local ssh_ro=(ssh -i "$C5_KEY" -o IdentitiesOnly=yes -o UserKnownHostsFile="$NETCHECK_KNOWN_HOSTS" \
      -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15 "netcheck-ro@$ip")
  title "C5-FRR : netcheck-ro (doas -u frr, arguments exacts) -- ce qui est refusé, en direct sur r3"
  before=$(docker exec "$c" vtysh -c 'show running-config' | c5_hash)

  out=$("${ssh_ro[@]}" "doas -u frr /usr/bin/vtysh -u -c 'show interface json'" 2>&1)
  [[ "$out" == *'"eth0"'* ]] && ok "lecture permise : show interface json (JSON reçu)" || { ko "lecture permise refusée"; echo "$out" | head -3; }
  out=$("${ssh_ro[@]}" "doas -u frr /usr/bin/vtysh -c 'show running-config'" 2>&1)
  [[ "$out" == *"hostname"* ]] && ok "lecture permise : show running-config (hors vue, un seul -c)" || ko "show running-config refusé"

  local label cmd
  while IFS='|' read -r label cmd; do
    out=$("${ssh_ro[@]}" "$cmd" </dev/null 2>&1 | head -2)      # </dev/null : ssh ne doit pas lire la liste ci-dessous
    [[ "$out" == *"Operation not permitted"* || "$out" == *"failed to connect to any daemons"* ]] \
      && ok "refusé : $label" || { ko "NON refusé : $label"; echo "    $out"; }
  done <<'EOF'
vtysh direct, sans doas (aucun accès aux sockets)|vtysh -c 'show version'
configuration (configure terminal)|doas -u frr /usr/bin/vtysh -c 'configure terminal'
un argument -c en plus|doas -u frr /usr/bin/vtysh -c 'show running-config' -c 'configure terminal'
vtysh sans argument (shell interactif)|doas -u frr /usr/bin/vtysh
un shell sous l'identité frr|doas -u frr /bin/sh
cible root|doas -u root id
cible par défaut (root)|doas id
doas -s (shell)|doas -s
une commande d'une autre règle sans -u|doas -u frr /usr/bin/vtysh -c 'show interface json'
-u sur la commande qui n'existe pas en vue|doas -u frr /usr/bin/vtysh -u -c 'show running-config'
une autre commande vtysh|doas -u frr /usr/bin/vtysh -u -c 'show version'
une commande collée par point-virgule|doas -u frr /usr/bin/vtysh -u -c 'show interface json;id'
EOF

  # VTYSH_PAGER : le témoin positif PUIS l'essai. vtysh lance le pager d'après l'environnement quand sa sortie va
  # à un terminal ; doas, sans keepenv, ne le transmet pas.
  docker cp tests/tools/ptyrun.py "$c:/tmp/c5_ptyrun.py" >/dev/null
  docker exec -i "$c" sh -c 'cat > /tmp/c5_pager.sh && chmod 755 /tmp/c5_pager.sh && rm -f /tmp/c5_pager_ran' <<'EOF'
#!/bin/sh
cat >/dev/null
id > /tmp/c5_pager_ran
EOF
  docker exec -u netops "$c" python3 /tmp/c5_ptyrun.py /tmp/c5_pager.sh /usr/bin/vtysh -c 'show running-config' >/dev/null 2>&1
  docker exec "$c" test -s /tmp/c5_pager_ran \
    && ok "témoin : un membre de frrvty qui lance vtysh directement avec VTYSH_PAGER fait exécuter le script (le test est probant)" \
    || ko "témoin VTYSH_PAGER : le script n'a pas été exécuté, l'essai ne prouverait rien"
  docker exec "$c" rm -f /tmp/c5_pager_ran
  docker exec -u netcheck-ro "$c" python3 /tmp/c5_ptyrun.py /tmp/c5_pager.sh doas -u frr /usr/bin/vtysh -c 'show running-config' >/dev/null 2>&1
  docker exec "$c" test -e /tmp/c5_pager_ran && ko "VTYSH_PAGER (script témoin) exécuté via doas" \
    || ok "VTYSH_PAGER=script témoin via doas : rien n'est exécuté (aucun fichier écrit)"
  out=$(docker exec -u netcheck-ro "$c" python3 /tmp/c5_ptyrun.py /bin/sh doas -u frr /usr/bin/vtysh -c 'show running-config' 2>&1 | head -3)
  [[ "$out" == *"Building configuration"* ]] && ok "VTYSH_PAGER=/bin/sh via doas : la sortie s'affiche, rien n'est lancé" \
    || { ko "VTYSH_PAGER=/bin/sh : sortie inattendue"; echo "$out"; }
  docker exec -u netcheck-ro "$c" sh -c 'VTYSH_PAGER=/tmp/c5_pager.sh PAGER=/tmp/c5_pager.sh LD_PRELOAD=/nonexistent doas -u frr /usr/bin/vtysh -c "show running-config" >/dev/null 2>&1'
  docker exec "$c" test -e /tmp/c5_pager_ran && ko "variables d'environnement transmises par doas" \
    || ok "VTYSH_PAGER, PAGER, LD_PRELOAD posés dans le shell : doas ne les transmet pas"
  docker exec "$c" rm -f /tmp/c5_pager.sh /tmp/c5_ptyrun.py /tmp/c5_pager_ran

  # Écritures et accès réseau
  out=$("${ssh_ro[@]}" "echo x >> /etc/frr/frr.conf" 2>&1); [[ "$out" == *"Permission denied"* || "$out" == *"denied"* ]] \
    && ok "écriture de /etc/frr/frr.conf refusée" || ko "écriture de frr.conf possible : $out"
  out=$("${ssh_ro[@]}" "touch /var/run/frr/c5-probe" 2>&1); [[ "$out" == *"Permission denied"* || "$out" == *"denied"* ]] \
    && ok "écriture dans /var/run/frr (sockets) refusée" || ko "écriture dans /var/run/frr possible : $out"
  out=$(timeout 20 ssh -i "$C5_KEY" -o UserKnownHostsFile="$NETCHECK_KNOWN_HOSTS" -o StrictHostKeyChecking=yes -o PubkeyAuthentication=no \
      -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=0 "netcheck-ro@$ip" true 2>&1 | tail -1)
  [[ "$out" == *"Permission denied"* ]] && ok "mot de passe refusé (clé seulement)" || ko "authentification sans clé : $out"
  local errfile="$JSON_DIR/c5_forward.err"; : >"$errfile"
  ssh -i "$C5_KEY" -o UserKnownHostsFile="$NETCHECK_KNOWN_HOSTS" -o StrictHostKeyChecking=yes -o BatchMode=yes -N \
      -L 127.0.0.1:2599:127.0.0.1:22 "netcheck-ro@$ip" 2>"$errfile" &
  local fwd=$!; sleep 4; (echo > /dev/tcp/127.0.0.1/2599) 2>/dev/null; sleep 1; kill "$fwd" 2>/dev/null; wait "$fwd" 2>/dev/null
  grep -q "administratively prohibited" "$errfile" && ok "transfert de port refusé (administratively prohibited)" \
    || { ko "transfert de port non refusé"; cat "$errfile"; }
  out=$(docker exec "$c" sshd -T -C user=netcheck-ro,host=x,addr=203.0.113.1 2>/dev/null | grep -E "^(passwordauthentication|authenticationmethods|allowtcpforwarding|allowagentforwarding|x11forwarding|permittunnel|permituserrc) " | tr '\n' ' ')
  [[ "$out" == *"passwordauthentication no"* && "$out" == *"authenticationmethods publickey"* && "$out" == *"allowtcpforwarding no"* \
     && "$out" == *"allowagentforwarding no"* && "$out" == *"x11forwarding no"* && "$out" == *"permittunnel no"* ]] \
    && ok "sshd -T : clé seulement, aucun transfert, agent, X11 ni tunnel pour netcheck-ro" || ko "sshd -T inattendu : $out"
  [[ "$(docker exec "$c" sh -c "grep -v '^#' /etc/doas.conf | grep -c -E 'keepenv|setenv|as root'")" == "0" ]] \
    && ok "doas.conf de l'image : ni keepenv, ni setenv, ni « as root »" || ko "doas.conf contient keepenv, setenv ou as root"

  after=$(docker exec "$c" vtysh -c 'show running-config' | c5_hash)
  [[ "$before" == "$after" ]] && ok "configuration de r3 : identique avant et après toutes les tentatives (diff à zéro)" \
    || ko "configuration de r3 modifiée ($before -> $after)"
}

# Lit les lignes de tests/tools/ro_probe.py : « OK … » / « KO … ». L'avertissement de la garde labtls.py (clés d'hôte ou
# TLS non vérifiés, permis parce que l'inventaire déclare lab: true) s'affiche, il n'est pas un échec ; TOUT AUTRE texte
# (trace d'erreur, sortie inattendue) est un échec : une sonde qui plante ne doit jamais passer pour un succès.
c5_report() {
  local line
  while IFS= read -r line; do
    case "$line" in
      "OK "*) ok "${line#OK }" ;;
      "KO "*) ko "${line#KO }" ;;
      AVERTISSEMENT*) echo "  ⚠️  ${line%% -- *} (lab seulement)" ;;
      *) ko "sortie inattendue de la sonde : $line" ;;
    esac
  done
}

# --- EOS ------------------------------------------------------------------------------------------------------------
c5_eos_proofs() {   # $1 = préfixe, $2 = adresse de r4
  local c="$1-r4" line before after sbefore safter
  title "C5-EOS : netcheck-ro (rôle dédié, deux lignes aaa) -- ce qui est refusé, en direct sur r4"
  [[ "$(docker exec "$c" Cli -p 15 -c "show running-config section aaa" | grep -c "^aaa authorization")" == "2" ]] \
    && ok "écart de configuration attendu présent : aaa authorization exec ET commands (sans elles, les rôles sont inertes)" \
    || ko "les deux lignes aaa authorization manquent"
  before=$(docker exec "$c" Cli -p 15 -c "show running-config" | c5_hash)
  sbefore=$(docker exec "$c" Cli -p 15 -c "show startup-config" | c5_hash)
  c5_report < <(netcheck/.venv/bin/python tests/tools/ro_probe.py eos --host "$2" --key "$C5_KEY" --lab-inventory "$C5_LAB_INV" 2>&1)
  [[ -z "$(docker exec "$c" sh -c 'ls /tmp/c5-* 2>/dev/null')" ]] \
    && ok "aucun fichier écrit dans /tmp par les copies, redirections et tee refusés" \
    || { ko "un fichier a été écrit"; docker exec "$c" sh -c 'ls -l /tmp/c5-*'; }
  after=$(docker exec "$c" Cli -p 15 -c "show running-config" | c5_hash)
  safter=$(docker exec "$c" Cli -p 15 -c "show startup-config" | c5_hash)
  [[ "$before" == "$after" ]] && ok "configuration courante de r4 : identique avant et après (diff à zéro)" || ko "running-config modifiée"
  [[ "$sbefore" == "$safter" ]] && ok "show startup-config : même empreinte avant et après (jamais de write)" || ko "startup-config modifiée"
  [[ -z "$(docker exec "$c" Cli -p 15 -c "show configuration sessions" | awk '/^ *---- /{t=1; next} t && NF')" ]] \
    && ok "aucune session de configuration restée ouverte" || ko "session de configuration résiduelle"
}

# --- SR Linux -----------------------------------------------------------------------------------------------------
c5_srl_proofs() {   # $1 = préfixe, $2 = adresse de r5
  local c="$1-r5" pw line before after sbefore safter token orig_name
  title "C5-SR Linux : netcheck-ro (rôle + politique Pathz) -- ce qui est refusé, en direct sur r5"
  pw=$(mktemp); chmod 600 "$pw"
  netcheck/.venv/bin/python -c 'import yaml; i = yaml.safe_load(open("automation/inventory-multivendor.yml")); r = i["routers"]["r5"]
print(r.get("password") or i["defaults"]["password"])' >"$pw"
  srl_cfg() { docker exec -i "$c" sr_cli 2>&1 | grep -c "All changes have been committed"; }
  docker exec "$c" sr_cli -- "info flat from running /" >"$JSON_DIR/c5_srl_before.txt"
  before=$(c5_hash <"$JSON_DIR/c5_srl_before.txt")
  sbefore=$(docker exec "$c" sh -c 'sha256sum /etc/opt/srlinux/config.json | cut -c1-16')
  c5_report < <(netcheck/.venv/bin/python tests/tools/ro_probe.py srlinux --host "$2" --key "$C5_KEY" --admin-password-file "$pw" --lab-inventory "$C5_LAB_INV" 2>&1)

  # politique Pathz : effective (relue), et la vérification est BRUYANTE (jamais de succès silencieux), TLS gardé
  local pzout pzcode pzbad pzpol=lab-access/pathz/netcheck-ro.json
  pzout=$(netcheck/.venv/bin/python lab-access/pathz_lab.py verify "$pzpol" --target "$2" --user admin --password-file "$pw" \
    --insecure --lab-inventory "$C5_LAB_INV" 2>&1); pzcode=$?
  [[ "$pzcode" == "0" && "$pzout" == *"effective sur"* && "$pzout" == *"AVERTISSEMENT"* ]] \
    && ok "Pathz : politique effective, relue sur r5 ; le TLS non vérifié est annoncé" \
    || { ko "Pathz : vérification (code $pzcode)"; echo "$pzout" | head -5; }
  pzbad=$(mktemp)
  netcheck/.venv/bin/python -c 'import json, sys
p = json.load(open(sys.argv[1]))
p["attendus"].append({"user": "netcheck-ro", "path": "/interface[name=ethernet-1/1]", "mode": "write", "action": "permit", "pourquoi": "FAUX expres"})
json.dump(p, open(sys.argv[2], "w"))' "$pzpol" "$pzbad"
  pzout=$(netcheck/.venv/bin/python lab-access/pathz_lab.py verify "$pzbad" --target "$2" --user admin --password-file "$pw" \
    --insecure --lab-inventory "$C5_LAB_INV" 2>&1); pzcode=$?
  [[ "$pzcode" == "1" && "$pzout" == *"NON EFFECTIVE"* && "$pzout" == *"FAUX expres"* ]] \
    && ok "Pathz : un attendu faux donne code 1 et « NON EFFECTIVE » avec la ligne fautive (pas de succès silencieux)" \
    || { ko "Pathz : l'écart n'a pas été signalé (code $pzcode)"; echo "$pzout" | head -5; }
  rm -f "$pzbad"
  pzout=$(netcheck/.venv/bin/python lab-access/pathz_lab.py verify "$pzpol" --target "$2" --user admin --password-file "$pw" 2>&1); pzcode=$?
  [[ "$pzcode" != "0" && "$pzout" == *"échec TLS"* ]] \
    && ok "Pathz : sans --insecure, la vérification TLS stricte refuse le certificat auto-signé (code $pzcode)" \
    || { ko "Pathz : TLS strict non appliqué (code $pzcode)"; echo "$pzout" | head -3; }
  pzout=$(netcheck/.venv/bin/python lab-access/pathz_lab.py verify "$pzpol" --target "$2" --user admin --password-file "$pw" --insecure 2>&1); pzcode=$?
  [[ "$pzcode" == "3" && "$pzout" == *"lab-inventory"* ]] \
    && ok "Pathz : --insecure sans --lab-inventory refusé (code 3)" || { ko "Pathz : --insecure accepté sans inventaire lab (code $pzcode)"; echo "$pzout" | head -3; }
  pzout=$(netcheck/.venv/bin/python lab-access/pathz_lab.py verify "$pzpol" --target "$2" --user admin --password-file "$pw" \
    --insecure --lab-inventory netcheck/rules/security.yml 2>&1); pzcode=$?
  [[ "$pzcode" == "3" && "$pzout" == *"lab: true"* ]] \
    && ok "Pathz : --insecure avec un fichier qui ne déclare pas lab: true refusé (code 3)" || { ko "Pathz : fichier non lab accepté (code $pzcode)"; echo "$pzout" | head -3; }

  # gNMI et JSON-RPC : un mot de passe TEMPORAIRE (le compte n'en a aucun) rend l'authentification possible, pour que
  # le refus observé vienne du RÔLE et non de l'absence de mot de passe. Retiré à la fin, services restaurés.
  token=$(head -c 12 /dev/urandom | base64 | tr -d '+/=')Aa1!
  local tmppw; tmppw=$(mktemp); chmod 600 "$tmppw"; printf '%s' "$token" >"$tmppw"
  [[ "$(printf 'enter candidate\nset / system aaa authentication user netcheck-ro password %s\ncommit now\n' "$token" | srl_cfg)" == "1" ]] \
    || ko "mot de passe temporaire non posé"
  c5_report < <(netcheck/.venv/bin/python tests/tools/ro_probe.py services --host "$2" --user netcheck-ro --password-file "$tmppw" --expect denied --insecure --lab-inventory "$C5_LAB_INV" 2>&1)
  # témoin : avec les services déclarés, gNMI et JSON-RPC répondent (le refus ci-dessus vient donc bien de « services [ cli ] »)
  printf 'enter candidate\nset / system aaa authorization role netcheck-ro services [ cli gnmi json-rpc ]\ncommit now\n' | srl_cfg >/dev/null
  c5_report < <(netcheck/.venv/bin/python tests/tools/ro_probe.py services --host "$2" --user netcheck-ro --password-file "$tmppw" --expect pathz --insecure --lab-inventory "$C5_LAB_INV" 2>&1)
  printf 'enter candidate\nset / system aaa authorization role netcheck-ro services [ cli ]\ndelete / system aaa authentication user netcheck-ro password\ncommit now\n' | srl_cfg >/dev/null
  rm -f "$tmppw"

  # admin : toujours complet (lecture ET écriture), puis retour
  [[ "$(printf 'enter candidate\nset / system name host-name c5-admin-write\ncommit now\n' | srl_cfg)" == "1" ]] \
    && [[ "$(docker exec "$c" sr_cli -- 'info from running system name host-name')" == *c5-admin-write* ]] \
    && ok "admin : écriture permise malgré la politique Pathz (hostname modifié, relu)" || ko "admin ne peut plus écrire"
  # retour exact : le nom d'hôte redevient ce qu'il était, y compris « non défini » (alors on supprime la ligne)
  orig_name=$(grep -m1 '^set / system name host-name ' "$JSON_DIR/c5_srl_before.txt" | awk '{print $NF}')
  if [[ -n "$orig_name" ]]; then
    printf 'enter candidate\nset / system name host-name %s\ncommit now\n' "$orig_name" | srl_cfg >/dev/null
  else
    printf 'enter candidate\ndelete / system name host-name\ncommit now\n' | srl_cfg >/dev/null
  fi
  docker exec "$c" sr_cli -- "info flat from running /" >"$JSON_DIR/c5_srl_after.txt"
  after=$(c5_hash <"$JSON_DIR/c5_srl_after.txt")
  safter=$(docker exec "$c" sh -c 'sha256sum /etc/opt/srlinux/config.json | cut -c1-16')
  [[ "$before" == "$after" ]] && ok "configuration courante de r5 : identique avant et après (diff à zéro)" \
    || { ko "configuration de r5 modifiée"; diff "$JSON_DIR/c5_srl_before.txt" "$JSON_DIR/c5_srl_after.txt" | head -8; }
  [[ "$sbefore" == "$safter" ]] && ok "configuration de démarrage de r5 : même empreinte (jamais de save)" || ko "démarrage de r5 modifié"
  rm -f "$pw"
}

# --- point d'entrée ---------------------------------------------------------------------------------------------------
c5_ro_scenarios() {
  local lab="$1" inv="$2" net="$3" prefix="$4" ro_inv="$JSON_DIR/c5_ro_inventory.yml" out code
  C5_LAB_INV="$inv"   # inventaire `lab: true` : autorise TLS --insecure et clés d'hôte non vérifiées des sondes (labtls.py)
  title "C5 : comptes netcheck-ro (lecture seule) : provisionnement, collecte avec le compte, diff à zéro contre admin"
  bash lab-access/accounts_lab.sh "$lab" provision >"$JSON_DIR/c5_provision.txt" 2>&1 \
    && ok "accounts_lab.sh : clé de lab, comptes et politique en place sur le lab $lab" \
    || { ko "accounts_lab.sh a échoué"; cat "$JSON_DIR/c5_provision.txt"; }
  [[ "$(stat -c %a "$C5_KEY" 2>/dev/null)" == "600" && "$(grep -c "BEGIN" "$C5_KEY.pub" 2>/dev/null)" == "0" ]] \
    && ok "clé de lab : fichier 0600, hors dépôt (lab-access/.keys/, ignoré par Git)" || ko "clé de lab absente ou mal protégée"
  git check-ignore -q "$C5_KEY" && ok "la clé privée est ignorée par Git" || ko "la clé privée n'est pas ignorée par Git"
  c5_make_ro_inventory "$inv" "$ro_inv"
  $NC snapshot c5_admin --force -i "$inv" >/dev/null 2>&1
  out=$($NC snapshot c5_ro --force -i "$ro_inv" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "snapshot avec le compte netcheck-ro : tous les équipements OK (code 0)" \
    || { ko "snapshot netcheck-ro : code $code"; echo "$out" | tail -12; }
  [[ "$out" == *"clé : $C5_KEY"* && "$out" != *"Identifiants, mot de passe :"* ]] \
    && ok "source affichée : « clé : chemin », aucun mot de passe" || { ko "source des identifiants inattendue"; echo "$out" | head -5; }
  out=$($NC diff c5_admin c5_ro 2>&1); code=$?
  [[ "$code" == "0" && "$out" == *"Verdict : OK"* ]] \
    && ok "diff admin <-> netcheck-ro : aucune différence (mêmes données collectées, code 0)" \
    || { ko "diff admin <-> netcheck-ro : code $code"; echo "$out" | head -12; }
  case "$lab" in
    frr)         c5_frr_proofs "$prefix" "$net.13" ;;
    ceos)        c5_eos_proofs "$prefix" "$net.14" ;;
    multivendor) c5_srl_proofs "$prefix" "$net.15" ;;
  esac
}
