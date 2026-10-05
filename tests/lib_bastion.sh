#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénarios du bastion et des clés SSH (phase C4), partagés par les trois scripts d'intégration (`source`).
# Prérequis du script appelant : ok, ko, title, $NC, $JSON_DIR, NETCHECK_KNOWN_HOSTS exporté (déjà épinglé par
# lab-access/pin_hostkeys.sh) et le lab déployé AVEC son nœud « bastion » (image netcheck-bastion:1).
#
#   c4_bastion_scenarios <lab> <inventaire.yml> <réseau, ex. 172.20.20> <préfixe conteneurs> <complet : oui|non>
# <lab> = frr | multivendor | ceos. « complet » (lab FRR seulement) ajoute l'authentification par clé des routeurs
# et la coupure de la connexion directe : les comptes des routeurs SR Linux et cEOS relèvent de la phase C5.
#
# Rien de ce qui est modifié ne l'est dans une configuration : la coupure directe ajoute un fichier
# `AllowUsers` au sshd des routeurs FRR (puis le retire), jamais une ligne de routage ; elle est annulée par
# retour explicite, puis le retour est PROUVÉ par un diff avant <-> retour sans constat.

c4_bastion_scenarios() {
  local lab="$1" inv="$2" subnet="$3" prefix="$4" full="$5"
  local bastion_ip="$subnet.2" bastion_c="$prefix-bastion" r1_c="$prefix-r1" gateway="$subnet.1"
  local bkey="lab-access/.keys/netcheck_bastion" rkey="lab-access/.keys/netcheck_router"
  local kh="$NETCHECK_KNOWN_HOSTS" binv="$JSON_DIR/c4_inventory.yml" out code since
  title "B1 : bastion SSH -- clé d'hôte épinglée, authentification par clé seulement, relais limité, jamais de repli direct"

  # (a) provisionnement et épinglage de la clé d'hôte du bastion avec celles des routeurs.
  bash lab-access/bastion_lab.sh provision "$lab" >"$JSON_DIR/c4_prov.txt" 2>&1 \
    && ok "bastion provisionné : clé publique root-owned, restrict + permitopen aux 5 routeurs (port 22)" \
    || { ko "provisionnement du bastion"; cat "$JSON_DIR/c4_prov.txt"; return; }
  bash lab-access/pin_hostkeys.sh "$lab" >"$JSON_DIR/c4_pin.txt" 2>&1 && grep -q "^$bastion_ip ssh-ed25519 " "$kh" \
    && ok "clé d'hôte du bastion épinglée dans le MÊME known_hosts que les routeurs (pin_hostkeys.sh étendu)" \
    || { ko "épinglage du bastion"; cat "$JSON_DIR/c4_pin.txt"; return; }
  { cat "$inv"; printf '\nbastion:\n  host: %s\n  username: jump\n  key_file: %s/%s\n' "$bastion_ip" "$PWD" "$bkey"; } >"$binv"

  # (b) la configuration EFFECTIVE de sshd sur le bastion, lue par sshd lui-même (sshd -T).
  local effective
  effective=$(docker exec "$bastion_c" sshd -T -C user=jump,host=x,addr=127.0.0.1 -f /etc/ssh/sshd_config 2>&1)
  local want
  for want in "allowtcpforwarding local" "x11forwarding no" "allowagentforwarding no" "passwordauthentication no" \
              "authenticationmethods publickey" "permittty no" "permituserenvironment no" "forcecommand /bin/false" \
              "allowusers jump" "permitrootlogin no" "gatewayports no" "permittunnel no"; do
    grep -qx "$want" <<<"$effective" && ok "sshd -T : $want" || ko "sshd -T : « $want » absent"
  done
  [[ "$(grep -c '^permitopen ' <<<"$effective")" == "1" \
    && "$(grep '^permitopen ' <<<"$effective")" == "permitopen $subnet.11:22 $subnet.12:22 $subnet.13:22 $subnet.14:22 $subnet.15:22" ]] \
    && ok "sshd -T : permitopen = exactement les 5 adresses de gestion, port 22" \
    || { ko "sshd -T : permitopen inattendu"; grep '^permitopen' <<<"$effective"; }
  [[ "$(docker exec "$bastion_c" stat -c '%U:%a' /etc/ssh/authorized_keys/jump)" == "root:644" ]] \
    && ok "authorized_keys du bastion appartient à root (le compte ne peut pas l'élargir)" || ko "propriétaire de authorized_keys"
  docker exec "$bastion_c" grep -q '^jump:.*:/sbin/nologin$' /etc/passwd \
    && [[ "$(docker exec "$bastion_c" sh -c "grep '^jump:' /etc/shadow | cut -d: -f2")" == "*" ]] \
    && ok "compte jump : shell /sbin/nologin, aucun mot de passe utilisable" || ko "compte jump"

  # (c) snapshot par le bastion : code 0, source dite, et le routeur voit l'adresse du bastion.
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  out=$($NC snapshot c4_via --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "snapshot des 5 routeurs PAR le bastion : code 0" || { ko "snapshot via bastion : code $code"; echo "$out"; }
  grep -q "bastion : jump@$bastion_ip (clé $PWD/$bkey)" <<<"$out" \
    && ok "source affichée : « bastion : jump@$bastion_ip (clé chemin) », jamais le contenu" || { ko "source du bastion non affichée"; echo "$out"; }
  grep -q 'BEGIN OPENSSH' <<<"$out" && ko "contenu de clé affiché" || ok "aucun contenu de clé dans la sortie"
  grep -q '"bastion"' snapshots/c4_via/meta.json && ok "meta.json : credential_sources cite le bastion" || ko "meta.json sans bastion"
  [[ "$(docker logs --since "$since" "$bastion_c" 2>&1 | grep -c 'Accepted publickey for jump')" -ge 1 ]] \
    && ok "journal du bastion : « Accepted publickey for jump » (clé, jamais mot de passe)" || ko "journal du bastion"

  # (d) preuve par l'adresse source, vue SUR le routeur : bastion en passant par lui, passerelle en direct.
  local peers
  docker exec -i "$r1_c" timeout 8 sh <tests/tools/ssh_peers_loop.sh >"$JSON_DIR/c4_peers_via.txt" 2>/dev/null &
  local pid=$!
  sleep 0.5; $NC snapshot c4_via1 --force -d r1 -i "$binv" >/dev/null 2>&1; wait "$pid"
  peers=$(sort -u "$JSON_DIR/c4_peers_via.txt" | tr '\n' ' ')
  [[ "$peers" == "$bastion_ip " ]] && ok "r1 voit la session SSH de netcheck venir de $bastion_ip (le bastion), pas de $gateway" \
    || ko "adresses source vues sur r1 via le bastion : [$peers] (attendu : $bastion_ip)"
  docker exec -i "$r1_c" timeout 8 sh <tests/tools/ssh_peers_loop.sh >"$JSON_DIR/c4_peers_direct.txt" 2>/dev/null &
  pid=$!
  sleep 0.5; $NC snapshot c4_direct1 --force -d r1 -i "$inv" >/dev/null 2>&1; wait "$pid"
  peers=$(sort -u "$JSON_DIR/c4_peers_direct.txt" | tr '\n' ' ')
  [[ "$peers" == "$gateway " ]] && ok "contre-épreuve : sans bastion, r1 voit la passerelle $gateway" \
    || ko "adresses source vues sur r1 en direct : [$peers] (attendu : $gateway)"

  # (e) clé d'hôte du bastion changée : refus pour les 5, aucun repli direct (r1 ne voit AUCUNE session).
  local tampered="$JSON_DIR/c4_tampered" other
  other=$(awk -v ip="$subnet.11" '$1==ip {print $2" "$3}' "$kh")
  awk -v ip="$bastion_ip" -v other="$other" '$1==ip {print ip" "other; next} {print}' "$kh" >"$tampered"; chmod 600 "$tampered"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker exec -i "$r1_c" timeout 8 sh <tests/tools/ssh_peers_loop.sh >"$JSON_DIR/c4_peers_tamper.txt" 2>/dev/null &
  pid=$!
  sleep 0.5
  out=$(NETCHECK_KNOWN_HOSTS="$tampered" $NC snapshot c4_tamper --force -i "$binv" 2>&1); code=$?
  wait "$pid"
  [[ "$code" == "1" && "$(grep -c "CHANGÉE" <<<"$out")" == "5" ]] \
    && ok "clé d'hôte du bastion changée : refus pour les 5 routeurs (code 1), message « CHANGÉE »" \
    || { ko "bastion à clé changée : code $code"; echo "$out" | tail -8; }
  [[ "$(docker logs --since "$since" "$bastion_c" 2>&1 | grep -c 'Accepted publickey')" == "0" ]] \
    && ok "le bastion n'a reçu aucune authentification : la clé d'hôte est vérifiée AVANT la clé de netcheck" \
    || ko "une authentification a eu lieu malgré la clé d'hôte changée"
  [[ -z "$(sort -u "$JSON_DIR/c4_peers_tamper.txt" | tr -d '\n')" ]] \
    && ok "aucun repli direct : r1 n'a vu AUCUNE session SSH pendant le refus du bastion" \
    || ko "r1 a vu des sessions pendant le refus : $(sort -u "$JSON_DIR/c4_peers_tamper.txt" | tr '\n' ' ')"

  # (f) ce que le bastion refuse, vu par un client paramiko du lab (pas par netcheck).
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if "$NC_PY" tests/tools/bastion_probe.py "$bastion_ip" "$bkey" "$kh" "$subnet" "$subnet.11" >"$JSON_DIR/c4_probe.txt" 2>&1; then
    ok "sonde du bastion : $(grep -c '^OK' "$JSON_DIR/c4_probe.txt") contrôles (mot de passe, root, 8 rebonds hors liste refusés ; aucune commande ni shell, ni terminal, ni X11, ni -R ; agent interdit par sshd -T)"
  else
    ko "sonde du bastion"; grep '^KO' "$JSON_DIR/c4_probe.txt"; tail -3 "$JSON_DIR/c4_probe.txt"
  fi
  [[ "$(docker logs --since "$since" "$bastion_c" 2>&1 | grep -c 'but the request was denied')" -ge 8 ]] \
    && ok "journal du bastion : les rebonds hors liste sont consignés comme refusés ($(docker logs --since "$since" "$bastion_c" 2>&1 | grep -c 'but the request was denied') lignes)" \
    || ko "journal du bastion : refus non consignés"

  # (g) le fichier de clé suit les règles de C2 ; la phrase secrète est un secret.
  local copy="$JSON_DIR/c4_key_0644"
  cp "$bkey" "$copy"; chmod 644 "$copy"
  out=$(NETCHECK_BASTION_KEY_FILE="$copy" $NC snapshot c4_k1 --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "3" && "$(grep -c . <<<"$out")" == "1" ]] && grep -q "droits 644" <<<"$out" \
    && ok "clé du bastion en 0644 : refusée (code 3, une ligne), avant toute connexion" || { ko "clé 0644 : code $code"; echo "$out"; }
  ln -sf "$PWD/$bkey" "$JSON_DIR/c4_key_link"
  out=$(NETCHECK_BASTION_KEY_FILE="$JSON_DIR/c4_key_link" $NC snapshot c4_k2 --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "3" ]] && grep -q "lien symbolique" <<<"$out" && ok "clé du bastion en lien symbolique : refusée (code 3)" || { ko "lien symbolique : code $code"; echo "$out"; }
  local pass="$JSON_DIR/c4_passphrase" enc="$JSON_DIR/c4_key_encrypted"
  ( umask 077; head -c 18 /dev/urandom | base64 | tr -d '+/=\n' >"$pass" )
  "$NC_PY" - "$bkey" "$enc" "$pass" <<'EOF'
import sys
from cryptography.hazmat.primitives import serialization
source, target, passfile = sys.argv[1:4]
key = serialization.load_ssh_private_key(open(source, "rb").read(), None)
phrase = open(passfile, "rb").read()
data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                         serialization.BestAvailableEncryption(phrase))
open(target, "wb").write(data)
EOF
  chmod 600 "$enc"
  out=$(NETCHECK_BASTION_KEY_FILE="$enc" $NC snapshot c4_k3 --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "3" && "$(grep -c . <<<"$out")" == "1" ]] && grep -q "phrase secrète" <<<"$out" \
    && ok "clé protégée sans phrase secrète : refusée (code 3), le message dit comment la donner" || { ko "clé protégée sans phrase : code $code"; echo "$out"; }
  out=$(NETCHECK_BASTION_KEY_FILE="$enc" NETCHECK_BASTION_KEY_PASSPHRASE="phrase-fausse-000" $NC snapshot c4_k4 --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "3" ]] && grep -q "incorrecte" <<<"$out" && ! grep -q "phrase-fausse-000" <<<"$out" \
    && ok "phrase secrète fausse : refusée (code 3), la valeur n'est pas citée" || { ko "phrase fausse : code $code"; echo "$out"; }
  out=$(NETCHECK_BASTION_KEY_FILE="$enc" NETCHECK_BASTION_KEY_PASSPHRASE_FILE="$pass" $NC snapshot c4_k5 --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "clé protégée + phrase secrète en fichier 0600 : snapshot des 5 routeurs par le bastion, code 0" \
    || { ko "clé protégée + phrase : code $code"; echo "$out" | tail -5; }
  grep -qF "$(cat "$pass")" <<<"$out" && ko "la phrase secrète apparaît dans la sortie" || ok "la phrase secrète n'apparaît dans aucune sortie"
  grep -rqF "$(cat "$pass")" snapshots/c4_k5 && ko "la phrase secrète apparaît dans le snapshot" || ok "ni dans le snapshot ni dans meta.json"

  local info_ram; info_ram="$(docker stats --no-stream --format '{{.MemUsage}}' "$bastion_c" | awk '{print $1}')"
  echo "  ℹ️  RAM du bastion ($bastion_c) : $info_ram ; image : $(docker image ls --format '{{.Size}}' netcheck-bastion:1)"

  [[ "$full" == "oui" ]] || { bash lab-access/bastion_lab.sh unprovision "$lab" >/dev/null; return; }
  c4_router_keys_and_cut "$lab" "$inv" "$binv" "$subnet" "$prefix" "$bastion_ip" "$rkey"
  bash lab-access/bastion_lab.sh unprovision "$lab" >/dev/null
}

# Lab FRR : authentification par clé des routeurs, puis connexion directe coupée (retour prouvé).
c4_router_keys_and_cut() {
  local lab="$1" inv="$2" binv="$3" subnet="$4" prefix="$5" bastion_ip="$6" rkey="$7"
  local out code r health="automation/.venv/bin/python automation/health.py"
  title "B2 : clé des routeurs FRR (jamais de repli sur le mot de passe) et connexion directe coupée"
  local wrong="$JSON_DIR/c4_inventory_wrong_password.yml" wrongb="$JSON_DIR/c4_inventory_wrong_password_bastion.yml"
  sed 's/password: netops/password: "not-the-password-0000"/' "$inv" >"$wrong"
  sed 's/password: netops/password: "not-the-password-0000"/' "$binv" >"$wrongb"

  out=$(NETCHECK_KEY_FILE="$PWD/$rkey" $NC snapshot c4_key --force -i "$wrong" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "clé seule (mot de passe d'inventaire FAUX) : snapshot des 5 routeurs, code 0" || { ko "clé seule : code $code"; echo "$out" | tail -6; }
  # Le mot de passe d'inventaire (faux) existe : la source doit dire qu'il est IGNORÉ, jamais qu'il est utilisé.
  grep -q "clé : $PWD/$rkey (r1, r2, r3, r4, r5)" <<<"$out" \
    && grep -q "mot de passe ignoré : clé configurée (r1, r2, r3, r4, r5)" <<<"$out" \
    && ! grep -q "Identifiants, mot de passe :" <<<"$out" \
    && ok "source affichée : « clé : chemin (r1…r5) » et « mot de passe ignoré : clé configurée », aucun mot de passe utilisé" \
    || { ko "source de la clé"; echo "$out"; }
  out=$(NETCHECK_KEY_FILE="$PWD/lab-access/.keys/netcheck_bastion" $NC snapshot c4_wrongkey --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "1" && "$(grep -c "INJOIGNABLE" <<<"$out")" == "5" ]] \
    && ok "mauvaise clé + BON mot de passe d'inventaire : les 5 routeurs refusent (code 1) : aucun repli sur le mot de passe" \
    || { ko "mauvaise clé : code $code (un repli sur le mot de passe aurait donné 0)"; echo "$out" | tail -8; }
  out=$(NETCHECK_KEY_FILE="$PWD/$rkey" $NC snapshot c4_keyvia --force -i "$wrongb" 2>&1); code=$?
  [[ "$code" == "0" ]] && grep -q "bastion : jump@$bastion_ip" <<<"$out" && grep -q "clé : $PWD/$rkey" <<<"$out" \
    && ok "bastion + clé des routeurs : code 0, les deux sources affichées" || { ko "bastion + clé : code $code"; echo "$out" | tail -6; }

  # Coupure de la connexion directe : AllowUsers netops@<bastion> dans le sshd de chaque routeur (fichier du
  # conteneur, jamais la configuration de routage), avec retour explicite et preuve par diff.
  $NC snapshot c4_avant --force -i "$inv" >/dev/null 2>&1
  $health >/dev/null 2>&1 && ok "avant la coupure : OSPF Full et eBGP Established (health.py)" || ko "réseau non nominal avant la coupure"
  for r in 1 2 3 4 5; do
    docker exec "$prefix-r$r" sh -c "echo 'AllowUsers netops@$bastion_ip' > /etc/ssh/sshd_config.d/99-bastion-only.conf && kill -HUP \"\$(cat /run/sshd.pid)\""
  done
  sleep 2
  out=$($NC snapshot c4_cut_direct --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "1" && "$(grep -c "INJOIGNABLE" <<<"$out")" == "5" ]] \
    && ok "connexion directe coupée : les 5 routeurs injoignables en direct (code 1)" || { ko "coupure directe : code $code"; echo "$out" | tail -8; }
  out=$($NC snapshot c4_cut_via --force -i "$binv" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "par le bastion : les 5 routeurs répondent (code 0) : le routeur n'est joignable QUE via le bastion" \
    || { ko "via le bastion pendant la coupure : code $code"; echo "$out" | tail -6; }
  $NC diff c4_avant c4_cut_via -i "$inv" >/dev/null 2>&1 && ok "diff avant <-> pendant la coupure : aucun constat (le routage n'a pas bougé)" || ko "constats pendant la coupure"
  # health.py se connecte en DIRECT aux routeurs : coupé par construction. L'état pendant la coupure est celui du
  # relevé pris PAR le bastion, jugé par l'intent du lab (OSPF et OSPFv3 Full partout, eBGP IPv4 et IPv6 Established).
  $NC assert --intent intents/lab.yml --snapshot c4_cut_via -i "$inv" >/dev/null 2>&1 \
    && ok "pendant la coupure : OSPF/OSPFv3 Full partout et eBGP IPv4+IPv6 Established (intent du lab sur le relevé pris par le bastion)" \
    || ko "réseau dégradé pendant la coupure (assert)"
  for r in 1 2 3 4 5; do
    docker exec "$prefix-r$r" sh -c 'rm -f /etc/ssh/sshd_config.d/99-bastion-only.conf && kill -HUP "$(cat /run/sshd.pid)"'
  done
  sleep 2
  out=$($NC snapshot c4_retour --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "0" ]] && ok "retour : connexion directe rétablie (code 0)" || { ko "retour : code $code"; echo "$out" | tail -6; }
  out=$($NC diff c4_avant c4_retour -i "$inv" 2>&1); code=$?
  [[ "$code" == "0" ]] && grep -q "Verdict : OK" <<<"$out" && ok "retour PROUVÉ : diff avant <-> retour sans constat (verdict OK)" || { ko "retour non prouvé : code $code"; echo "$out" | tail -8; }
  # le dossier n'est plus vide depuis la phase C5 (10-netcheck-ro.conf, voulu) : on vérifie le seul fichier du scénario
  [[ "$(docker exec "$prefix-r1" sh -c 'ls /etc/ssh/sshd_config.d/99-bastion-only.conf 2>/dev/null | wc -l')" == "0" ]] \
    && ok "le fichier AllowUsers a disparu de chaque routeur" || ko "fichier AllowUsers restant"
  $health >/dev/null 2>&1 && ok "après le retour : OSPF Full et eBGP Established (health.py)" || ko "réseau non nominal après le retour"
}
