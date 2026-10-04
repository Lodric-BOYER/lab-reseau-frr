#!/usr/bin/env bash
# shellcheck disable=SC2015
# Justification : ok()/ko() ne font qu'un echo et un incrément, le motif « cond && ok || ko » est sûr.
# Scénarios de clés d'hôte (phase C1), partagés par les trois scripts d'intégration (`source`).
# Prérequis du script appelant : ok, ko, title, $NC, $JSON_DIR, et NETCHECK_KNOWN_HOSTS exporté
# (le fichier dédié, déjà épinglé par lab-access/pin_hostkeys.sh).
#
#   c1_hostkeys_scenarios <lab> <inventaire.yml> <adresse-du-1er-routeur> <adresse-du-2e-routeur>
# <lab> = frr | multivendor | ceos.

c1_hostkeys_scenarios() {
  local lab="$1" inv="$2" ip1="$3" ip2="$4"
  local kh="$NETCHECK_KNOWN_HOSTS" out code
  title "H1 : clés d'hôte -- strict par défaut, clé changée refusée, accept-new réservé au lab"

  # (a) épinglage : relu depuis les conteneurs ; refuse deux routeurs qui annoncent la même clé.
  bash lab-access/pin_hostkeys.sh "$lab" >"$JSON_DIR/c1_pin.txt" 2>&1 \
    && ok "pin_hostkeys.sh : 5 clés d'hôte distinctes épinglées depuis les conteneurs" \
    || { ko "pin_hostkeys.sh a échoué"; cat "$JSON_DIR/c1_pin.txt"; }

  # (b) known_hosts absent : chaque routeur est refusé avec un message clair, aucun n'est contacté en SSH.
  out=$(NETCHECK_KNOWN_HOSTS="$JSON_DIR/c1_absent" $NC snapshot c1_absent --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "1" && "$(grep -c "clé d'hôte inconnue" <<<"$out")" == "5" ]] \
    && ok "known_hosts absent : les 5 routeurs refusés (clé d'hôte inconnue), code 1" \
    || { ko "known_hosts absent : code $code"; echo "$out"; }

  # (c) clé de $ip1 remplacée par celle de $ip2 : refus « CHANGÉE » pour ce seul routeur.
  local tampered="$JSON_DIR/c1_tampered" other
  other=$(awk -v ip="$ip2" '$1==ip {print $2" "$3}' "$kh")
  awk -v ip="$ip1" -v k="$other" '$1==ip {print $1" "k; next} {print}' "$kh" >"$tampered"
  chmod 600 "$tampered"
  out=$(NETCHECK_KNOWN_HOSTS="$tampered" $NC snapshot c1_tamper --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "1" && "$(grep -c "CHANGÉE" <<<"$out")" == "1" && "$(grep -c " OK$" <<<"$out")" == "4" ]] \
    && ok "clé changée : refusée pour $ip1 seulement (4 autres OK), code 1" \
    || { ko "clé changée : code $code"; echo "$out"; }

  # (d) accept-new sur un inventaire qui n'est pas marqué `lab: true` : refusé AVANT toute connexion.
  local nonlab="$JSON_DIR/c1_nonlab.yml"
  grep -v '^lab: true$' "$inv" >"$nonlab"
  out=$($NC snapshot c1_nonlab --force -i "$nonlab" --host-keys accept-new 2>&1); code=$?
  [[ "$code" == "3" && "$out" == *"lab: true"* && "$out" != *"INJOIGNABLE"* && "$out" != *" OK"* ]] \
    && ok "accept-new sur un inventaire non marqué lab : refusé, code 3, aucune connexion" \
    || { ko "accept-new hors lab : code $code"; echo "$out"; }

  # (e) accept-new sur un inventaire de lab, fichier vide : avertissement, 5 clés apprises (0600), puis strict OK.
  local fresh="$JSON_DIR/c1_fresh/known_hosts"
  rm -rf "$JSON_DIR/c1_fresh"
  out=$(NETCHECK_KNOWN_HOSTS="$fresh" $NC snapshot c1_new --force -i "$inv" --host-keys accept-new 2>&1); code=$?
  [[ "$code" == "0" && "$out" == *"Avertissement"* && "$(wc -l <"$fresh")" == "5" \
     && "$(stat -c %a "$fresh")" == "600" ]] \
    && ok "accept-new + lab: true : avertissement, 5 clés apprises, fichier 0600, code 0" \
    || { ko "accept-new + lab : code $code"; echo "$out"; }
  NETCHECK_KNOWN_HOSTS="$fresh" $NC snapshot c1_new2 --force -i "$inv" >/dev/null 2>&1 \
    && ok "les clés apprises suffisent ensuite au mode strict (code 0)" \
    || ko "le mode strict refuse les clés qu'accept-new vient d'apprendre"
  # Une clé apprise par le réseau doit être celle lue dans le conteneur (même type de clé : même contenu).
  local compared mismatched
  compared=$(awk 'NR==FNR {k[$1" "$2]=$3; next} ($1" "$2) in k {n++} END {print n+0}' "$kh" "$fresh")
  mismatched=$(awk 'NR==FNR {k[$1" "$2]=$3; next} ($1" "$2) in k && k[$1" "$2]!=$3 {n++} END {print n+0}' \
    "$kh" "$fresh")
  [[ "$compared" -ge 1 && "$mismatched" == "0" ]] \
    && ok "les clés apprises par le réseau sont celles lues dans les conteneurs ($compared comparées)" \
    || ko "clés apprises : $compared comparée(s), $mismatched différente(s) de celles des conteneurs"

  # (f) il n'existe pas de mode « ignore ».
  $NC snapshot c1_ignore --force -i "$inv" --host-keys ignore >/dev/null 2>&1; code=$?
  [[ "$code" == "2" ]] && ok "--host-keys ignore : refusé par la CLI (code 2)" || ko "--host-keys ignore : code $code"

  # (g) le ~/.ssh/known_hosts de l'utilisateur n'est jamais lu : même rempli, il ne suffit pas.
  local fake_home="$JSON_DIR/c1_home"
  rm -rf "$fake_home"; mkdir -p "$fake_home/.ssh"; cp "$kh" "$fake_home/.ssh/known_hosts"
  out=$(unset NETCHECK_KNOWN_HOSTS; HOME="$fake_home" $NC snapshot c1_home --force -i "$inv" 2>&1); code=$?
  [[ "$code" == "1" && "$(grep -c "clé d'hôte inconnue" <<<"$out")" == "5" ]] \
    && ok "le known_hosts personnel (.ssh) n'est pas lu : le fichier dédié, absent, donne un refus" \
    || { ko "known_hosts personnel : code $code"; echo "$out"; }
}
