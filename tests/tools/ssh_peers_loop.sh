#!/bin/sh
# Lu par `sh` DANS un routeur (docker exec -i ... timeout N sh < ce-fichier) : affiche en boucle l'adresse DISTANTE
# de chaque session TCP entrante sur le port 22. Sert à prouver d'où le routeur voit arriver netcheck : l'adresse
# du bastion, ou celle de la passerelle du réseau de gestion (connexion directe).
while :; do
  ss -tn | awk '$4 ~ /:22$/ { sub(/:[0-9]+$/, "", $5); print $5 }'
done
