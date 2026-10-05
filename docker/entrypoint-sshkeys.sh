#!/bin/sh
# Point d'entrée de l'image frr-ssh : (1) génère les clés d'hôte SSH manquantes, (2) lance sshd, (3) passe la main à
# l'entrée d'origine de l'image FRR (tini). `ssh-keygen -A` ne crée que les clés absentes : un conteneur redémarré
# (même système de fichiers) garde ses clés, un conteneur recréé (nouveau déploiement) en reçoit de nouvelles.
#
# sshd est lancé ICI, jamais avant que les clés existent, et un échec arrête le conteneur (code 1, message sur
# stderr donc dans `docker logs`) : plus de conteneur vivant sans sshd, qui répondrait « Connection refused » à
# netcheck sans qu'aucun journal ne dise pourquoi (c'était possible quand containerlab lançait sshd par `exec:`
# après le démarrage, sans que personne ne regarde son code retour).
fail() {
    echo "entrypoint-sshkeys: $*" >&2
    exit 1
}

ssh-keygen -A >/dev/null 2>&1 || fail "ssh-keygen -A a échoué : pas de clés d'hôte, le conteneur s'arrête"
if [ ! -s /etc/ssh/ssh_host_ed25519_key ] || [ ! -s /etc/ssh/ssh_host_ed25519_key.pub ]; then
    fail "clé d'hôte ed25519 absente après ssh-keygen -A : le conteneur s'arrête"
fi

# sshd ne rend la main qu'une fois ses sockets d'écoute ouverts (il passe en arrière-plan après le bind) : un code 0
# veut donc dire « à l'écoute ».
/usr/sbin/sshd || fail "sshd n'a pas démarré : le conteneur s'arrête"

exec /sbin/tini -- "$@"
