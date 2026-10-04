#!/bin/sh
# Point d'entrée du bastion : génère la clé d'hôte ed25519 si elle manque (un conteneur recréé en reçoit une
# nouvelle, un conteneur redémarré garde la sienne), puis lance sshd au premier plan, journal sur stderr
# (`docker logs`) : les rebonds refusés y sont écrits (LogLevel VERBOSE).
if [ ! -s /etc/ssh/ssh_host_ed25519_key ]; then
    if ! ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key; then
        echo "entrypoint-bastion: génération de la clé d'hôte impossible : sshd ne pourra pas démarrer" >&2
    fi
fi
exec /usr/sbin/sshd -D -e
