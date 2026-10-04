#!/bin/sh
# Point d'entrée : génère les clés d'hôte SSH manquantes, puis passe la main à l'entrée d'origine de
# l'image FRR (tini). `ssh-keygen -A` ne crée que les clés absentes : un conteneur redémarré (même
# système de fichiers) garde ses clés, un conteneur recréé (nouveau déploiement) en reçoit de nouvelles.
if ! ssh-keygen -A >/dev/null 2>&1; then
    echo "entrypoint-sshkeys: ssh-keygen -A a échoué : sshd ne pourra pas démarrer" >&2
fi
exec /sbin/tini -- "$@"
