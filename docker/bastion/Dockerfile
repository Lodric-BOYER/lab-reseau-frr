# Bastion SSH de LAB pour netcheck (phase C4) : un sshd qui ne fait QUE relayer des connexions vers les adresses
# de gestion des routeurs, port 22. Pas de shell, pas de mot de passe, pas d'agent, pas de X11.
#
#   docker build -t netcheck-bastion:1 docker/bastion/
#
# Compte « jump » : shell /sbin/nologin, verrouillé pour les mots de passe (`*`, pas `!` : sshd refuse un compte
# verrouillé même pour une clé), clé publique dans /etc/ssh/authorized_keys/jump (propriété de root : le compte ne
# peut pas la modifier). La liste `PermitOpen` et la clé sont posées APRÈS le déploiement par
# lab-access/bastion_lab.sh ; tant qu'elles ne le sont pas, le bastion ne relaie rien (`PermitOpen none`).
# La clé d'hôte est générée au DÉMARRAGE du conteneur (comme celles des routeurs : voir docker/Dockerfile).
FROM alpine:3.20.3

RUN apk add --no-cache openssh-server \
 && rm -f /etc/ssh/ssh_host_* \
 && adduser -D -s /sbin/nologin jump \
 && sed -i 's/^jump:!:/jump:*:/' /etc/shadow \
 && mkdir -p /etc/ssh/authorized_keys /etc/ssh/sshd_config.d \
 && : > /etc/ssh/authorized_keys/jump \
 && echo 'PermitOpen none' > /etc/ssh/sshd_config.d/10-permitopen.conf \
 && chmod 755 /etc/ssh/authorized_keys /etc/ssh/sshd_config.d \
 && chmod 644 /etc/ssh/authorized_keys/jump /etc/ssh/sshd_config.d/10-permitopen.conf

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 644 /etc/ssh/sshd_config && chmod 755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
