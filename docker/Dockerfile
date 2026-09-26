# Image FRR + serveur SSH, pour que Netmiko puisse se connecter aux routeurs.
# Compte "netops" membre du groupe frrvty : il peut lancer vtysh sans être root.
# Identifiants volontairement simples : image de LAB uniquement, jamais en production.
FROM quay.io/frrouting/frr:10.2.1

RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh netops \
 && echo "netops:netops" | chpasswd \
 && addgroup netops frrvty \
 && touch /etc/frr/vtysh.conf && chmod 644 /etc/frr/vtysh.conf \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
