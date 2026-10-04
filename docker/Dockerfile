# Image FRR + serveur SSH, pour que Netmiko puisse se connecter aux routeurs.
# Compte "netops" membre du groupe frrvty : il peut lancer vtysh sans être root.
# Identifiants volontairement simples : image de LAB uniquement, jamais en production.
#
# Clés d'hôte SSH (phase C1) : elles ne sont PAS générées à la construction de l'image (tous les
# conteneurs auraient la même clé, et en compromettre un permettrait d'usurper les autres), mais au
# DÉMARRAGE de chaque conteneur, par le point d'entrée ci-dessous.
FROM quay.io/frrouting/frr:10.2.1

RUN apk add --no-cache openssh-server \
 && rm -f /etc/ssh/ssh_host_* \
 && adduser -D -s /bin/sh netops \
 && echo "netops:netops" | chpasswd \
 && addgroup netops frrvty \
 && touch /etc/frr/vtysh.conf && chmod 644 /etc/frr/vtysh.conf \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint-sshkeys.sh /usr/local/bin/entrypoint-sshkeys.sh
RUN chmod 755 /usr/local/bin/entrypoint-sshkeys.sh

# Redéfinir ENTRYPOINT efface le CMD hérité de l'image FRR : on le répète tel quel.
ENTRYPOINT ["/usr/local/bin/entrypoint-sshkeys.sh"]
CMD ["/usr/lib/frr/docker-start"]
