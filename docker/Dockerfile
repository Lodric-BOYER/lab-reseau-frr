# Image FRR + serveur SSH, pour que Netmiko puisse se connecter aux routeurs.
# Compte "netops" membre du groupe frrvty : il peut lancer vtysh sans être root.
# Identifiants volontairement simples : image de LAB uniquement, jamais en production.
#
# Clés d'hôte SSH (phase C1) : elles ne sont PAS générées à la construction de l'image (tous les
# conteneurs auraient la même clé, et en compromettre un permettrait d'usurper les autres), mais au
# DÉMARRAGE de chaque conteneur, par le point d'entrée ci-dessous, qui lance ensuite sshd (et arrête le
# conteneur si les clés ou sshd manquent). HEALTHCHECK : si sshd meurt plus tard, `docker ps` le montre
# (« unhealthy ») au lieu de laisser un conteneur qui répond « Connection refused ».
#
# Compte en LECTURE SEULE « netcheck-ro » (phase C5) : vtysh n'a pas de RBAC (qui atteint ses sockets, frr:frrvty,
# a tout). Le compte n'est donc PAS dans frrvty ; `doas` (docker/doas.conf, arguments exacts, « as frr », sans
# keepenv) lui donne l'identité frr pour les dix commandes de netcheck et rien d'autre. Mot de passe « * » (pas
# « ! » : sshd refuse un compte verrouillé), authentification par clé seulement (bloc Match de sshd). La clé
# publique n'est PAS dans l'image : lab-access/accounts_lab.sh l'installe après chaque déploiement.
# Limite assumée : il garde un shell non privilégié (lecture des fichiers lisibles par tous, rebond réseau).
FROM quay.io/frrouting/frr:10.2.1

RUN apk add --no-cache openssh-server doas \
 && rm -f /etc/ssh/ssh_host_* \
 && adduser -D -s /bin/sh netops \
 && echo "netops:netops" | chpasswd \
 && addgroup netops frrvty \
 && adduser -D -s /bin/sh netcheck-ro \
 && sed -i 's/^netcheck-ro:!:/netcheck-ro:*:/' /etc/shadow \
 && mkdir -p /home/netcheck-ro/.ssh \
 && chown root:root /home/netcheck-ro/.ssh && chmod 755 /home/netcheck-ro/.ssh \
 && touch /etc/frr/vtysh.conf && chmod 644 /etc/frr/vtysh.conf \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY doas.conf /etc/doas.conf
COPY sshd_netcheck_ro.conf /etc/ssh/sshd_config.d/10-netcheck-ro.conf
RUN chown root:root /etc/doas.conf && chmod 640 /etc/doas.conf \
 && chmod 644 /etc/ssh/sshd_config.d/10-netcheck-ro.conf

COPY entrypoint-sshkeys.sh /usr/local/bin/entrypoint-sshkeys.sh
RUN chmod 755 /usr/local/bin/entrypoint-sshkeys.sh

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=2 \
  CMD ss -ltn | grep -q ':22 ' || exit 1

# Redéfinir ENTRYPOINT efface le CMD hérité de l'image FRR : on le répète tel quel.
ENTRYPOINT ["/usr/local/bin/entrypoint-sshkeys.sh"]
CMD ["/usr/lib/frr/docker-start"]
