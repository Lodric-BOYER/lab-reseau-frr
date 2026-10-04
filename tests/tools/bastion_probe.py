"""Sonde de lab du bastion (phase C4) : ce que le BASTION refuse, vu par un client paramiko écrit à la main.

Ce n'est pas netcheck : c'est la preuve négative faite avec les outils du lab, côté serveur. Elle essaie
tout ce
qu'un bastion de relais ne doit pas permettre et affiche une ligne « OK » ou « KO » par essai.

    python tests/tools/bastion_probe.py <bastion> <cle-privee> <known_hosts> <sous-reseau> <routeur-ip>

Code retour 0 si tout est refusé comme il se doit (et si le rebond autorisé fonctionne), 1 sinon.
"""

from __future__ import annotations

import sys

import paramiko


def main(bastion: str, key_path: str, known_hosts: str, subnet: str, router: str) -> int:
    failures = 0

    def verdict(ok: bool, what: str) -> None:
        nonlocal failures
        print(("OK " if ok else "KO ") + what)
        failures += 0 if ok else 1

    def client(**auth) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        c.load_host_keys(known_hosts)  # la clé d'hôte épinglée, jamais ~/.ssh
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        c.connect(
            bastion,
            username=auth.pop("username", "jump"),
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            **auth,
        )
        return c

    key = paramiko.Ed25519Key.from_private_key_file(key_path)

    # 1. Authentification : la clé seulement.
    try:
        client(password="un-mot-de-passe-quelconque").close()
        verdict(False, "authentification par mot de passe acceptée")
    except paramiko.AuthenticationException:
        verdict(True, "mot de passe refusé (seule la clé authentifie)")
    try:
        client(username="root", pkey=key).close()
        verdict(False, "connexion en root acceptée")
    except paramiko.AuthenticationException:
        verdict(True, "compte root refusé (AllowUsers jump)")

    # 2. Avec la bonne clé : le rebond autorisé fonctionne (contrôle positif)...
    c = client(pkey=key)
    transport = c.get_transport()
    try:
        transport.open_channel("direct-tcpip", (router, 22), ("127.0.0.1", 0), timeout=10).close()
        verdict(True, f"rebond autorisé vers {router}:22 ouvert (contrôle positif)")
    except paramiko.SSHException:
        verdict(False, f"rebond autorisé vers {router}:22 refusé")

    # 3. ... et tout autre rebond est refusé PAR LE BASTION.
    forbidden = [
        (f"{subnet}.1", 22, "passerelle du réseau de gestion"),
        (bastion, 22, "le bastion lui-même"),
        ("127.0.0.1", 22, "le bouclage du bastion"),
        ("192.0.2.1", 22, "une adresse hors lab"),
        (router, 179, "port BGP du routeur"),
        (router, 80, "port 80 du routeur"),
        (router, 2222, "autre port SSH du routeur"),
        ("172.20.20.99", 22, "adresse inconnue du lab"),
    ]
    for host, port, what in forbidden:
        try:
            transport.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=10).close()
            verdict(False, f"rebond vers {host}:{port} ({what}) ACCEPTÉ")
        except paramiko.ChannelException:
            verdict(True, f"rebond vers {host}:{port} ({what}) refusé par le bastion")
        except paramiko.SSHException as error:
            verdict(False, f"rebond vers {host}:{port} : erreur inattendue {type(error).__name__}")

    # 4. Aucune exécution : sshd ouvre le CANAL de session (c'est le protocole), mais le compte n'a pas de
    # shell
    #    (/sbin/nologin) et ForceCommand vaut /bin/false : aucune commande ne tourne. Ni terminal, ni X11, ni
    #    agent, ni redirection de port distante.
    stdin, stdout, stderr = c.exec_command("id; echo OWNED")
    output = stdout.read() + stderr.read()
    status = stdout.channel.recv_exit_status()
    verdict(
        b"uid=" not in output and b"OWNED" not in output and status != 0,
        f"commande « id; echo OWNED » : aucune exécution (code retour {status}, sortie du shell nologin)",
    )
    for what, attempt in (
        ("terminal (pty)", lambda chan: chan.get_pty()),
        ("redirection X11", lambda chan: chan.request_x11()),
    ):
        chan = transport.open_session(timeout=10)
        try:
            attempt(chan)
            verdict(False, f"{what} ACCEPTÉ")
        except (paramiko.SSHException, EOFError, OSError):
            verdict(True, f"{what} refusé")
        finally:
            chan.close()
    # Un « shell » demandé s'exécute comme la commande forcée : nologin refuse, la session se ferme.
    chan = transport.open_session(timeout=10)
    chan.settimeout(5)
    try:
        chan.invoke_shell()
        chan.send(b"echo OWNED; id\n")
        data = b""
        while True:
            part = chan.recv(4096)
            if not part:
                break
            data += part
    except (paramiko.SSHException, OSError, EOFError):
        pass
    verdict(
        b"OWNED" not in data and b"uid=" not in data and chan.recv_exit_status() != 0,
        "shell demandé : aucune commande exécutée (shell nologin, ForceCommand /bin/false), session fermée",
    )
    chan.close()
    # (La redirection d'agent ne se refuse pas côté client : paramiko l'envoie sans attendre de réponse.
    # Elle est interdite par sshd : `sshd -T` montre allowagentforwarding no ; `restrict` dans la clé.)
    try:
        transport.request_port_forward("127.0.0.1", 0)
        verdict(False, "redirection de port distante (-R) ACCEPTÉE")
    except (paramiko.SSHException, EOFError, OSError):
        verdict(True, "redirection de port distante (-R) refusée")
    c.close()
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(*sys.argv[1:]))
