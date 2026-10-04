"""Connexion aux équipements VIA un bastion SSH (phase C4, SPEC_v4 §6).

netcheck ouvre une session SSH vers le bastion (clé obligatoire, clé d'hôte vérifiée en strict comme celle
d'un routeur, dans le MÊME known_hosts), puis un canal `direct-tcpip` vers `routeur:port` à travers elle. Ce
canal est passé à Netmiko (`sock=`) : la session vers le routeur se déroule DANS le tunnel, la clé d'hôte du
routeur est vérifiée de bout en bout, et le routeur voit l'adresse du bastion comme source.

Ce qui n'existe pas, volontairement :
- aucun repli : si le bastion est injoignable, refuse la clé ou refuse le rebond, l'équipement est
  « injoignable » ; netcheck ne tente JAMAIS la connexion directe (le bastion est une frontière de sécurité,
  pas une commodité) ;
- ni redirection d'agent SSH, ni X11, ni session interactive : seul un canal `direct-tcpip` est demandé,
  jamais `shell`, `exec`, `auth-agent-req` ni `x11-req` (test statique à l'appui) ;
- ni mot de passe de bastion, ni agent, ni clés de ~/.ssh : seule la clé désignée est présentée.

Côté serveur le bastion se limite lui-même (compte sans shell, `restrict`, `permitopen` aux adresses de
gestion des routeurs sur le port 22) : c'est la barrière qui compte, celle-ci n'est que le client.
"""
from __future__ import annotations

import paramiko

from netcheck import hostkeys, sshkeys
from netcheck.sshkeys import Bastion

TIMEOUT = 10


class BastionError(Exception):
    """Le bastion ne peut pas servir de passerelle : message pour l'opérateur, sans secret."""


class BastionLink:
    """Une session SSH ouverte vers le bastion, d'où l'on ouvre des canaux vers les équipements."""

    def __init__(self, client: paramiko.SSHClient, spec: Bastion):
        self.client = client
        self.spec = spec

    @classmethod
    def open(cls, spec: Bastion, policy: hostkeys.HostKeyPolicy) -> BastionLink:
        hostkeys.check_file(policy.path)
        hostkeys.learn(spec.host, spec.port, policy)    # accept-new (lab) : premier contact du bastion
        pkey = sshkeys.load_private_key(spec.key, "clé du bastion")
        client = paramiko.SSHClient()
        if policy.path.is_file():
            client.load_host_keys(str(policy.path))     # le known_hosts dédié ; jamais ~/.ssh/known_hosts
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(spec.host, port=spec.port, username=spec.username, pkey=pkey,
                           look_for_keys=False, allow_agent=False, timeout=TIMEOUT,
                           banner_timeout=TIMEOUT, auth_timeout=TIMEOUT)
        except Exception as e:  # noqa: BLE001 -- traduit : jamais le texte de la bibliothèque
            client.close()
            raise _translate(e, spec, policy) from None
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(15)
        return cls(client, spec)

    def open_channel(self, host: str, port: int):
        """Un canal direct-tcpip vers host:port, ou BastionError (rebond refusé par le bastion...)."""
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise BastionError(f"bastion {self.spec.label} : session fermée")
        try:
            return transport.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=TIMEOUT)
        except paramiko.ChannelException:
            raise BastionError(f"le bastion {self.spec.label} a refusé le rebond vers {host}:{port} "
                               "(hors de sa liste permitopen)") from None
        except (paramiko.SSHException, EOFError, OSError):
            raise BastionError(
                f"rebond vers {host}:{port} impossible via le bastion {self.spec.label}") from None

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:  # noqa: BLE001 -- fermeture au mieux
            pass


def _translate(error: Exception, spec: Bastion, policy: hostkeys.HostKeyPolicy) -> Exception:
    explained = hostkeys.explain(error, spec.host, policy)
    if explained is not None:
        return hostkeys.HostKeyError(f"bastion {spec.label} : {explained}")
    if isinstance(error, paramiko.AuthenticationException):
        return BastionError(f"le bastion {spec.label} a refusé la clé {spec.key.path} (authentification par "
                            "clé seulement : ni mot de passe, ni agent)")
    if isinstance(error, (OSError, TimeoutError, EOFError)):
        return BastionError(f"bastion {spec.label} injoignable ({type(error).__name__})")
    return BastionError(f"bastion {spec.label} : échec de la connexion SSH ({type(error).__name__})")
