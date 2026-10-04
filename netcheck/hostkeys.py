"""Vérification des clés d'hôte SSH (phase C1, SPEC_v4 §6).

Avant la phase C, netcheck laissait Netmiko à son défaut (`ssh_strict=False`, soit
`paramiko.AutoAddPolicy`) : n'importe quelle clé d'hôte était acceptée sans rien vérifier.
Maintenant :

- **strict (défaut)** : la clé de l'équipement doit figurer dans un fichier `known_hosts` DÉDIÉ
  (`~/.netcheck/known_hosts`, ou `--known-hosts` / `NETCHECK_KNOWN_HOSTS`). Le `~/.ssh/known_hosts`
  de l'utilisateur n'est jamais lu. Une clé inconnue ou changée est refusée.
- **accept-new** : le premier contact enregistre la clé, puis la connexion se fait quand même en
  mode strict. Une clé CHANGÉE reste refusée. Réservé au lab : refusé si l'inventaire n'est pas
  marqué `lab: true`.

Il n'existe aucun mode « ignorer » : aucun chemin de code n'accepte une clé sans la comparer à une
entrée connue (test statique à l'appui).
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import threading
from dataclasses import dataclass
from pathlib import Path

import paramiko

MODES = ("strict", "accept-new")
DEFAULT_MODE = "strict"
ENV_MODE = "NETCHECK_HOST_KEYS"
ENV_KNOWN_HOSTS = "NETCHECK_KNOWN_HOSTS"
CONNECT_TIMEOUT = 10


class HostKeyError(Exception):
    """Clé d'hôte inconnue, changée, ou mode non autorisé : message destiné à l'opérateur."""


def default_known_hosts() -> Path:
    return Path.home() / ".netcheck" / "known_hosts"


@dataclass(frozen=True)
class HostKeyPolicy:
    mode: str = DEFAULT_MODE
    known_hosts: Path | None = None
    lab: bool = False   # l'inventaire est marqué `lab: true` (seul cas où accept-new est permis)

    @property
    def path(self) -> Path:
        return self.known_hosts or default_known_hosts()


def configure(mode: str | None, known_hosts: str | None, lab: bool,
              environ: dict | None = None) -> HostKeyPolicy:
    """Ordre : option de la CLI, puis variable d'environnement, puis défaut (strict). Lève
    HostKeyError pour un mode inconnu ou pour accept-new sur un inventaire non marqué lab."""
    env = os.environ if environ is None else environ
    mode = mode or env.get(ENV_MODE) or DEFAULT_MODE
    if mode not in MODES:
        raise HostKeyError(f"mode de clés d'hôte inconnu : {mode!r} (valeurs : {', '.join(MODES)})")
    raw_path = known_hosts or env.get(ENV_KNOWN_HOSTS)
    if mode == "accept-new" and not lab:
        raise HostKeyError(
            "--host-keys accept-new est réservé au lab : l'inventaire doit déclarer `lab: true`. "
            "Sinon épinglez les clés de vos équipements (voir « Migration » du README).")
    return HostKeyPolicy(mode=mode, known_hosts=Path(raw_path).expanduser() if raw_path else None, lab=lab)


# Politique du processus : posée une fois par la CLI, lue par le collecteur (qui tourne en threads).
_policy: HostKeyPolicy | None = None


def set_policy(policy: HostKeyPolicy | None) -> None:
    global _policy
    _policy = policy


def current() -> HostKeyPolicy:
    """Sans configuration explicite : strict, fichier dédié par défaut (jamais accept-new par
    simple variable d'environnement hors de la CLI, qui seule connaît `lab`)."""
    if _policy is not None:
        return _policy
    env_mode = os.environ.get(ENV_MODE)
    mode = env_mode if env_mode in MODES else DEFAULT_MODE
    raw_path = os.environ.get(ENV_KNOWN_HOSTS)
    return HostKeyPolicy(mode=mode, known_hosts=Path(raw_path).expanduser() if raw_path else None)


def entry_name(host: str, port: int = 22) -> str:
    """Nom d'une entrée known_hosts, comme OpenSSH et Paramiko : `host`, ou `[host]:port`."""
    return host if port == 22 else f"[{host}]:{port}"


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def check_file(path: Path) -> None:
    """Un known_hosts modifiable par d'autres comptes permettrait d'y injecter une clé : refusé."""
    if os.name == "nt" or not path.exists():
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o022:
        raise HostKeyError(
            f"{path} est modifiable par d'autres comptes (droits {mode:o}) : refusé. "
            f"Corrigez avec : chmod 600 {path}")


def preflight(policy: HostKeyPolicy) -> None:
    """Avant toute connexion : un known_hosts qui EXISTE mais est inutilisable (dossier, droits trop
    larges) est une erreur de configuration, pas une panne de chaque équipement. Un fichier absent reste un
    refus par équipement (clé inconnue) : c'est aussi le cas normal d'un premier contact en accept-new."""
    path = policy.path
    if path.is_dir():
        raise HostKeyError(f"{path} est un dossier : un fichier known_hosts est attendu")
    check_file(path)


_lock = threading.Lock()


def _is_known(path: Path, name: str) -> bool:
    hk = paramiko.HostKeys()
    if path.is_file():
        hk.load(str(path))
    return hk.lookup(name) is not None


def _fetch_server_key(host: str, port: int, opener=None) -> paramiko.PKey:
    """Lit la clé d'hôte annoncée par le serveur, sans s'authentifier. `opener(host, port)` (phase C4) donne
    un canal ouvert VIA le bastion : le premier contact d'un routeur ne doit jamais se faire en direct."""
    try:
        if opener:
            sock = opener(host, port)
        else:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except OSError as e:
        raise HostKeyError(f"{host}:{port} injoignable pour lire sa clé d'hôte : {e}") from None
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=CONNECT_TIMEOUT)
        return transport.get_remote_server_key()
    except paramiko.SSHException as e:
        raise HostKeyError(f"{host}:{port} : échange de clés impossible ({e})") from None
    finally:
        transport.close()


def learn(host: str, port: int, policy: HostKeyPolicy, opener=None) -> bool:
    """Mode accept-new : enregistre la clé d'un hôte INCONNU (premier contact). Renvoie True si une
    entrée a été écrite. Un hôte déjà connu n'est pas recontacté ici : la connexion stricte qui
    suit le vérifie, et refuse une clé changée. Sans effet en mode strict."""
    if policy.mode != "accept-new":
        return False
    if not policy.lab:   # défense en profondeur : la CLI refuse déjà ce cas avant toute collecte
        raise HostKeyError("accept-new n'est permis que sur un inventaire marqué `lab: true`")
    path, name = policy.path, entry_name(host, port)
    check_file(path)
    if _is_known(path, name):
        return False
    key = _fetch_server_key(host, port, opener)
    with _lock:
        if _is_known(path, name):   # un autre thread l'a enregistré entre-temps
            return False
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        prefix = ""
        if path.is_file() and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
            prefix = "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{prefix}{name} {key.get_name()} {key.get_base64()}\n")
    return True


def explain(error: Exception, host: str, policy: HostKeyPolicy) -> str | None:
    """Message clair pour un refus de clé d'hôte ; None si l'erreur n'en est pas un. Netmiko enveloppe
    l'exception de Paramiko dans une NetmikoTimeoutException : on remonte la chaîne des causes."""
    chain, seen = error, set()
    while chain is not None and id(chain) not in seen:
        seen.add(id(chain))
        if isinstance(chain, paramiko.BadHostKeyException):
            return (f"clé d'hôte CHANGÉE pour {host} : annoncée {fingerprint(chain.key)}, attendue "
                    f"{fingerprint(chain.expected_key)} ({policy.path}). Connexion refusée : si le "
                    "changement est légitime (équipement réinstallé), réépinglez la clé après "
                    "l'avoir vérifiée.")
        chain = chain.__cause__ or chain.__context__
    if "not found in known_hosts" in str(error):
        where = f"absent de {policy.path}" if policy.path.is_file() else f"fichier {policy.path} absent"
        return (f"clé d'hôte inconnue pour {host} : {where}. Épinglez-la (voir « Migration » du README) ; "
                "sur un lab, l'inventaire `lab: true` permet --host-keys accept-new au premier contact.")
    return None
