"""Authentification SSH par clé et bastion (phase C4, SPEC_v4 §6).

Une clé privée est un secret : le fichier suit les MÊMES règles que les mots de passe de C2 (fichier
régulier, pas un lien symbolique, à l'utilisateur courant, droits 0600 ou 0400, taille bornée), et sa phrase
secrète éventuelle est un `SecretStr` (jamais en argument de ligne de commande, jamais affichée). La source
affichée est « clé : <chemin> », jamais le contenu.

Clé d'un équipement, par ordre de priorité :
    NETCHECK_<DRIVER>_KEY_FILE, NETCHECK_KEY_FILE (variables), puis `key_file` de l'inventaire.
Phrase secrète (la clé peut ne pas en avoir) : NETCHECK_<DRIVER>_KEY_PASSPHRASE, puis son `_FILE` (fichier
0600), puis NETCHECK_KEY_PASSPHRASE, puis son `_FILE`. Quand une clé est configurée pour un équipement, c'est
SON mode d'authentification : le mot de passe n'est ni résolu ni présenté, jamais en repli.

Bastion (bloc `bastion:` de l'inventaire : host, port, username, key_file) : clé obligatoire (jamais de mot
de passe), NETCHECK_BASTION_KEY_FILE la remplace, NETCHECK_BASTION_KEY_PASSPHRASE[_FILE] pour sa phrase
secrète.

La clé est chargée par netcheck (paramiko) et présentée comme `pkey` : seule cette clé est offerte, ni
l'agent SSH ni les clés de ~/.ssh (Netmiko, avec `key_file`, laisserait paramiko essayer aussi `~/.ssh/id_*`).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from netcheck.credentials import CredentialError, check_private_file, read_secret_file
from netcheck.secrets import SecretStr

MAX_KEY_BYTES = 65536
DEFAULT_BASTION_PORT = 22
BASTION_KEYS = ("host", "port", "username", "key_file")


@dataclass(frozen=True, eq=False)
class KeySpec:
    path: str
    passphrase: SecretStr | None


@dataclass(frozen=True, eq=False)
class Bastion:
    host: str
    port: int
    username: str
    key: KeySpec

    @property
    def label(self) -> str:
        suffix = f":{self.port}" if self.port != DEFAULT_BASTION_PORT else ""
        return f"{self.username}@{self.host}{suffix}"


def _key_path(variables: list[str], inventory_value: str | None, environ: dict) -> str | None:
    for var in variables:
        raw = environ.get(var)
        if raw:
            return str(Path(raw).expanduser())
    return str(Path(inventory_value).expanduser()) if inventory_value else None


def _passphrase(variables: list[tuple[str, str]], environ: dict, who: str) -> SecretStr | None:
    for kind, var in variables:
        raw = environ.get(var)
        if not raw:
            continue
        if kind == "env":
            return SecretStr(raw, f"variable {var}")
        return SecretStr(read_secret_file(raw, f"{var} ({who})"), f"fichier {Path(raw).expanduser()}")
    return None


def load_private_key(spec: KeySpec, what: str):
    """La clé chargée (paramiko), ou CredentialError sans jamais citer le contenu ni le texte de la
    bibliothèque."""
    import paramiko
    passphrase = spec.passphrase.reveal() if spec.passphrase else None
    # `PKey.from_path` n'est pas utilisable : en paramiko 5 il passe la phrase secrète en `str` à
    # cryptography, qui exige des octets (TypeError), et son argument a changé de nom (`passphrase` puis
    # `password`). On essaie donc chaque type de clé par `from_private_key_file(chemin, phrase_secrète)`,
    # stable d'une version à l'autre.
    needs_passphrase = False
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key_file(spec.path, passphrase)
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except Exception:  # noqa: BLE001 -- jamais le texte de l'exception : il peut citer du contenu
            continue                                       # autre type de clé (ou phrase secrète incorrecte)
    if needs_passphrase and passphrase is None:
        raise CredentialError(f"{what} : la clé {spec.path} est protégée par une phrase secrète : donnez-la "
                              "par NETCHECK_KEY_PASSPHRASE_FILE (fichier 0600)")
    hint = " (phrase secrète incorrecte ?)" if passphrase is not None else ""
    raise CredentialError(f"{what} : la clé {spec.path} est illisible ou invalide{hint}")


def resolve_key(driver: str, inventory_key_file: str | None, device: str, environ: dict) -> KeySpec | None:
    """La clé de l'équipement (fichier contrôlé, chargée une fois pour valider), ou None : mot de passe."""
    d = driver.upper()
    path = _key_path([f"NETCHECK_{d}_KEY_FILE", "NETCHECK_KEY_FILE"], inventory_key_file, environ)
    if path is None:
        return None
    check_private_file(path, f"clé de {device}", MAX_KEY_BYTES)
    passphrase = _passphrase(
        [("env", f"NETCHECK_{d}_KEY_PASSPHRASE"), ("file", f"NETCHECK_{d}_KEY_PASSPHRASE_FILE"),
         ("env", "NETCHECK_KEY_PASSPHRASE"), ("file", "NETCHECK_KEY_PASSPHRASE_FILE")], environ, device)
    spec = KeySpec(path, passphrase)
    load_private_key(spec, f"clé de {device}")
    return spec


def resolve_bastion(spec: dict, environ: dict) -> Bastion:
    """Le bastion décrit par le bloc `bastion:` de l'inventaire (structure déjà validée par l'inventaire)."""
    path = _key_path(["NETCHECK_BASTION_KEY_FILE"], spec.get("key_file"), environ)
    if path is None:
        raise CredentialError("bastion : aucune clé (key_file dans l'inventaire ou "
                              "NETCHECK_BASTION_KEY_FILE) ; le bastion n'accepte jamais de mot de passe")
    check_private_file(path, "clé du bastion", MAX_KEY_BYTES)
    passphrase = _passphrase([("env", "NETCHECK_BASTION_KEY_PASSPHRASE"),
                              ("file", "NETCHECK_BASTION_KEY_PASSPHRASE_FILE")], environ, "bastion")
    key = KeySpec(path, passphrase)
    load_private_key(key, "clé du bastion")
    return Bastion(host=spec["host"], port=spec.get("port", DEFAULT_BASTION_PORT),
                   username=spec["username"], key=key)
