"""Fournisseur de secrets HashiCorp Vault / OpenBao (phase C3, SPEC_v4 §6, C20).

netcheck LIT des identifiants dans Vault ; il n'y écrit jamais. Exactement deux appels réseau existent :

    POST /v1/auth/approle/login              (la seule écriture : ouvrir une session, rien n'est modifié)
    GET  /v1/<montage>/data/<chemin>         (KV v2, le seul chemin configuré)

Ils sont imposés par une liste blanche EXACTE posée dans l'adaptateur HTTP de `hvac` : tout autre appel (une
écriture sur un secret, une lecture ailleurs, un `sys/...`) lève avant d'envoyer quoi que ce soit.

Configuration, uniquement par l'environnement (aucun secret en argument de ligne de commande : `ps` le voit) :

    NETCHECK_VAULT_ADDR             https://hote:8200 ; http:// seulement pour le bouclage (127.0.0.0/8, ::1,
                                    localhost). Sans cette variable, Vault est désactivé.
    NETCHECK_VAULT_ROLE_ID          identifiant du rôle AppRole (non secret)
    NETCHECK_VAULT_SECRET_ID_FILE   fichier du secret_id : mêmes règles que les mots de passe de C2 (une
                                    ligne, droits 0600 ou 0400, propriétaire courant, pas de lien symbolique)
    NETCHECK_VAULT_PATH             chemin du secret KV v2 (ex. netcheck/lab)
    NETCHECK_VAULT_MOUNT            montage KV v2 (défaut : secret)
    NETCHECK_VAULT_CACERT           autorité de certification (optionnel ; TLS ne se désactive pas)

Le secret contient des clés texte `username` / `password`, et éventuellement `<driver>_username` /
`<driver>_password` (ex. `srlinux_password`) qui passent avant les clés génériques. Une clé absente laisse
la main au niveau suivant, comme une variable non définie ; en revanche Vault injoignable, authentification
refusée, secret introuvable ou lecture refusée sont des ERREURS (code 3) : jamais de repli silencieux sur
`LAB_PASS` ou sur l'inventaire. Le jeton est un `SecretStr` inscrit dans le registre d'expurgation ; le
`secret_id` aussi. Aucune redirection n'est suivie et les variables de proxy de l'environnement sont
ignorées : le jeton ne sort que vers l'adresse configurée.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from netcheck.credentials import CredentialError, Source, read_secret_file
from netcheck.secrets import SecretStr

ENV_ADDR = "NETCHECK_VAULT_ADDR"
ENV_ROLE_ID = "NETCHECK_VAULT_ROLE_ID"
ENV_SECRET_ID_FILE = "NETCHECK_VAULT_SECRET_ID_FILE"
ENV_PATH = "NETCHECK_VAULT_PATH"
ENV_MOUNT = "NETCHECK_VAULT_MOUNT"
ENV_CACERT = "NETCHECK_VAULT_CACERT"
DEFAULT_MOUNT = "secret"
LOGIN_PATH = "/v1/auth/approle/login"
TIMEOUT = 5          # secondes, connexion et lecture
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*")
_LOOPBACK_NAMES = {"localhost"}


class VaultError(CredentialError):
    """Vault ne peut pas fournir les identifiants : message pour l'opérateur, jamais un secret."""


class VaultCallRefused(PermissionError):
    """Un appel hors liste blanche a été demandé : c'est un défaut de netcheck, pas une erreur d'usage."""


@dataclass(frozen=True)
class VaultConfig:
    addr: str
    role_id: str
    secret_id_file: str
    path: str
    mount: str = DEFAULT_MOUNT
    cacert: str | None = None

    @property
    def label(self) -> str:
        return f"({self.mount}/{self.path})"

    @property
    def read_path(self) -> str:
        return f"/v1/{self.mount}/data/{self.path}"


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_addr(addr: str) -> str:
    parts = urllib.parse.urlsplit(addr)
    try:
        host, _port = parts.hostname, parts.port
    except ValueError:
        host = None
    if parts.scheme not in ("http", "https") or not host:
        raise VaultError(f"{ENV_ADDR} : adresse invalide (https://hôte:port attendu)")
    if parts.username or parts.password:
        raise VaultError(f"{ENV_ADDR} : des identifiants dans l'adresse sont refusés")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise VaultError(f"{ENV_ADDR} : l'adresse ne doit contenir ni chemin ni paramètre")
    if parts.scheme == "http" and not _is_loopback(host):
        raise VaultError(f"{ENV_ADDR} : http:// n'est accepté que pour le bouclage (127.0.0.1, ::1, "
                         "localhost) ; utilisez https:// pour un autre hôte")
    return f"{parts.scheme}://{parts.netloc}"


def from_environment(environ: dict) -> VaultConfig | None:
    """None si Vault n'est pas configuré (NETCHECK_VAULT_ADDR absent ou vide). Sinon la configuration
    complète, ou VaultError qui nomme ce qui manque ou ce qui est refusé."""
    addr = environ.get(ENV_ADDR)
    if not addr:
        return None
    addr = _check_addr(addr)
    missing = [var for var in (ENV_ROLE_ID, ENV_SECRET_ID_FILE, ENV_PATH) if not environ.get(var)]
    if missing:
        raise VaultError(f"Vault est configuré ({ENV_ADDR}) mais il manque : {', '.join(missing)}")
    mount = environ.get(ENV_MOUNT) or DEFAULT_MOUNT
    path = environ[ENV_PATH]
    for label, value in ((ENV_MOUNT, mount), (ENV_PATH, path)):
        if not _NAME.fullmatch(value):   # un segment ne commence ni par « . » ni par « / » : pas de « .. »
            raise VaultError(f"{label} : nom invalide (lettres, chiffres, « . », « - », « _ » et « / » ; "
                             "ni « .. » ni « / » en tête ou en fin)")
    cacert = environ.get(ENV_CACERT) or None
    if cacert and not Path(cacert).expanduser().is_file():
        raise VaultError(f"{ENV_CACERT} : fichier introuvable")
    return VaultConfig(addr=addr, role_id=environ[ENV_ROLE_ID], secret_id_file=environ[ENV_SECRET_ID_FILE],
                       path=path, mount=mount, cacert=str(Path(cacert).expanduser()) if cacert else None)


def allowed_calls(config: VaultConfig) -> frozenset[tuple[str, str]]:
    """Les deux seuls appels que netcheck peut faire, (méthode, chemin) EXACTS."""
    return frozenset({("POST", LOGIN_PATH), ("GET", config.read_path)})


def _import_hvac():
    try:
        import hvac
        import requests
    except ImportError:
        raise VaultError("Vault demande la bibliothèque hvac (extra optionnel) : "
                         "pip install 'netcheck[vault]'") from None
    return hvac, requests


def build_client(config: VaultConfig, hvac=None, requests=None):
    """Client hvac dont l'adaptateur n'envoie QUE les appels de `allowed_calls` ; pas de redirection, pas de
    proxy d'environnement, vérification TLS toujours active."""
    if hvac is None:
        hvac, requests = _import_hvac()
    allowed = allowed_calls(config)

    class GuardedAdapter(hvac.adapters.JSONAdapter):
        def request(self, method, url, *args, **kwargs):
            if (str(method).upper(), url) not in allowed:
                raise VaultCallRefused(f"appel Vault hors liste blanche refusé : {str(method).upper()} {url}")
            return super().request(method, url, *args, **kwargs)

    session = requests.Session()
    session.trust_env = False
    # hvac IGNORE son paramètre `verify` quand on lui donne une session : la vérification TLS (et l'autorité
    # donnée) se règle donc ici. Jamais False.
    session.verify = config.cacert or True
    return hvac.Client(url=config.addr, timeout=TIMEOUT, session=session, allow_redirects=False,
                       adapter=GuardedAdapter)


_cache: dict[VaultConfig, dict] = {}


def forget_cache() -> None:
    _cache.clear()


def _login(client, config: VaultConfig, hvac, requests) -> SecretStr:
    secret_id = SecretStr(read_secret_file(config.secret_id_file, ENV_SECRET_ID_FILE), "Vault")
    try:
        reply = client.auth.approle.login(role_id=config.role_id, secret_id=secret_id.reveal(),
                                          use_token=False)
        return SecretStr(reply["auth"]["client_token"], "Vault")
    except (hvac.exceptions.InvalidRequest, hvac.exceptions.Forbidden, hvac.exceptions.Unauthorized):
        raise VaultError(f"Vault a refusé l'authentification AppRole (rôle ou secret_id invalide, expiré ou "
                         f"consommé) : {config.addr}") from None
    except (KeyError, TypeError):
        raise VaultError(f"Vault : réponse d'authentification inattendue ({config.addr})") from None
    except Exception as e:  # noqa: BLE001 -- traduit ci-dessous : jamais le texte de la bibliothèque
        raise _translate(e, config, hvac, requests, "authentification") from None


def _read(client, config: VaultConfig, token: SecretStr, hvac, requests) -> dict:
    client.token = token.reveal()
    try:
        reply = client.secrets.kv.v2.read_secret_version(path=config.path, mount_point=config.mount,
                                                         raise_on_deleted_version=True)
        data = reply["data"]["data"]
    except hvac.exceptions.Forbidden:
        raise VaultError(f"Vault a refusé la lecture de {config.label} : la politique du rôle ne "
                         "l'autorise pas") from None
    except hvac.exceptions.InvalidPath:
        raise VaultError(f"Vault : secret introuvable {config.label} (montage KV v2 ? chemin ?)") from None
    except (KeyError, TypeError):
        raise VaultError(f"Vault : {config.label} n'est pas un secret KV v2 lisible") from None
    except Exception as e:  # noqa: BLE001
        raise _translate(e, config, hvac, requests, "lecture") from None
    if not isinstance(data, dict):
        raise VaultError(f"Vault : {config.label} ne contient pas d'objet clé/valeur")
    return data


def _translate(error: Exception, config: VaultConfig, hvac, requests, phase: str) -> Exception:
    """Message clair par famille d'erreur, sans jamais reprendre le texte de la bibliothèque."""
    if isinstance(error, VaultCallRefused):
        return error
    if isinstance(error, requests.exceptions.SSLError):
        return VaultError(f"Vault : certificat TLS refusé ({config.addr}) ; autorité : {ENV_CACERT}")
    if isinstance(error, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return VaultError(f"Vault injoignable ({config.addr}, pendant {phase})")
    if isinstance(error, (hvac.exceptions.VaultDown, hvac.exceptions.InternalServerError)):
        return VaultError(f"Vault indisponible ou scellé ({config.addr}, pendant {phase})")
    return VaultError(f"Vault : erreur pendant {phase} ({type(error).__name__}, {config.addr})")


def secret_document(config: VaultConfig) -> dict:
    """Le contenu du secret, lu une seule fois par processus (deux appels réseau au total)."""
    if config in _cache:
        return _cache[config]
    hvac, requests = _import_hvac()
    client = build_client(config, hvac, requests)
    token = _login(client, config, hvac, requests)
    document = _read(client, config, token, hvac, requests)
    client.token = None
    _cache[config] = document
    return document


def lookup(kind: str, driver: str, environ: dict) -> tuple[str, Source] | None:
    """(valeur, source) pour « USER » ou « PASS », ou None si Vault est désactivé ou n'a pas cette clé."""
    config = from_environment(environ)
    if config is None:
        return None
    document = secret_document(config)
    base = "username" if kind == "USER" else "password"
    for key in (f"{driver.lower()}_{base}", base):
        if key in document:
            value = document[key]
            if not isinstance(value, str) or not value:
                raise VaultError(f"Vault : la clé « {key} » de {config.label} doit être un texte non vide")
            return value, Source("Vault", config.label)
    return None
