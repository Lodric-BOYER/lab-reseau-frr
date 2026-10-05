"""Aides communes des scripts NetBox du LAB (lab-access/netbox/) : jamais importées par netcheck/.

- lecture du `.env` de netbox-docker (0600 exigé ; les valeurs ne sont jamais affichées) ;
- jeton d'ADMINISTRATION éphémère : obtenu avec le superutilisateur du lab, valable une heure, supprimé
  en fin de session ;
- jeton en LECTURE SEULE de netcheck : fichier 0600 hors dépôt.

Rien ici ne parle à un autre NetBox que celui du lab (adresse de bouclage par défaut). Aucun secret
n'est affiché : un message d'erreur ne cite jamais un mot de passe, un jeton ni le corps d'une réponse
d'authentification."""

from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import requests

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_ENV_FILE = Path(os.environ.get("NETBOX_DOCKER_DIR", str(Path.home() / "netbox-docker"))) / ".env"
DEFAULT_TOKEN_FILE = Path.home() / ".config" / "netcheck" / "netbox-ro.token"
RO_USER = "netcheck-ro"
LAB_SITES = {"frr": "lab-frr", "multivendor": "lab-multivendor", "ceos": "lab-ceos"}
ADMIN_TOKEN_LIFETIME = dt.timedelta(hours=1)


def fail(message: str) -> None:
    raise SystemExit(f"erreur : {message}")


def read_env(path: Path | str = DEFAULT_ENV_FILE) -> dict[str, str]:
    path = Path(path)
    if not path.is_file():
        fail(f"{path} introuvable : lancez d'abord « bash lab-access/netbox/netbox_lab.sh up »")
    mode = path.stat().st_mode & 0o777
    if mode not in (0o600, 0o400):
        fail(f"{path} : droits {oct(mode)} (0600 ou 0400 attendus)")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.startswith("#"):
            values[key.strip()] = value
    for needed in ("NB_SUPERUSER_NAME", "NB_SUPERUSER_PASSWORD"):
        if not values.get(needed):
            fail(f"{path} : {needed} manque")
    return values


def new_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = (
        False  # ni proxy d'environnement ni netrc : le jeton ne sort que vers l'adresse donnée
    )
    session.headers["Accept"] = "application/json"
    return session


def bearer_from(reply: dict) -> str:
    """Le jeton v2 complet `nbt_<clé>.<secret>` d'une réponse de création de jeton."""
    token = reply.get("token")
    if isinstance(token, str) and token.startswith("nbt_"):
        return token
    key = reply.get("key")
    if isinstance(key, str) and isinstance(token, str) and token:
        return f"nbt_{key}.{token}"
    fail("la réponse de NetBox ne contient pas de jeton v2 exploitable (forme inattendue)")
    raise AssertionError("inatteignable")


def write_token_file(path: Path | str, token: str) -> None:
    """Fichier 0600, remplacé atomiquement. Un dossier CRÉÉ ici est en 0700 ; un dossier qui existait
    déjà (par exemple /tmp) garde ses droits : ce n'est pas à ce script de les changer. Jamais d'affichage."""
    path = Path(path)
    missing = [p for p in reversed(path.parents) if not p.exists()]
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for created in missing:
        os.chmod(created, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


class Admin:
    """Session d'administration éphémère : un jeton v2 obtenu avec le superutilisateur du lab,
    supprimé à la sortie."""

    def __init__(self, base: str = DEFAULT_URL, env_file: Path | str = DEFAULT_ENV_FILE):
        self.base = base.rstrip("/")
        self.env = read_env(env_file)
        self.session = new_session()
        self.token = ""
        self.token_id: int | None = None

    def __enter__(self) -> Admin:
        expires = (dt.datetime.now(dt.timezone.utc) + ADMIN_TOKEN_LIFETIME).strftime("%Y-%m-%dT%H:%M:%SZ")
        reply = self.session.post(
            f"{self.base}/api/users/tokens/provision/",
            json={
                "username": self.env["NB_SUPERUSER_NAME"],
                "password": self.env["NB_SUPERUSER_PASSWORD"],
                "description": "chargement du lab (éphémère)",
                "expires": expires,
                "write_enabled": True,
            },
            timeout=30,
        )
        if reply.status_code not in (200, 201):
            fail(
                "le jeton d'administration n'a pas pu être obtenu "
                f"(HTTP {reply.status_code}) : NetBox est-il prêt ?"
            )
        body = reply.json()
        self.token, self.token_id = bearer_from(body), body.get("id")
        self.session.headers["Authorization"] = f"Bearer {self.token}"
        return self

    def __exit__(self, *_exc) -> None:
        if self.token_id is not None:
            answer = self.session.delete(f"{self.base}/api/users/tokens/{self.token_id}/", timeout=30)
            if answer.status_code not in (200, 204):
                print(
                    f"avertissement : le jeton d'administration éphémère n'a pas pu être supprimé "
                    f"(HTTP {answer.status_code}) ; il expire dans {ADMIN_TOKEN_LIFETIME}",
                    file=sys.stderr,
                )
        self.session.headers.pop("Authorization", None)

    def call(self, method: str, path: str, **kwargs) -> requests.Response:
        return self.session.request(method, f"{self.base}{path}", timeout=60, **kwargs)

    def json(self, path: str, **kwargs) -> dict:
        reply = self.call("GET", path, **kwargs)
        if reply.status_code != 200:
            fail(f"GET {path} : HTTP {reply.status_code}")
        return reply.json()
