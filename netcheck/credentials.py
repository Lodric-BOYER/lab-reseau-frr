"""Résolution des identifiants d'accès aux équipements (phase C2, SPEC_v4 §6).

Un identifiant peut venir de quatre endroits. Ordre de priorité, du plus spécifique au moins spécifique, et à
spécificité égale une variable avant un fichier :

  1. NETCHECK_<DRIVER>_USER / _PASS             variable d'environnement, ce driver seulement
  2. NETCHECK_<DRIVER>_USER_FILE / _PASS_FILE   fichier 0600 contenant la valeur
  3. NETCHECK_USER / NETCHECK_PASS              variable, tous les drivers
  4. NETCHECK_USER_FILE / NETCHECK_PASS_FILE    fichier 0600
  5. LAB_USER / LAB_PASS                        variable historique (labs)
  6. la valeur du fichier d'inventaire          valeurs par défaut des images de lab (C11)

(HashiCorp Vault s'insérera entre 5 et 6 en phase C3 : une variable ou un fichier posé par l'opérateur
l'emporte toujours, l'inventaire ne vient qu'en dernier.) Le niveau « driver » passe avant le niveau
générique, fichier ou non : un NETCHECK_PASS posé pour FRR n'écrase pas le NETCHECK_SRLINUX_PASS_FILE de r5.

Un fichier désigné mais illisible ou mal protégé est une ERREUR, jamais un repli silencieux sur la valeur
suivante. Chaque identifiant porte sa source (« variable NETCHECK_PASS », « fichier /chemin »,
« inventaire »), jamais sa valeur : les rapports la citent.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from netcheck.secrets import SecretStr

MAX_SECRET_FILE_BYTES = 4096


class CredentialError(Exception):
    """Identifiant introuvable ou fichier de secret refusé. Le message ne contient jamais de valeur."""


@dataclass(frozen=True)
class Source:
    kind: str   # "variable" | "fichier" | "inventaire"
    name: str   # nom de la variable, chemin du fichier, ou "" pour l'inventaire

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name}".strip()


def read_secret_file(path: str | Path, what: str = "secret") -> str:
    """Lit un secret dans un fichier texte. Refus (CredentialError) si le fichier n'est pas un fichier
    régulier (pas un lien symbolique), n'appartient pas à l'utilisateur courant, est lisible par d'autres
    (droits autres que 0600 ou 0400), est vide, trop gros, ou fait plus d'une ligne (un fichier
    d'environnement entier donnerait une valeur fausse). La fin de ligne finale est retirée ; rien d'autre
    n'est modifié."""
    p = Path(path).expanduser()
    if p.is_symlink():
        raise CredentialError(
            f"{what} : {p} est un lien symbolique : refusé (donnez un vrai fichier, droits 600)")
    try:
        info = p.stat()
    except OSError as e:
        raise CredentialError(
            f"{what} : fichier {p} illisible ({e.strerror or e.__class__.__name__})") from None
    if not stat.S_ISREG(info.st_mode):
        raise CredentialError(f"{what} : {p} n'est pas un fichier régulier")
    if os.name != "nt":
        if info.st_uid != os.getuid():
            raise CredentialError(f"{what} : {p} n'appartient pas à l'utilisateur courant : refusé")
        mode = stat.S_IMODE(info.st_mode)
        if mode not in (0o600, 0o400):
            raise CredentialError(
                f"{what} : {p} a les droits {mode:o}, attendu 600 (lisible par vous seul) : chmod 600 '{p}'")
    if info.st_size > MAX_SECRET_FILE_BYTES:
        raise CredentialError(f"{what} : {p} fait plus de {MAX_SECRET_FILE_BYTES} octets : refusé")
    text = p.read_text(encoding="utf-8")
    value = text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith("\n") else text
    if not value:
        raise CredentialError(f"{what} : {p} est vide")
    if "\n" in value or "\r" in value:
        raise CredentialError(f"{what} : {p} contient plusieurs lignes (une seule valeur attendue)")
    return value


def _candidates(kind: str, driver: str) -> list[tuple[str, str]]:
    """[(« env » | « file », nom de variable)] dans l'ordre de priorité. kind = « USER » ou « PASS »."""
    d = driver.upper()
    return [("env", f"NETCHECK_{d}_{kind}"), ("file", f"NETCHECK_{d}_{kind}_FILE"),
            ("env", f"NETCHECK_{kind}"), ("file", f"NETCHECK_{kind}_FILE"),
            ("env", f"LAB_{kind}")]


def resolve(kind: str, driver: str, fallback: str | None, device: str = "?",
            environ: dict | None = None) -> tuple[str, Source]:
    """La valeur (str) et la source d'un identifiant. `fallback` = valeur de l'inventaire (peut manquer)."""
    env = os.environ if environ is None else environ
    tried = []
    for provider, var in _candidates(kind, driver):
        tried.append(var)
        raw = env.get(var)
        if not raw:                       # absent ou vide : comme avant la phase C2
            continue
        if provider == "env":
            return raw, Source("variable", var)
        return read_secret_file(raw, f"{var} ({device})"), Source("fichier", str(Path(raw).expanduser()))
    if fallback:
        return fallback, Source("inventaire", "")
    label = "mot de passe" if kind == "PASS" else "utilisateur"
    raise CredentialError(f"aucun {label} pour {device} : ni variable ni fichier ({', '.join(tried)}), "
                          "ni valeur dans l'inventaire")


def resolve_device(router: dict, environ: dict | None = None) -> dict:
    """Ajoute à un routeur de l'inventaire son identité résolue : `username` (str), `password` (SecretStr)
    et `credential_sources` ({« username » | « password » : source}), sans aucune valeur."""
    name, driver = router["name"], router.get("driver", "frr")
    user, user_src = resolve("USER", driver, router.get("username"), name, environ)
    password, pass_src = resolve("PASS", driver, router.get("password"), name, environ)
    return {**router, "username": user, "password": SecretStr(password, pass_src.label),
            "credential_sources": {"username": user_src.label, "password": pass_src.label}}


def describe_sources(routers: dict) -> dict[str, dict[str, list[str]]] | None:
    """{« utilisateur » | « mot de passe » : {source : [équipements]}} pour les rapports ; None si aucun
    routeur n'a d'identité résolue (mode hors ligne). Jamais une valeur."""
    out: dict[str, dict[str, list[str]]] = {"utilisateur": {}, "mot de passe": {}}
    seen = False
    for name, router in sorted(routers.items()):
        sources = router.get("credential_sources")
        if not sources:
            continue
        seen = True
        out["utilisateur"].setdefault(sources["username"], []).append(name)
        out["mot de passe"].setdefault(sources["password"], []).append(name)
    return out if seen else None


def format_sources(described: dict[str, dict[str, list[str]]]) -> list[str]:
    """Une ligne par genre : « mot de passe : variable NETCHECK_PASS (r1, r2) ; inventaire (r3) »."""
    return [f"{kind} : " + " ; ".join(f"{src} ({', '.join(names)})" for src, names in by_source.items())
            for kind, by_source in described.items() if by_source]
