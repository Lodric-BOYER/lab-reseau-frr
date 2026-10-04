"""Erreurs d'usage : tout ce qui vient de l'opérateur (fichier absent, YAML invalide, option incohérente)
et non d'un défaut de netcheck. La CLI les traduit en code 3, une ligne sur stderr, jamais de traceback.

Règle de sécurité : aucun message d'ici ne cite le CONTENU d'un fichier. Un message d'erreur de PyYAML
reproduit la ligne fautive, or un inventaire peut contenir un mot de passe : `parse_yaml` ne garde que la
position (ligne, colonne) et le type du problème.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class UsageError(ValueError):
    """Erreur d'usage (code 3). Sous-classe de ValueError : les chargeurs qui levaient déjà ValueError
    restent compatibles avec leurs appelants."""


def read_text(path: str | Path, what: str = "fichier") -> str:
    """Lit un fichier texte UTF-8. Sans le contenu dans les messages."""
    p = Path(path)
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise UsageError(f"{p} : {what} introuvable") from None
    except IsADirectoryError:
        raise UsageError(f"{p} : {what} attendu, mais c'est un dossier") from None
    except PermissionError:
        raise UsageError(f"{p} : {what} illisible (permission refusée)") from None
    except UnicodeDecodeError:
        raise UsageError(f"{p} : {what} qui n'est pas du texte UTF-8") from None
    except OSError as e:
        raise UsageError(f"{p} : {what} illisible ({e.strerror or e.__class__.__name__})") from None


def yaml_position(error: yaml.YAMLError) -> str:
    mark = getattr(error, "problem_mark", None)
    if mark is None:
        return ""
    return f" (ligne {mark.line + 1}, colonne {mark.column + 1})"


def parse_yaml(text: str, path: str | Path) -> Any:
    """`yaml.safe_load` exclusivement ; en cas d'erreur : position et type du problème, jamais l'extrait."""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        problem = getattr(e, "problem", None) or e.__class__.__name__
        raise UsageError(
            f"{path} : fichier YAML invalide ou refusé{yaml_position(e)} : {' '.join(str(problem).split())}"
        ) from None


def load_yaml(path: str | Path, what: str = "fichier") -> Any:
    return parse_yaml(read_text(path, what), path)


def _nearest_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return Path(".")


def check_output_path(path: str | Path, option: str, create_parents: bool = False) -> None:
    """Refuse AVANT toute action un fichier de sortie qu'on ne pourra pas écrire : un `guard` ne doit pas
    découvrir à la fin, après avoir exécuté le changement, que `--json` pointe vers un dossier absent.
    `create_parents` : le programme créera les dossiers manquants (fichier d'état de monitor)."""
    p = Path(path)
    if p.is_dir():
        raise UsageError(f"{option} : {p} est un dossier (donnez un nom de fichier)")
    parent = _nearest_existing(p.parent) if create_parents else p.parent
    if not parent.is_dir():
        raise UsageError(f"{option} : le dossier {p.parent} n'existe pas")
    if os.name != "nt" and not os.access(parent, os.W_OK | os.X_OK):
        raise UsageError(f"{option} : le dossier {parent} n'est pas accessible en écriture")
    if p.exists() and os.name != "nt" and not os.access(p, os.W_OK):
        raise UsageError(f"{option} : {p} n'est pas modifiable")
