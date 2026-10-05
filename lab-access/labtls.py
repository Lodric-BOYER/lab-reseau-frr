"""Garde commune des outils de lab qui ne vérifient pas l'identité de l'équipement.

Cas couverts : TLS `--insecure` de curl et clés d'hôte SSH acceptées sans contrôle.

Les équipements du lab présentent un certificat auto-signé : `curl` ne peut pas le vérifier. Ce n'est
permis QUE si l'appelant le demande explicitement (`--insecure`) ET désigne un inventaire qui déclare
`lab: true` : même règle que `--host-keys accept-new` de netcheck (netcheck/hostkeys.py). Sinon : refus,
code 3, et la vérification stricte de curl reste en place (`--cacert` pour une autorité de confiance).
Chaque usage est annoncé sur la sortie d'erreur.

Bibliothèque standard seulement. Outil de lab : netcheck/ n'importe rien d'ici
(tests/test_lab_access_hardening.py).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_LAB_LINE = re.compile(r"^lab:[ \t]*true[ \t]*(#.*)?$", re.M)
_announced: set[str] = set()


class TlsRefused(Exception):
    """Usage refusé (code 3) : jamais de repli silencieux vers une connexion non vérifiée."""


def is_lab_inventory(path: str | None) -> bool:
    """`lab: true` au niveau racine du fichier. Toute autre forme est refusée (échec fermé)."""
    if not path:
        return False
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(_LAB_LINE.search(text))


def require_lab(inventory: str | None, what: str) -> None:
    """Refuse (TlsRefused) sauf si `inventory` déclare `lab: true`. Annonce l'usage une fois par processus."""
    if not inventory:
        raise TlsRefused(f"{what} : --lab-inventory <inventaire marqué `lab: true`> est obligatoire")
    if not is_lab_inventory(inventory):
        raise TlsRefused(f"{what} est réservé au lab : {inventory} ne déclare pas `lab: true`")
    if what not in _announced:
        _announced.add(what)
        print(
            f"AVERTISSEMENT : {what} -- identité de l'équipement NON vérifiée, "
            f"permis car {inventory} déclare `lab: true`. Réservé au lab.",
            file=sys.stderr,
        )


def curl_tls_args(
    insecure: bool = False, cacert: str | None = None, lab_inventory: str | None = None
) -> list[str]:
    """Options TLS de curl. Défaut : vérification stricte (rien à ajouter)."""
    if insecure and cacert:
        raise TlsRefused("--insecure et --cacert s'excluent")
    if cacert:
        if not Path(cacert).is_file():
            raise TlsRefused(f"--cacert : fichier introuvable : {cacert}")
        return ["--cacert", cacert]
    if not insecure:
        return []
    require_lab(lab_inventory, "TLS non vérifié (--insecure)")
    return ["--insecure"]


def add_arguments(parser) -> None:
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="ne pas vérifier le certificat (auto-signé du lab) ; exige --lab-inventory",
    )
    parser.add_argument("--cacert", help="autorité de confiance du certificat de l'équipement (hors lab)")
    parser.add_argument("--lab-inventory", help="inventaire qui déclare `lab: true` (autorise --insecure)")


def tls_from_args(args) -> list[str]:
    return curl_tls_args(args.insecure, args.cacert, args.lab_inventory)
