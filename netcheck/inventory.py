"""Lecture de l'inventaire : réutilise automation/inventory.yml (même fichier), mais pas la
fonction load_inventory() de labtools, dont la résolution d'identifiants ne convient pas ici
(contrainte C3 : NETCHECK_USER/NETCHECK_PASS d'abord, puis LAB_USER/LAB_PASS, puis l'inventaire).

Sur un inventaire mixte (Phase D1), NETCHECK_USER/PASS s'appliqueraient sinon uniformément à
TOUS les routeurs, y compris ceux d'un autre driver (ex. écraser les identifiants SR Linux avec
ceux pensés pour FRR) : un niveau plus spécifique, par driver (NETCHECK_<DRIVER>_USER/PASS, ex.
NETCHECK_SRLINUX_USER), est prioritaire sur le générique. Depuis la phase C2, la résolution (variables,
fichiers 0600, valeur de l'inventaire) vit dans netcheck/credentials.py : l'ordre complet y est documenté.
Le mot de passe d'un routeur est un SecretStr (jamais affiché), et le routeur porte la SOURCE de chaque
identifiant (`credential_sources`), jamais sa valeur.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from netcheck import credentials

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = REPO_ROOT / "automation" / "inventory.yml"


@dataclass
class Inventory:
    routers: dict[str, dict]
    management_interfaces: list[str] = field(default_factory=list)
    # Phase B2 : VRF de management (ex. `mgmt` sur SR Linux), exclues comme les interfaces de management.
    management_vrfs: list[str] = field(default_factory=list)
    # Phase C1 : `lab: true` dans le fichier. Seul un inventaire de lab peut utiliser --host-keys accept-new.
    lab: bool = False


def load(only: list[str] | None = None, path: Path | str | None = None,
         resolve_credentials: bool = True) -> Inventory:
    """Fusionne defaults + attributs de chaque routeur ; filtre éventuel sur une liste de noms.

    `path` omis = automation/inventory.yml (lab mono-constructeur). Un autre fichier (ex.
    automation/inventory-multivendor.yml) peut être passé explicitement -- c'est ce que fait
    l'option -i/--inventory de la CLI (Phase D1).

    `resolve_credentials=False` (hors ligne : diff, check --config-dir/--snapshot, assert --snapshot) :
    aucun identifiant n'est résolu, aucun fichier de secret n'est lu, un fichier de secret absent n'y est
    donc jamais une erreur."""
    path = Path(path) if path else INVENTORY_PATH
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})

    routers = {}
    for name, attrs in data["routers"].items():
        if only and name not in only:
            continue
        r = {**defaults, **(attrs or {}), "name": name}
        routers[name] = credentials.resolve_device(r) if resolve_credentials else r

    if only and set(only) - set(routers):
        raise SystemExit(f"Routeur(s) inconnu(s) : {', '.join(sorted(set(only) - set(routers)))}")

    lab = data.get("lab", False)
    if not isinstance(lab, bool):
        raise SystemExit(f"Inventaire {path} : « lab » doit valoir true ou false (reçu : {lab!r})")

    return Inventory(routers=routers, management_interfaces=data.get("management_interfaces", []),
                     management_vrfs=data.get("management_vrfs", []), lab=lab)
