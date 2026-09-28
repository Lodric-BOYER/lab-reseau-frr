"""Lecture de l'inventaire : réutilise automation/inventory.yml (même fichier), mais pas la
fonction load_inventory() de labtools, dont la résolution d'identifiants ne convient pas ici
(contrainte C3 : NETCHECK_USER/NETCHECK_PASS d'abord, puis LAB_USER/LAB_PASS, puis l'inventaire).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = REPO_ROOT / "automation" / "inventory.yml"


@dataclass
class Inventory:
    routers: dict[str, dict]
    management_interfaces: list[str] = field(default_factory=list)


def load(only: list[str] | None = None, path: Path | str | None = None) -> Inventory:
    """Fusionne defaults + attributs de chaque routeur ; filtre éventuel sur une liste de noms.

    `path` omis = automation/inventory.yml (lab mono-constructeur). Un autre fichier (ex.
    automation/inventory-multivendor.yml) peut être passé explicitement -- c'est ce que fait
    l'option -i/--inventory de la CLI (Phase D1)."""
    path = Path(path) if path else INVENTORY_PATH
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})

    username = os.environ.get("NETCHECK_USER") or os.environ.get("LAB_USER")
    password = os.environ.get("NETCHECK_PASS") or os.environ.get("LAB_PASS")

    routers = {}
    for name, attrs in data["routers"].items():
        if only and name not in only:
            continue
        r = {**defaults, **(attrs or {}), "name": name}
        r["username"] = username or r["username"]
        r["password"] = password or r["password"]
        routers[name] = r

    if only and set(only) - set(routers):
        raise SystemExit(f"Routeur(s) inconnu(s) : {', '.join(sorted(set(only) - set(routers)))}")

    return Inventory(routers=routers, management_interfaces=data.get("management_interfaces", []))
