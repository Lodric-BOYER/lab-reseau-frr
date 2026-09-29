"""Lecture de l'inventaire : réutilise automation/inventory.yml (même fichier), mais pas la
fonction load_inventory() de labtools, dont la résolution d'identifiants ne convient pas ici
(contrainte C3 : NETCHECK_USER/NETCHECK_PASS d'abord, puis LAB_USER/LAB_PASS, puis l'inventaire).

Sur un inventaire mixte (Phase D1), NETCHECK_USER/PASS s'appliqueraient sinon uniformément à
TOUS les routeurs, y compris ceux d'un autre driver (ex. écraser les identifiants SR Linux avec
ceux pensés pour FRR) : _resolve_credential ajoute un niveau plus spécifique, par driver
(NETCHECK_<DRIVER>_USER/PASS, ex. NETCHECK_SRLINUX_USER), prioritaire sur le générique. Ordre
complet, du plus spécifique au moins spécifique :
  NETCHECK_<DRIVER>_USER/PASS  >  NETCHECK_USER/PASS  >  LAB_USER/PASS  >  inventaire
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


def _resolve_credential(kind: str, driver_name: str, fallback: str) -> str:
    """kind = "USER" ou "PASS". Le plus spécifique gagne : voir l'ordre documenté en tête de
    module. NETCHECK_<DRIVER>_* n'a d'effet que sur les routeurs de ce driver précis ; les
    autres (variables génériques ou absence de variable) suivent la résolution historique."""
    per_driver = os.environ.get(f"NETCHECK_{driver_name.upper()}_{kind}")
    generic = os.environ.get(f"NETCHECK_{kind}") or os.environ.get(f"LAB_{kind}")
    return per_driver or generic or fallback


def load(only: list[str] | None = None, path: Path | str | None = None) -> Inventory:
    """Fusionne defaults + attributs de chaque routeur ; filtre éventuel sur une liste de noms.

    `path` omis = automation/inventory.yml (lab mono-constructeur). Un autre fichier (ex.
    automation/inventory-multivendor.yml) peut être passé explicitement -- c'est ce que fait
    l'option -i/--inventory de la CLI (Phase D1)."""
    path = Path(path) if path else INVENTORY_PATH
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})

    routers = {}
    for name, attrs in data["routers"].items():
        if only and name not in only:
            continue
        r = {**defaults, **(attrs or {}), "name": name}
        driver_name = r.get("driver", "frr")
        r["username"] = _resolve_credential("USER", driver_name, r["username"])
        r["password"] = _resolve_credential("PASS", driver_name, r["password"])
        routers[name] = r

    if only and set(only) - set(routers):
        raise SystemExit(f"Routeur(s) inconnu(s) : {', '.join(sorted(set(only) - set(routers)))}")

    return Inventory(routers=routers, management_interfaces=data.get("management_interfaces", []))
