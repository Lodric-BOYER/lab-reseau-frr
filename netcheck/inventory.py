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

import os
from dataclasses import dataclass, field
from pathlib import Path

from netcheck import credentials, sshkeys
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.usage import UsageError, load_yaml

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
    source: str = ""   # fichier d'origine, pour les messages
    # Phase C4 : bastion résolu (clé contrôlée et chargée), ou None (hors ligne, ou pas de bloc `bastion:`).
    bastion: sshkeys.Bastion | None = None


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
    data = load_yaml(path, "inventaire")
    if not isinstance(data, dict):
        raise UsageError(f"Inventaire {path} : un objet YAML est attendu (clés `routers`, `defaults`…)")
    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise UsageError(f"Inventaire {path} : `defaults` doit être un objet (clé: valeur)")
    declared = data.get("routers")
    if not isinstance(declared, dict) or not declared:
        raise UsageError(f"Inventaire {path} : `routers` doit être un objet non vide (un routeur par clé)")

    # Phase C4 : bloc `bastion:` au niveau de l'inventaire. Sa structure est toujours validée ; sa clé n'est
    # lue (et contrôlée) qu'en mode direct : les commandes hors ligne n'ont besoin d'aucun fichier de clé.
    bastion_spec = data.get("bastion")
    if bastion_spec is not None:
        _check_bastion(bastion_spec, path)
    bastion = sshkeys.resolve_bastion(bastion_spec, os.environ) \
        if bastion_spec is not None and resolve_credentials else None

    routers = {}
    for name, attrs in declared.items():
        if not isinstance(name, str):
            raise UsageError(f"Inventaire {path} : nom de routeur {name!r} invalide "
                             "(mettez-le entre guillemets)")
        if attrs is not None and not isinstance(attrs, dict):
            raise UsageError(f"Inventaire {path} : routeur {name} : un objet (clé: valeur) est attendu")
        if only and name not in only:
            continue
        r = {**defaults, **(attrs or {}), "name": name}
        _check_router(r, path)
        if bastion is not None:
            r["bastion"] = bastion
        routers[name] = credentials.resolve_device(r) if resolve_credentials else r

    if only and set(only) - set(routers):
        raise UsageError(f"Routeur(s) inconnu(s) : {', '.join(sorted(set(only) - set(routers)))} "
                         f"(inventaire {path} : {', '.join(declared)})")

    lab = data.get("lab", False)
    if not isinstance(lab, bool):
        raise UsageError(f"Inventaire {path} : « lab » doit valoir true ou false (reçu : {lab!r})")
    lists = {}
    for key in ("management_interfaces", "management_vrfs"):
        value = data.get(key) or []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise UsageError(f"Inventaire {path} : `{key}` doit être une liste de noms")
        lists[key] = value

    return Inventory(routers=routers, management_interfaces=lists["management_interfaces"],
                     management_vrfs=lists["management_vrfs"], lab=lab, source=str(path), bastion=bastion)


def _check_bastion(spec, path: Path) -> None:
    """Structure du bloc `bastion:` (host, port, username, key_file). Jamais de mot de passe de bastion."""
    if not isinstance(spec, dict):
        raise UsageError(f"Inventaire {path} : `bastion` doit être un objet (host, username, key_file, port)")
    unknown = sorted(set(spec) - set(sshkeys.BASTION_KEYS))
    if unknown:
        raise UsageError(f"Inventaire {path} : bastion : clé(s) inconnue(s) {unknown} (attendu : "
                         f"{', '.join(sshkeys.BASTION_KEYS)} ; un bastion n'a jamais de mot de passe)")
    for key in ("host", "username"):
        if not isinstance(spec.get(key), str) or not spec[key].strip():
            raise UsageError(f"Inventaire {path} : bastion : `{key}` manque (ou n'est pas du texte)")
    if "key_file" in spec and (not isinstance(spec["key_file"], str) or not spec["key_file"].strip()):
        raise UsageError(f"Inventaire {path} : bastion : `key_file` doit être un chemin (texte)")
    if "port" in spec:
        port = spec["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise UsageError(f"Inventaire {path} : bastion : `port` doit être un entier de 1 à 65535")


def _check_router(router: dict, path: Path) -> None:
    """Types des champs d'un routeur. Aucun message ne cite une valeur d'identifiant : l'inventaire peut
    contenir un mot de passe."""
    name = router["name"]
    if "bastion" in router:
        raise UsageError(f"Inventaire {path} : routeur {name} : `bastion` se déclare une fois, au niveau de "
                         "l'inventaire, pas par routeur")
    if "key_file" in router and (not isinstance(router["key_file"], str) or not router["key_file"].strip()):
        raise UsageError(f"Inventaire {path} : routeur {name} : `key_file` doit être un chemin (texte)")
    for key in ("username", "password"):
        if key in router and not isinstance(router[key], str):
            raise UsageError(f"Inventaire {path} : routeur {name} : `{key}` doit être du texte "
                             "(entre guillemets : « 12345678 » sans guillemets est un nombre)")
    if "port" in router:
        port = router["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise UsageError(f"Inventaire {path} : routeur {name} : `port` doit être un entier de 1 à 65535")


def check_collectable(inv: Inventory) -> None:
    """Avant une collecte en direct : un routeur sans `host` ni `device_type`, ou dont le driver est inconnu,
    est une erreur d'usage (code 3), pas un équipement « injoignable » (code 1 ou 2). Séparé de `load` : les
    commandes hors ligne n'ont besoin d'aucun de ces champs."""
    for name, router in inv.routers.items():
        for key in ("host", "device_type"):
            if not isinstance(router.get(key), str) or not router[key].strip():
                raise UsageError(f"Inventaire {inv.source} : routeur {name} : `{key}` manque "
                                 "(ou n'est pas du texte)")
        driver = router.get("driver", "frr")
        if driver not in DRIVER_REGISTRY:
            raise UsageError(f"Inventaire {inv.source} : routeur {name} : driver {driver!r} inconnu "
                             f"(disponibles : {', '.join(sorted(DRIVER_REGISTRY))})")
