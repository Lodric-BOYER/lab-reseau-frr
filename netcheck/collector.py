"""Connexion SSH générique et liste blanche des commandes (contrainte C1 : lecture seule).

Contrairement à automation/labtools.py, ce module ne connaît pas vtysh : c'est le driver qui
traduit une commande logique en commande CLI réelle (Driver.translate) et qui l'analyse
(Driver.parse). Un driver Cisco ou FortiGate n'a donc besoin de toucher qu'à drivers/.
"""
from __future__ import annotations

import sys
from pathlib import Path

from netmiko import ConnectHandler

# automation/ n'est pas un paquet Python (pas de __init__.py) : on réutilise run_parallel tel
# quel en ajoutant son dossier à sys.path, sans dupliquer sa logique (C2 : rien n'y est modifié).
AUTOMATION_DIR = Path(__file__).resolve().parent.parent / "automation"
if str(AUTOMATION_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_DIR))
from labtools import run_parallel  # noqa: E402  (import après modification de sys.path)

from netcheck.drivers.base import Driver
from netcheck.model import DeviceState

# Commandes logiques autorisées (tableau §4 du cahier des charges). Un driver ne peut pas en
# demander d'autres : toute commande de configuration est refusée avant même la connexion SSH.
ALLOWED_COMMANDS = {
    "show interface json",
    "show ip route json",
    "show ip ospf neighbor json",
    "show bgp ipv4 unicast summary json",
    "show bgp ipv4 unicast json",
    "show running-config",
}


def _ensure_allowed(commands) -> None:
    """Lève PermissionError si une commande n'est pas dans la liste blanche (C1)."""
    unknown = set(commands) - ALLOWED_COMMANDS
    if unknown:
        raise PermissionError(f"commande(s) hors liste blanche : {sorted(unknown)}")


def collect(router: dict, driver: Driver) -> DeviceState:
    """Se connecte à un équipement, exécute les commandes du driver, renvoie l'état normalisé.

    La liste blanche est vérifiée deux fois : une première fois ici, sur tout
    REQUIRED_COMMANDS, *avant même d'ouvrir la connexion SSH* (un driver mal écrit ne
    contacte jamais l'équipement) ; une seconde fois juste avant l'envoi de chaque
    commande individuelle, au plus près de l'action sensible. La seconde ne peut pas être
    contournée par un futur appelant qui construirait sa propre liste de commandes sans
    repasser par ce premier contrôle.
    """
    _ensure_allowed(driver.REQUIRED_COMMANDS)

    conn = ConnectHandler(
        device_type=router["device_type"], host=router["host"],
        username=router["username"], password=router["password"],
        timeout=10, conn_timeout=10,
    )
    try:
        raw = {}
        for command in driver.REQUIRED_COMMANDS:
            _ensure_allowed([command])
            out = conn.send_command(driver.translate(command), read_timeout=30)
            raw[command] = driver.clean_output(out)
    finally:
        conn.disconnect()
    return driver.parse(raw, router["name"], router["host"])


def collect_all(routers: dict, driver: Driver, workers: int = 5) -> dict:
    """Collecte en parallèle ; renvoie {nom: (True, DeviceState) ou (False, message d'erreur)}.

    Un équipement injoignable ne bloque pas les autres (réutilise run_parallel de labtools).
    """
    return run_parallel(lambda r: collect(r, driver), routers, workers=workers)
