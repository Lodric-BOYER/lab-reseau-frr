"""Registre des drivers disponibles, indexé par le champ « driver » de l'inventaire.

Il vit dans son propre module (et non plus dans `collector.py`) pour que le moteur de conformité
puisse résoudre les évaluateurs d'un driver sans importer le collecteur (donc sans Netmiko) : importer
`netcheck.compliance` ne charge plus ni l'un ni l'autre. `collector.DRIVER_REGISTRY` reste le même
objet (alias), donc tout code existant continue de fonctionner.
"""
from __future__ import annotations

from netcheck.drivers.base import Driver
from netcheck.drivers.eos import EosDriver
from netcheck.drivers.frr import FrrDriver
from netcheck.drivers.srlinux import SrlinuxDriver

# Absent de l'inventaire = "frr" (comportement historique, lab mono-constructeur inchangé).
DRIVER_REGISTRY: dict[str, type[Driver]] = {
    "frr": FrrDriver,
    "srlinux": SrlinuxDriver,
    "eos": EosDriver,
}
