"""Relevés BRUTS des labs en double pile (phase B2), pris en direct par les commandes de chaque driver.

`tests/fixtures/dualstack/<lab>/<routeur>.json` = {"driver", "host", "commands": {commande logique: sortie}} :
la sortie de chaque commande de la liste blanche, telle que le collecteur la reçoit (après `clean_output`),
sur un lab démarré à froid et convergé (OSPFv3 Full partout, eBGP IPv4 et IPv6 Established). Labs : `frr`
(lab FRR), `mixed` (r5 = Nokia SR Linux 26.7.2), `ceos` (r4 = Arista cEOS 4.34.8M). `ceos/r4_tmpvrf.json` :
les commandes d'EOS relevées pendant une VRF temporaire `TMPVRF` sur r4 (interface Loopback99, routes IPv4 et
IPv6), retirée ensuite avec preuve. Rien n'y est inventé ; un test qui modifie une sortie le dit.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState

ROOT = Path(__file__).resolve().parent / "fixtures" / "dualstack"
ROUTERS = ("r1", "r2", "r3", "r4", "r5")


def load_raw(lab: str, router: str) -> dict:
    return json.loads((ROOT / lab / f"{router}.json").read_text(encoding="utf-8"))


def parse(raw_file: dict, name: str) -> DeviceState:
    driver = DRIVER_REGISTRY[raw_file["driver"]]()
    state = driver.parse(copy.deepcopy(raw_file["commands"]), name, raw_file["host"])
    state.driver = raw_file["driver"]
    return state


def load_lab(lab: str) -> dict[str, DeviceState]:
    return {r: parse(load_raw(lab, r), r) for r in ROUTERS}


def parse_with(lab: str, router: str, overrides: dict[str, str]) -> DeviceState:
    """L'état d'un routeur dont certaines sorties sont REMPLACÉES (clé = commande logique) : pour les cas
    que le lab ne produit pas. Un test qui s'en sert dit ce qu'il a modifié."""
    raw_file = load_raw(lab, router)
    raw_file["commands"].update(overrides)
    return parse(raw_file, router)
