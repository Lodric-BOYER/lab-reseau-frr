"""Filtrage des interfaces de management : partagé par diff.py et compliance.py.

Les interfaces listées dans `management_interfaces` (automation/inventory.yml) n'ont pas de
sens fonctionnel pour le routage étudié ici (ajustement validé avec l'utilisateur après la
phase 1) : elles, leurs routes et leurs sous-réseaux connectés sont ignorés partout.
"""
from __future__ import annotations

import ipaddress
from dataclasses import replace

from netcheck.model import DeviceState, Route


def subnets(state: DeviceState, mgmt_names: set[str]) -> set[str]:
    """Sous-réseaux connectés portés par les interfaces de management (ex. 172.20.20.0/24)."""
    result = set()
    for iface in state.interfaces:
        if iface.name in mgmt_names:
            for addr in iface.addresses:
                try:
                    result.add(str(ipaddress.ip_interface(addr).network))
                except ValueError:
                    continue
    return result


def filtered(state: DeviceState, mgmt_names: set[str]) -> DeviceState:
    """Renvoie une copie de state sans les interfaces de management ni leurs routes."""
    if not mgmt_names:
        return state
    mgmt_subnets = subnets(state, mgmt_names)

    def is_management_route(r: Route) -> bool:
        if r.prefix in mgmt_subnets:
            return True
        return bool(r.nexthops) and all(nh.interface in mgmt_names for nh in r.nexthops)

    return replace(
        state,
        interfaces=[i for i in state.interfaces if i.name not in mgmt_names],
        routes=[r for r in state.routes if not is_management_route(r)],
    )
