"""Filtrage du management : partagé par diff.py, compliance.py et assertions.py.

Les interfaces listées dans `management_interfaces` (automation/inventory.yml) n'ont pas de
sens fonctionnel pour le routage étudié ici (ajustement validé avec l'utilisateur après la
phase 1) : elles, leurs routes et leurs sous-réseaux connectés sont ignorés partout.

Phase B2 : le même filtrage s'étend aux VRF de management déclarées dans l'inventaire
(`management_vrfs`, ex. `mgmt` sur SR Linux) : une VRF de management, ses interfaces, ses routes et ses
sessions BGP sont exclues comme `eth0` ou `Management0`.
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
            for addr in iface.addresses + iface.addresses6:
                try:
                    result.add(str(ipaddress.ip_interface(addr).network))
                except ValueError:
                    continue
    return result


def filtered(state: DeviceState, mgmt_names: set[str], mgmt_vrfs: set[str] | None = None) -> DeviceState:
    """Renvoie une copie de state sans les interfaces de management ni leurs routes, ni les VRF de
    management."""
    vrfs = set(mgmt_vrfs or ())
    if not mgmt_names and not vrfs:
        return state
    mgmt_subnets = subnets(state, mgmt_names)

    def is_management_route(r: Route) -> bool:
        if r.vrf in vrfs:
            return True
        # Les sous-réseaux de management ne se comparent que dans la VRF de l'interface de management : un
        # même préfixe dans une autre VRF n'est pas la route de management (identité = (vrf, préfixe)).
        if r.prefix in mgmt_subnets and any(
                i.name in mgmt_names and i.vrf == r.vrf for i in state.interfaces):
            return True
        return bool(r.nexthops) and all(nh.interface in mgmt_names for nh in r.nexthops)

    return replace(
        state,
        interfaces=[i for i in state.interfaces if i.name not in mgmt_names and i.vrf not in vrfs],
        routes=[r for r in state.routes if not is_management_route(r)],
        bgp_peers=[p for p in state.bgp_peers if p.vrf not in vrfs],
        bgp_prefixes=[p for p in state.bgp_prefixes if p.vrf not in vrfs],
    )
