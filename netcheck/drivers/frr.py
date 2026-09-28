"""Driver FRRouting (10.x) : commandes vtysh -> modèle normalisé (netcheck/model.py).

Champs vérifiés sur le vrai lab (FRR 10.2.1), pas devinés : voir tests/fixtures/.
"""
from __future__ import annotations

import json
import shlex

from netcheck.drivers.base import Driver
from netcheck.model import BgpPeer, BgpPrefix, DeviceState, Interface, NextHop, OspfNeighbor, Route


class FrrDriver(Driver):
    REQUIRED_COMMANDS = [
        "show interface json",
        "show ip route json",
        "show ip ospf neighbor json",
        "show bgp ipv4 unicast summary json",
        "show bgp ipv4 unicast json",
        "show running-config",
    ]

    def translate(self, command: str) -> str:
        return f"vtysh -c {shlex.quote(command)}"

    def clean_output(self, raw: str) -> str:
        # vtysh non-root avertit qu'il ne lit pas vtysh.conf : bruit sans conséquence (cf.
        # automation/labtools.py, même filtre pour rester cohérent avec health/backup/drift).
        out = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("% Can't open configuration file")
        )
        for marker in ("command not found", "failed to connect to any daemons"):
            if marker in out.lower():
                raise RuntimeError(f"vtysh inutilisable : {out.strip()[:120]}")
        return out

    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        return DeviceState(
            name=name,
            host=host,
            timestamp=self.now(),
            reachable=True,
            interfaces=self._parse_interfaces(raw["show interface json"]),
            routes=self._parse_routes(raw["show ip route json"]),
            ospf_neighbors=self._parse_ospf(raw["show ip ospf neighbor json"]),
            bgp_peers=self._parse_bgp_summary(raw["show bgp ipv4 unicast summary json"]),
            bgp_prefixes=self._parse_bgp_prefixes(raw["show bgp ipv4 unicast json"]),
            running_config=raw["show running-config"],
        )

    # -- Interfaces -----------------------------------------------------------------------
    @staticmethod
    def _parse_interfaces(text: str) -> list[Interface]:
        data = json.loads(text)
        interfaces = []
        for ifname, attrs in data.items():
            # Seules les adresses IPv4 nous intéressent (§4) ; une adresse IPv6 contient ':'.
            v4 = [a["address"] for a in attrs.get("ipAddresses", []) if ":" not in a["address"]]
            interfaces.append(Interface(
                name=ifname,
                description=attrs.get("description"),  # absente sur eth0/lo : reste à None
                admin_up=attrs.get("administrativeStatus") == "up",
                oper_up=attrs.get("operationalStatus") == "up",
                addresses=v4,
            ))
        return interfaces

    # -- Routes -----------------------------------------------------------------------------
    @staticmethod
    def _parse_routes(text: str) -> list[Route]:
        data = json.loads(text)
        routes = []
        for prefix, entries in data.items():
            for e in entries:
                nexthops = [
                    NextHop(
                        ip=nh.get("ip"),
                        interface=nh.get("interfaceName"),
                        directly_connected=nh.get("directlyConnected", False),
                    )
                    for nh in e.get("nexthops", [])
                ]
                routes.append(Route(
                    prefix=prefix,
                    protocol=e.get("protocol", "?"),
                    metric=e.get("metric", 0),
                    distance=e.get("distance", 0),
                    # Absente (pas juste false) sur les chemins candidats non installés.
                    selected=e.get("selected", False),
                    nexthops=nexthops,
                ))
        return routes

    # -- OSPF -------------------------------------------------------------------------------
    @staticmethod
    def _parse_ospf(text: str) -> list[OspfNeighbor]:
        neighbors_by_rid = json.loads(text).get("neighbors", {})
        neighbors = []
        for router_id, entries in neighbors_by_rid.items():
            for e in entries:
                # FRR 10.2.1 utilise "nbrState" ; on garde "state" par robustesse inter-versions.
                state = e.get("nbrState") or e.get("state", "")
                neighbors.append(OspfNeighbor(
                    router_id=router_id, state=state, interface=e.get("ifaceName", ""),
                ))
        return neighbors

    # -- BGP ----------------------------------------------------------------------------------
    @staticmethod
    def _parse_bgp_summary(text: str) -> list[BgpPeer]:
        peers = json.loads(text).get("peers", {})
        return [
            BgpPeer(
                neighbor=ip,
                remote_as=attrs.get("remoteAs"),
                state=attrs.get("state", "absent"),
                pfx_received=attrs.get("pfxRcd", 0),
                pfx_sent=attrs.get("pfxSnt", 0),
            )
            for ip, attrs in peers.items()
        ]

    @staticmethod
    def _parse_bgp_prefixes(text: str) -> list[BgpPrefix]:
        routes = json.loads(text).get("routes", {})
        prefixes = []
        for prefix, paths in routes.items():
            for p in paths:
                nexthops = p.get("nexthops") or []
                next_hop = nexthops[0].get("ip", "") if nexthops else ""
                prefixes.append(BgpPrefix(
                    prefix=prefix,
                    as_path=p.get("path", ""),  # chaîne vide = origine locale
                    next_hop=next_hop,
                    best=p.get("bestpath", False),
                ))
        return prefixes
