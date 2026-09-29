"""Modèle de données normalisé : indépendant de tout constructeur.

Un driver (netcheck/drivers/) construit un DeviceState à partir des commandes de son
équipement. Tout le reste de netcheck (diff, compliance, report) ne travaille que sur
ces dataclasses.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Interface:
    """Une interface réseau."""
    name: str
    description: str | None
    admin_up: bool
    oper_up: bool
    addresses: list[str] = field(default_factory=list)  # CIDR IPv4, ex. "10.1.13.1/30"
    # None = inconnu (driver qui n'expose pas l'info, ou snapshot pris avant ce champ) :
    # dans ce cas, compliance._check_interface_description_required retombe sur le nom.
    is_loopback: bool | None = None


@dataclass
class NextHop:
    """Un saut suivant d'une route (IP absente si la route est directement connectée)."""
    ip: str | None
    interface: str | None
    directly_connected: bool = False


@dataclass
class Route:
    """Une entrée de la table de routage (une par protocole candidat sur un même préfixe)."""
    prefix: str
    protocol: str
    metric: int
    distance: int
    selected: bool  # chemin installé dans la RIB
    nexthops: list[NextHop] = field(default_factory=list)


@dataclass
class OspfNeighbor:
    """Un voisin OSPF."""
    router_id: str
    state: str      # ex. "Full/-"
    interface: str  # ex. "eth2:10.1.13.1"

    @property
    def is_full(self) -> bool:
        return self.state.startswith("Full")


@dataclass
class BgpPeer:
    """Une session BGP."""
    neighbor: str
    remote_as: int | None
    state: str
    pfx_received: int
    pfx_sent: int


@dataclass
class BgpPrefix:
    """Un préfixe BGP reçu ou annoncé, avec le meilleur chemin retenu."""
    prefix: str
    as_path: str  # chaîne d'AS séparés par des espaces, vide si origine locale
    next_hop: str
    best: bool


@dataclass
class DeviceState:
    """État complet d'un équipement à un instant donné (contenu d'un snapshot)."""
    name: str
    host: str
    timestamp: str  # ISO 8601
    reachable: bool
    error: str | None = None
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    ospf_neighbors: list[OspfNeighbor] = field(default_factory=list)
    bgp_peers: list[BgpPeer] = field(default_factory=list)
    bgp_prefixes: list[BgpPrefix] = field(default_factory=list)
    running_config: str = ""
    # Nom du driver ayant produit cet état (registre collector.DRIVER_REGISTRY), utilisé par
    # compliance.py pour filtrer les règles par driver (Phase D2). Défaut "frr" : un snapshot
    # écrit avant l'ajout de ce champ (ou tout appelant qui construit un DeviceState à la
    # main, comme les tests) reste valide sans le renseigner -- même logique de compatibilité
    # ascendante que is_loopback (v2, O3).
    driver: str = "frr"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceState:
        return cls(
            name=data["name"],
            host=data["host"],
            timestamp=data["timestamp"],
            reachable=data["reachable"],
            error=data.get("error"),
            interfaces=[Interface(**i) for i in data.get("interfaces", [])],
            routes=[
                Route(
                    prefix=r["prefix"], protocol=r["protocol"], metric=r["metric"],
                    distance=r["distance"], selected=r["selected"],
                    nexthops=[NextHop(**n) for n in r.get("nexthops", [])],
                )
                for r in data.get("routes", [])
            ],
            ospf_neighbors=[OspfNeighbor(**o) for o in data.get("ospf_neighbors", [])],
            bgp_peers=[BgpPeer(**p) for p in data.get("bgp_peers", [])],
            bgp_prefixes=[BgpPrefix(**b) for b in data.get("bgp_prefixes", [])],
            running_config=data.get("running_config", ""),
            driver=data.get("driver", "frr"),
        )
