"""Modèle de données normalisé : indépendant de tout constructeur.

Un driver (netcheck/drivers/) construit un DeviceState à partir des commandes de son
équipement. Tout le reste de netcheck (diff, compliance, report) ne travaille que sur
ces dataclasses.

Phase B2 (v4) : IPv6, VRF et sections collectées.
- Une route, une session BGP, un préfixe BGP et une interface portent un champ `vrf` (défaut « default »).
  L'identité d'une route est (vrf, préfixe) : le même préfixe dans deux VRF = deux routes.
- Un DeviceState dit quelles SECTIONS ont réellement été relevées (`collected`). Une section relevée mais
  vide (une liste vide) n'est pas une section non relevée : la première veut dire « rien n'est configuré »,
  la seconde « on ne sait pas » (NON ÉVALUABLE pour assert, constat « section non comparable » pour diff).
- Un snapshot écrit avant la phase B2 (sans `collected`, sans `vrf`) se lit comme un relevé de la VRF
  « default » des sections de la v0.3.0 (voir LEGACY_SECTIONS).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DEFAULT_VRF = "default"

# Les sections qu'un driver peut relever. `vrf` = « les VRF autres que default sont relevées » (appartenance
# des interfaces et routes de toutes les VRF) ; `bgp_vrf` = sessions et préfixes BGP des VRF autres que
# default (aucun driver ne le relève encore : une assertion sur le BGP d'une VRF est NON ÉVALUABLE).
SECTIONS = (
    "interfaces", "routes_v4", "routes_v6", "ospf_v2", "ospf_v3", "bgp_v4", "bgp_v6", "vrf", "bgp_vrf",
    "config",
)

# Ce qu'un relevé de la v0.3.0 contenait. SR Linux ne relevait déjà aucune session BGP (bgp_peers toujours
# vide).
LEGACY_SECTIONS = ("interfaces", "routes_v4", "ospf_v2", "bgp_v4", "config")
_LEGACY_SECTIONS_BY_DRIVER = {"srlinux": ("interfaces", "routes_v4", "ospf_v2", "config")}


@dataclass
class Interface:
    """Une interface réseau (dans une VRF : le même nom peut exister dans deux VRF, côté SR Linux)."""
    name: str
    description: str | None
    admin_up: bool
    oper_up: bool
    addresses: list[str] = field(default_factory=list)  # CIDR IPv4, ex. "10.1.13.1/30"
    # None = inconnu (driver qui n'expose pas l'info, ou snapshot pris avant ce champ) :
    # dans ce cas, compliance._check_interface_description_required retombe sur le nom.
    is_loopback: bool | None = None
    # Phase B2 : adresses IPv6 globales (CIDR, ex. "2001:db8:34::2/127"), l'adresse de lien local à part
    # (une seule par interface, "fe80::…" sans longueur de préfixe) et la VRF.
    addresses6: list[str] = field(default_factory=list)
    link_local6: str | None = None
    vrf: str = DEFAULT_VRF


@dataclass
class NextHop:
    """Un saut suivant d'une route (IP absente si la route est directement connectée)."""
    ip: str | None
    interface: str | None
    directly_connected: bool = False


@dataclass
class Route:
    """Une entrée de la table de routage (une par protocole candidat sur un même préfixe, par VRF)."""
    prefix: str
    protocol: str
    metric: int
    distance: int
    selected: bool  # chemin installé dans la RIB
    nexthops: list[NextHop] = field(default_factory=list)
    vrf: str = DEFAULT_VRF


@dataclass
class OspfNeighbor:
    """Un voisin OSPF (OSPFv2 dans `ospf_neighbors`, OSPFv3 dans `ospf6_neighbors`)."""
    router_id: str
    state: str      # ex. "Full/-"
    interface: str  # ex. "eth2:10.1.13.1"

    @property
    def is_full(self) -> bool:
        return self.state.startswith("Full")


@dataclass
class BgpPeer:
    """Une session BGP (par famille d'adresses : `address_family` est celle de la table résumée)."""
    neighbor: str
    remote_as: int | None
    state: str
    pfx_received: int
    pfx_sent: int
    vrf: str = DEFAULT_VRF
    address_family: str = "ipv4"   # "ipv4" ou "ipv6" (unicast)


@dataclass
class BgpPrefix:
    """Un préfixe BGP reçu ou annoncé, avec le meilleur chemin retenu."""
    prefix: str
    as_path: str  # chaîne d'AS séparés par des espaces, vide si origine locale
    next_hop: str
    best: bool
    vrf: str = DEFAULT_VRF


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
    # Phase B2 : voisins OSPFv3, sections réellement relevées et, pour chaque section non relevée, pourquoi.
    ospf6_neighbors: list[OspfNeighbor] = field(default_factory=list)
    # None = non renseigné (snapshot d'avant la phase B2, état construit à la main) : lu comme les sections
    # de la v0.3.0 de ce driver. Un driver renseigne toujours la liste, même quand tout est relevé.
    collected: list[str] | None = None
    section_errors: dict[str, str] = field(default_factory=dict)

    def has_section(self, name: str) -> bool:
        """Vrai si la section a été relevée (même vide). Faux = inconnue : jamais « rien »."""
        if name not in SECTIONS:
            raise ValueError(f"section inconnue : {name!r} (attendu : {list(SECTIONS)})")
        if self.collected is None:
            return name in _LEGACY_SECTIONS_BY_DRIVER.get(self.driver, LEGACY_SECTIONS)
        return name in self.collected

    def why_missing(self, name: str) -> str:
        """Raison lisible d'une section non relevée (pour « NON ÉVALUABLE : … »)."""
        if name in self.section_errors:
            return f"section « {name} » non relevée sur {self.name} : {self.section_errors[name]}"
        origin = ("ce relevé a été pris avant la phase B2" if self.collected is None
                  else "le driver ne la relève pas")
        return f"section « {name} » non relevée sur {self.name} ({origin})"

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
                    vrf=r.get("vrf", DEFAULT_VRF),
                )
                for r in data.get("routes", [])
            ],
            ospf_neighbors=[OspfNeighbor(**o) for o in data.get("ospf_neighbors", [])],
            bgp_peers=[BgpPeer(**p) for p in data.get("bgp_peers", [])],
            bgp_prefixes=[BgpPrefix(**b) for b in data.get("bgp_prefixes", [])],
            running_config=data.get("running_config", ""),
            driver=data.get("driver", "frr"),
            ospf6_neighbors=[OspfNeighbor(**o) for o in data.get("ospf6_neighbors", [])],
            collected=data.get("collected"),
            section_errors=dict(data.get("section_errors") or {}),
        )
