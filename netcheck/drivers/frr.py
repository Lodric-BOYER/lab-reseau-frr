"""Driver FRRouting (10.x) : commandes vtysh -> modèle normalisé (netcheck/model.py).

Champs vérifiés sur le vrai lab (FRR 10.2.1), pas devinés : voir tests/fixtures/.
"""
from __future__ import annotations

import ipaddress
import json
import shlex

from netcheck.confparse import ParsedConfig, parse_indented
from netcheck.drivers import frr_rules
from netcheck.drivers.base import Driver
from netcheck.drivers.sections import Sections, SectionUnavailable, json_object
from netcheck.model import (
    DEFAULT_VRF,
    BgpPeer,
    BgpPrefix,
    DeviceState,
    Interface,
    NextHop,
    OspfNeighbor,
    Route,
)

# Commande logique -> commande vtysh, quand elle diffère du nom logique. Phase B2 : les tables de routage
# sont lues pour TOUTES les VRF (`vrf all`, sortie {vrf: {préfixe: [...]}}) ; la commande OSPFv3 de FRR
# s'appelle `ospf6`.
_TRANSLATION = {
    "show ip route json": "show ip route vrf all json",
    "show ipv6 route json": "show ipv6 route vrf all json",
    "show ipv6 ospf neighbor json": "show ipv6 ospf6 neighbor json",
}


# Phase C5 : compte en lecture seule. `privilege_wrapper: doas` (option d'inventaire) fait lancer chaque
# commande par `doas -u frr /usr/bin/vtysh` : le compte n'est pas dans le groupe `frrvty`, c'est `doas`
# (règles à arguments EXACTS, /etc/doas.conf) qui lui donne, une commande à la fois, l'identité `frr`.
# `-u` (vue native de vtysh) en seconde couche pour toutes les commandes qui l'acceptent : `show
# running-config` n'existe pas en vue.
WRAPPER_DOAS = "doas"
_DOAS = "doas -u frr /usr/bin/vtysh"
_NO_VIEW_MODE = frozenset({"show running-config"})


def _cli(command: str, wrapper: str | None) -> str:
    """La commande CLI RÉELLE d'une commande logique : la seule fonction qui fabrique ce qui part vers FRR."""
    text = shlex.quote(_TRANSLATION.get(command, command))
    if wrapper is None:
        return f"vtysh -c {text}"
    view = "" if _TRANSLATION.get(command, command) in _NO_VIEW_MODE else " -u"
    return f"{_DOAS}{view} -c {text}"


class FrrDriver(Driver):
    REQUIRED_COMMANDS = [
        "show interface json",
        "show ip route json",
        "show ipv6 route json",
        "show ip ospf neighbor json",
        "show ipv6 ospf neighbor json",
        "show bgp ipv4 unicast summary json",
        "show bgp ipv4 unicast json",
        "show bgp ipv6 unicast summary json",
        "show bgp ipv6 unicast json",
        "show running-config",
    ]

    # Phase C5 : liste blanche EXACTE des dix commandes CLI réelles (même modèle qu'EOS). Un pipe, un `;`,
    # un second `-c`, un espace de trop ou une autre commande est refusé AVANT la connexion et avant chaque
    # envoi.
    ALLOWED_CLI = frozenset(_cli(c, None) for c in REQUIRED_COMMANDS)

    def __init__(self, wrapper: str | None = None):
        if wrapper not in (None, WRAPPER_DOAS):
            raise ValueError(f"privilege_wrapper inconnu : {wrapper!r} (seule valeur : {WRAPPER_DOAS!r})")
        self.wrapper = wrapper
        if wrapper is not None:       # l'instance « doas » n'accepte QUE ses dix chaînes doas
            self.ALLOWED_CLI = frozenset(_cli(c, wrapper) for c in self.REQUIRED_COMMANDS)

    def for_router(self, router: dict) -> "Driver":
        wrapper = router.get("privilege_wrapper")
        return FrrDriver(wrapper) if wrapper and wrapper != self.wrapper else self

    # Phase A (v4) : les règles qui lisent la syntaxe de FRR vivent dans drivers/frr_rules.py.
    CONFIG_CHECKS = frr_rules.CHECKS
    IPV6_CONFIG_PREFIXES = ("router ospf6", "ipv6 ospf6", "address-family ipv6", "ipv6 route",
                            "ipv6 prefix-list")
    CONFIG_FILENAMES = ("frr.conf",)
    # Observés : exit, interface, ip, frr, router, route-map, end, hostname, log, domainname, no, service, et
    # l'en-tête de `show running-config` (Building, Current). Ajoutés : les commandes racines courantes.
    ROOT_KEYWORDS = frozenset({
        "frr", "hostname", "domainname", "service", "log", "line", "password", "enable", "banner", "no", "ip",
        "ipv6", "interface", "router", "route-map", "access-list", "bgp", "vrf", "debug", "end", "exit",
        "exit-vrf", "mpls", "segment-routing", "bfd", "key", "agentx", "nexthop-group", "pbr-map", "rpki",
        "table", "affinity-map", "fpm", "zebra", "Building", "Current"})

    def parse_config(self, running_config: str) -> ParsedConfig:
        # Blocs par indentation ; « ! » est un séparateur, « exit » une ligne comme une autre. FRR,
        # lui, ignore l'indentation : une sous-commande au premier niveau est signalée (voir
        # frr_rules.flag_misplaced_subcommands).
        cfg = parse_indented(running_config)
        frr_rules.flag_misplaced_subcommands(cfg)
        return cfg

    def translate(self, command: str) -> str:
        return _cli(command, self.wrapper)

    def clean_output(self, raw: str) -> str:
        # vtysh non-root avertit qu'il ne lit pas vtysh.conf : bruit sans conséquence (cf.
        # automation/labtools.py, même filtre pour rester cohérent avec health/backup/drift).
        out = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("% Can't open configuration file")
        )
        for marker in ("command not found", "failed to connect to any daemons", "doas: "):
            if marker in out.lower():
                raise RuntimeError(f"vtysh inutilisable : {out.strip()[:120]}")
        return out

    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        s = Sections(raw)
        interfaces = s.required("interfaces", "show interface json", self._parse_interfaces)
        # Les routes sont lues pour toutes les VRF (`vrf all`). Une sortie au format d'avant la phase B2
        # (celle de `show ip route json`, par préfixe et non par VRF) ne contient que la VRF « default » :
        # la section « vrf » n'est alors pas relevée.
        routes_v4, vrf_aware = self._read_routes(raw["show ip route json"])
        s.collected.append("routes_v4")
        routes_v6 = s.optional("routes_v6", "show ipv6 route json", self._parse_routes, [])
        s.mark("vrf", vrf_aware,
               "les routes ne sont lues que pour la VRF default (relevé d'avant la phase B2)")
        ospf = s.required("ospf_v2", "show ip ospf neighbor json", self._parse_ospf)
        ospf6 = s.optional("ospf_v3", "show ipv6 ospf neighbor json", self._parse_ospf6, [])
        peers = s.required("bgp_v4", "show bgp ipv4 unicast summary json",
                           lambda t: self._parse_bgp_summary(t, "ipv4"))
        prefixes = self._parse_bgp_prefixes(raw["show bgp ipv4 unicast json"])
        v6 = s.optional(
            "bgp_v6", ("show bgp ipv6 unicast summary json", "show bgp ipv6 unicast json"),
            lambda summary, table: (self._parse_bgp_summary(summary, "ipv6", strict=True),
                                    self._parse_bgp_prefixes(table, strict=True)),
            ([], []))
        config = s.required("config", "show running-config", lambda t: t)
        return DeviceState(
            name=name,
            host=host,
            timestamp=self.now(),
            reachable=True,
            interfaces=interfaces,
            routes=routes_v4 + routes_v6,
            ospf_neighbors=ospf,
            bgp_peers=peers + v6[0],
            bgp_prefixes=prefixes + v6[1],
            running_config=config,
            ospf6_neighbors=ospf6,
            collected=s.collected,
            section_errors=s.errors,
        )

    # -- Interfaces -----------------------------------------------------------------------
    @staticmethod
    def _parse_interfaces(text: str) -> list[Interface]:
        data = json.loads(text)
        interfaces = []
        for ifname, attrs in data.items():
            vrf = attrs.get("vrfName") or DEFAULT_VRF
            # Le périphérique d'une VRF (`DEMO`) est listé comme une interface sans adresse : c'est la VRF
            # elle-même, pas un port. Il est écarté ; la VRF existe par ses interfaces et ses routes.
            if vrf != DEFAULT_VRF and ifname == vrf:
                continue
            v4, v6, link_local = [], [], None
            for a in attrs.get("ipAddresses", []):
                address = a["address"]
                if ":" not in address:
                    v4.append(address)
                elif ipaddress.ip_interface(address).ip.is_link_local:
                    link_local = address.split("/")[0]
                else:
                    v6.append(address)
            interfaces.append(Interface(
                name=ifname,
                description=attrs.get("description"),  # absente sur eth0/lo : reste à None
                admin_up=attrs.get("administrativeStatus") == "up",
                oper_up=attrs.get("operationalStatus") == "up",
                addresses=v4,
                # FRR expose toujours "type" ("Ethernet"/"Loopback"/...), même interface
                # coupée (admin down) : jamais None pour ce driver, contrairement au champ
                # par défaut du modèle qui reste optionnel pour un futur driver moins bavard.
                is_loopback=attrs.get("type") == "Loopback",
                addresses6=v6,
                link_local6=link_local,
                vrf=vrf,
            ))
        return interfaces

    # -- Routes -----------------------------------------------------------------------------
    @staticmethod
    def _read_routes(text: str) -> tuple[list[Route], bool]:
        """(routes, la sortie était-elle par VRF ?). `vrf all` rend {vrf: {préfixe: [entrées]}} ; la sortie
        d'une commande sans `vrf all` rend {préfixe: [entrées]} (VRF default seulement)."""
        data = json_object(text)
        if not isinstance(data, dict):
            raise SectionUnavailable("sortie de routes inattendue")
        by_vrf = bool(data) and all(isinstance(v, dict) for v in data.values())
        tables = data if by_vrf else {DEFAULT_VRF: data}
        routes = []
        for vrf, table in tables.items():
            for prefix, entries in table.items():
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
                        vrf=vrf,
                    ))
        # Une table vide ({}) est celle d'un équipement sans route : relevée, vide. Faute de clé « VRF », on
        # ne sait pas si les autres VRF ont été lues : on dit « par VRF » seulement si la sortie l'était
        # vraiment.
        return routes, by_vrf

    @classmethod
    def _parse_routes(cls, text: str) -> list[Route]:
        return cls._read_routes(text)[0]

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

    @staticmethod
    def _parse_ospf6(text: str) -> list[OspfNeighbor]:
        """`show ipv6 ospf6 neighbor json` : {"neighbors": [{neighborId, state, interfaceName, ...}]}."""
        data = json_object(text)
        if not isinstance(data, dict):
            raise SectionUnavailable("sortie OSPFv3 inattendue")
        return [
            OspfNeighbor(router_id=e.get("neighborId", ""), state=e.get("state", ""),
                         interface=e.get("interfaceName", ""))
            for e in data.get("neighbors", [])
        ]

    # -- BGP ----------------------------------------------------------------------------------
    @staticmethod
    def _parse_bgp_summary(text: str, family: str = "ipv4", strict: bool = False) -> list[BgpPeer]:
        # Sans BGP dans cette famille, FRR répond `{}` ou `{"warning": "Default BGP instance not found"}` :
        # une section relevée mais vide. `strict` (IPv6, facultative) refuse en plus une sortie qui n'est
        # pas du JSON.
        data = json_object(text) if strict else json.loads(text)
        peers = data.get("peers", {})
        return [
            BgpPeer(
                neighbor=ip,
                remote_as=attrs.get("remoteAs"),
                state=attrs.get("state", "absent"),
                pfx_received=attrs.get("pfxRcd", 0),
                pfx_sent=attrs.get("pfxSnt", 0),
                address_family=family,
            )
            for ip, attrs in peers.items()
        ]

    @staticmethod
    def _parse_bgp_prefixes(text: str, strict: bool = False) -> list[BgpPrefix]:
        data = json_object(text) if strict else json.loads(text)
        routes = data.get("routes", {})
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
