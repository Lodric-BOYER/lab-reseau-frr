"""Driver Arista EOS (cEOS-lab) : commandes `| json` -> modèle normalisé (netcheck/model.py).

Champs vérifiés EN DIRECT sur le lab cEOS (image ceos:4.34.8M, EOS 4.34.8M), pas devinés : voir
tests/fixtures/ceos/ (nominal et quatre états dégradés capturés par les six commandes ci-dessous ;
phase B2 : les relevés IPv6 et VRF, tests/fixtures/dualstack/).
Points propres à EOS, constatés sur l'équipement :

- Netmiko `device_type="arista_eos"`, identifiants par défaut de l'image admin / admin (lab).
  La session s'ouvre en MODE UTILISATEUR (invite `r4>`) : `show running-config` y répond « %
  Invalid input (privileged mode required) ». Le collecteur appelle donc la méthode `enable()`
  de Netmiko (NEEDS_ENABLE) -- aucun mot de passe `enable` n'est configuré, admin est privilège
  15 -- et jamais `send_command("enable")`.
- Liste blanche EXACTE (ALLOWED_CLI) : seules ces douze chaînes complètes, suffixe `| json`
  compris, peuvent partir vers l'équipement. Un second pipe, une redirection, `tee`, un ajout
  (`>>`) ou toute variante d'espacement sont refusés avant l'envoi.
- OSPF et BGP se lisent sous `vrfs.default` ; les routes se lisent pour TOUTES les VRF (`vrf all`). Le JSON
  EOS est verbeux ; seuls les champs nécessaires au modèle sont lus.
- Phase B2, constaté sur cEOS 4.34.8M (lab double pile, plus une VRF temporaire `TMPVRF`) : `show interfaces
  | json` ne dit ni la VRF ni l'IPv6 d'une interface. `show ipv6 interface | json` donne les adresses
  (`address` + `subnet`, d'où la longueur du préfixe) et le lien local ; `show vrf | json` donne les
  interfaces de chaque VRF. `show ip route | json` ne montre que la VRF default, `vrf all` donne une clé par
  VRF. OSPFv3 : `show ospfv3 neighbor | json` (la syntaxe `show ipv6 ospf neighbor` existe aussi, ancienne,
  non utilisée). Les types de route IPv6 sortent en minuscules (`ospf`, là où l'IPv4 dit `OSPF`).
- ASN : chaîne ("65001") -> entier. adjacencyState OSPF : minuscules ("full") -> "Full/-" comme
  le format FRR ("Full/-"), le modèle testant `startswith("Full")`. Seul l'état `full` a été
  observé : les autres sont simplement mis en majuscule initiale, pas devinés.
- Session BGP à l'arrêt par dépassement de `maximum-routes` : `peerState: "Idle"` accompagné de
  `peerStateIdleReason: "MaxPath"` -> état normalisé "Idle(MaxPath)", comme l'affiche la CLI.
- Une route statique vers Null0 sort en `routeType: "dropRoute"`, `routeAction: "drop"`, `vias:
  []` (mais `directlyConnected: true`, trompeur) : normalisée en route sans next-hop exploitable
  -- signature d'un trou noir pour `assert path`, comme la route `blackhole` de FRR.
- Interface coupée par `shutdown` : `interfaceStatus: "disabled"`, `lineProtocolStatus: "down"`.
  `hardware: "loopback"` identifie une loopback (jamais deviné d'après le nom).
- Management0 et sa route connectée apparaissent comme n'importe quelle interface : ils sont
  filtrés par l'inventaire (`management_interfaces`), comme eth0 côté FRR.
- Adresses IPv4 secondaires : jamais observées dans ce lab, donc ignorées (non devinées).
- `i686` dans `show version` : image 32 bits, normal pour cEOS-lab.
"""
from __future__ import annotations

import json

from netcheck.confparse import ParsedConfig, parse_indented
from netcheck.drivers import eos_rules
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

# Commande logique du collecteur -> commande EOS réelle. Les noms logiques sont ceux de la liste
# blanche du collecteur (inchangée par ce driver) : seule la traduction est propre à EOS.
_COMMANDS = {
    "show interface json": "show interfaces | json",
    "show ipv6 interface json": "show ipv6 interface | json",
    "show vrf json": "show vrf | json",
    "show ip route json": "show ip route vrf all | json",
    "show ipv6 route json": "show ipv6 route vrf all | json",
    "show ip ospf neighbor json": "show ip ospf neighbor | json",
    "show ipv6 ospf neighbor json": "show ospfv3 neighbor | json",
    "show bgp ipv4 unicast summary json": "show ip bgp summary | json",
    "show bgp ipv4 unicast json": "show ip bgp | json",
    "show bgp ipv6 unicast summary json": "show ipv6 bgp summary | json",
    "show bgp ipv6 unicast json": "show ipv6 bgp | json",
    "show running-config": "show running-config",
}

# routeType EOS -> `protocol` du modèle (mêmes valeurs que FRR : ospf, bgp, static, connected).
_PROTOCOLS = {"connected": "connected", "static": "static", "dropRoute": "static",
              "eBGP": "bgp", "iBGP": "bgp"}


def _protocol(route_type: str) -> str:
    # "OSPF" en IPv4, "ospf" en IPv6 ; les variantes externes : non observées
    if route_type.lower().startswith("ospf"):
        return "ospf"
    return _PROTOCOLS.get(route_type, route_type.lower() or "?")


class EosDriver(Driver):
    REQUIRED_COMMANDS = list(_COMMANDS)
    NEEDS_ENABLE = True
    ALLOWED_CLI = frozenset(_COMMANDS.values())

    # Phase A (v4) : les règles qui lisent la syntaxe d'EOS vivent dans drivers/eos_rules.py.
    CONFIG_CHECKS = eos_rules.CHECKS
    IPV6_CONFIG_PREFIXES = ("ipv6 unicast-routing", "ipv6 enable", "router ospfv3", "ospfv3 ",
                            "address-family ipv6", "ipv6 route", "ipv6 prefix-list")
    CONFIG_FILENAMES = ("startup-config",)
    # Observés : ip, interface, router, no, route-map, end, hostname, service, spanning-tree, system,
    # transceiver, username, management. Ajoutés : les commandes racines courantes d'EOS.
    ROOT_KEYWORDS = frozenset({
        "hostname", "interface", "router", "ip", "ipv6", "no", "service", "spanning-tree", "system",
        "transceiver", "username", "management", "aaa", "banner", "end", "vlan", "vrf", "logging", "ntp",
        "clock", "snmp-server", "lldp", "mpls", "daemon", "queue-monitor", "route-map", "class-map",
        "policy-map", "tacacs-server", "radius-server", "dns", "monitor", "event-handler", "errdisable",
        "hardware", "platform", "mac", "arp", "redundancy", "terminal", "boot", "alias", "ptp", "dot1x",
        "mlag", "agent", "switchport", "load-interval", "tap", "ntp", "link", "port-channel",
        "role"})    # phase C5 : `role netcheck-ro` (compte en lecture seule) fait partie de configs-ceos/r4

    def parse_config(self, running_config: str) -> ParsedConfig:
        # Blocs par indentation ; « ! » est un commentaire qui ne ferme aucun bloc (vérifié sur cEOS) ;
        # une bannière est du texte libre jusqu'à `EOF`. EOS ignore l'indentation : une sous-commande au
        # premier niveau est signalée (voir eos_rules.flag_misplaced_subcommands).
        cfg = parse_indented(running_config, raw_blocks=eos_rules.RAW_BLOCKS)
        eos_rules.flag_misplaced_subcommands(cfg)
        return cfg

    def translate(self, command: str) -> str:
        try:
            return _COMMANDS[command]
        except KeyError:
            raise PermissionError(f"commande logique inconnue du driver EOS : {command!r}") from None

    def clean_output(self, raw: str) -> str:
        # EOS signale une commande refusée par une ligne « % ... » (ex. mode non privilégié) :
        # mieux vaut échouer clairement que laisser json.loads() lever une erreur incompréhensible.
        if raw.lstrip().startswith("% "):
            raise RuntimeError(f"EOS a refusé la commande : {raw.strip()[:120]}")
        return raw

    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        s = Sections(raw)
        # Les adresses IPv6 et la VRF d'une interface viennent de deux commandes de plus : sans elles,
        # l'interface est lue comme avant la phase B2 (IPv4, VRF default).
        v6_text = raw.get("show ipv6 interface json")
        vrf_text = raw.get("show vrf json")
        interfaces = s.required("interfaces", "show interface json",
                                lambda t: self._parse_interfaces(t, v6_text, vrf_text))
        routes_v4 = s.required("routes_v4", "show ip route json", self._parse_routes)
        routes_v6 = s.optional("routes_v6", "show ipv6 route json", self._parse_routes, [])
        s.optional("vrf", "show vrf json", self._vrf_members, {})
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

    @staticmethod
    def _default_vrf(text: str) -> dict:
        """Contenu de `vrfs.default` ({} si absent : protocole non configuré, pas une erreur)."""
        return json.loads(text).get("vrfs", {}).get("default", {})

    # -- Interfaces -----------------------------------------------------------------------
    @staticmethod
    def _vrf_members(text: str) -> dict[str, str]:
        """{interface: VRF} d'après `show vrf | json` (`vrfs.<nom>.interfaces`)."""
        data = json_object(text)
        if not isinstance(data, dict):
            raise SectionUnavailable("sortie de `show vrf` inattendue")
        return {ifname: vrf for vrf, attrs in data.get("vrfs", {}).items()
                for ifname in attrs.get("interfaces", [])}

    @staticmethod
    def _ipv6_addresses(text: str) -> dict[str, tuple[list[str], str | None]]:
        """{interface: (adresses globales en CIDR, lien local)} d'après `show ipv6 interface | json`."""
        result = {}
        for ifname, attrs in json_object(text).get("interfaces", {}).items():
            globals_ = []
            for a in attrs.get("addresses", []):
                # `address` n'a pas de longueur ; elle est dans `subnet` ("2001:db8:34::2/127" pour
                # l'adresse ::3).
                length = (a.get("subnet") or "/128").rsplit("/", 1)[-1]
                globals_.append(f"{a['address']}/{length}")
            result[ifname] = (globals_, (attrs.get("linkLocal") or {}).get("address"))
        return result

    @classmethod
    def _parse_interfaces(cls, text: str, v6_text: str | None = None, vrf_text: str | None = None
                          ) -> list[Interface]:
        try:
            v6 = cls._ipv6_addresses(v6_text) if v6_text is not None else {}
        except SectionUnavailable:
            v6 = {}
        try:
            members = cls._vrf_members(vrf_text) if vrf_text is not None else {}
        except SectionUnavailable:
            members = {}
        interfaces = []
        for ifname, attrs in json.loads(text).get("interfaces", {}).items():
            addresses = []
            for entry in attrs.get("interfaceAddress", []):
                primary = entry.get("primaryIp") or {}
                address = primary.get("address")
                if address and address != "0.0.0.0":
                    addresses.append(f"{address}/{primary.get('maskLen', 32)}")
            addresses6, link_local = v6.get(ifname, ([], None))
            interfaces.append(Interface(
                name=ifname,
                description=attrs.get("description") or None,   # EOS écrit "" : le modèle veut None
                admin_up=attrs.get("interfaceStatus") != "disabled",
                oper_up=attrs.get("lineProtocolStatus") == "up",
                addresses=addresses,
                is_loopback=(attrs["hardware"] == "loopback") if "hardware" in attrs else None,
                addresses6=addresses6,
                link_local6=link_local,
                vrf=members.get(ifname, DEFAULT_VRF),
            ))
        return interfaces

    # -- Routes -----------------------------------------------------------------------------
    @staticmethod
    def _parse_routes(text: str) -> list[Route]:
        """Routes de toutes les VRF : `vrfs.<vrf>.routes` (la commande `vrf all`)."""
        data = json_object(text)
        if not isinstance(data, dict):
            raise SectionUnavailable("sortie de routes inattendue")
        routes = []
        for vrf, table in data.get("vrfs", {}).items():
            for prefix, e in table.get("routes", {}).items():
                route_type = e.get("routeType", "")
                if route_type == "dropRoute" or e.get("routeAction") == "drop":
                    # Trou noir (Null0) : aucun next-hop exploitable, même signature que FRR
                    # (NextHop sans ip ni interface). `directlyConnected: true` ne s'applique PAS ici.
                    nexthops = [NextHop(ip=None, interface=None, directly_connected=False)]
                else:
                    nexthops = [
                        NextHop(ip=via.get("nexthopAddr"), interface=via.get("interface"),
                                directly_connected=bool(e.get("directlyConnected")))
                        for via in e.get("vias", [])
                    ]
                routes.append(Route(
                    prefix=prefix,
                    protocol=_protocol(route_type),
                    metric=e.get("metric", 0),
                    distance=e.get("preference", 0),
                    selected=True,   # la table EOS ne liste que les routes installées
                    nexthops=nexthops,
                    vrf=vrf,
                ))
        return routes

    # -- OSPF -------------------------------------------------------------------------------
    @classmethod
    def _parse_ospf(cls, text: str) -> list[OspfNeighbor]:
        neighbors = []
        for instance in cls._default_vrf(text).get("instList", {}).values():
            for e in instance.get("ospfNeighborEntries", []):
                state = e.get("adjacencyState", "")
                # "Full/-" : même forme que FRR ; drState est null sur un lien point-à-point.
                neighbors.append(OspfNeighbor(
                    router_id=e["routerId"],
                    state=f"{state[:1].upper()}{state[1:]}/{e.get('drState') or '-'}",
                    interface=e.get("interfaceName", ""),
                ))
        return neighbors

    @classmethod
    def _parse_ospf6(cls, text: str) -> list[OspfNeighbor]:
        """`show ospfv3 neighbor | json` : vrfs.default.addressFamily.ipv6.ospf3NeighborEntries."""
        data = json_object(text)
        if not isinstance(data, dict):
            raise SectionUnavailable("sortie OSPFv3 inattendue")
        entries = (data.get("vrfs", {}).get("default", {}).get("addressFamily", {}).get("ipv6", {})
                   .get("ospf3NeighborEntries", []))
        neighbors = []
        for e in entries:
            state = e.get("adjacencyState", "")
            neighbors.append(OspfNeighbor(
                router_id=e["routerId"],
                state=f"{state[:1].upper()}{state[1:]}/{e.get('designatedRouter') or '-'}",
                interface=e.get("interfaceName", ""),
            ))
        return neighbors

    # -- BGP ----------------------------------------------------------------------------------
    @classmethod
    def _parse_bgp_summary(cls, text: str, family: str = "ipv4", strict: bool = False) -> list[BgpPeer]:
        peers = []
        if strict:
            json_object(text)
        for ip, attrs in cls._default_vrf(text).get("peers", {}).items():
            state = attrs.get("peerState", "absent")
            if attrs.get("peerStateIdleReason"):   # ex. "MaxPath" : affiché "Idle(MaxPath)" par la CLI
                state = f"{state}({attrs['peerStateIdleReason']})"
            asn = attrs.get("asn", "")
            peers.append(BgpPeer(
                neighbor=ip,
                remote_as=int(asn) if str(asn).isdigit() else None,
                state=state,
                pfx_received=attrs.get("prefixReceived", 0),
                pfx_sent=attrs.get("prefixAdvertised", 0),
                address_family=family,
            ))
        return peers

    @classmethod
    def _parse_bgp_prefixes(cls, text: str, strict: bool = False) -> list[BgpPrefix]:
        prefixes = []
        if strict:
            json_object(text)
        for prefix, entry in cls._default_vrf(text).get("bgpRouteEntries", {}).items():
            for path in entry.get("bgpRoutePaths", []):
                tokens = (path.get("asPathEntry") or {}).get("asPath", "").split()
                if tokens and tokens[-1] in ("i", "e", "?"):   # code d'origine, pas un AS
                    tokens = tokens[:-1]
                prefixes.append(BgpPrefix(
                    prefix=prefix,
                    as_path=" ".join(tokens),   # chaîne vide = origine locale, comme FRR
                    next_hop=path.get("nextHop", ""),
                    best=bool((path.get("routeType") or {}).get("active")),
                ))
        return prefixes
