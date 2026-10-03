"""Driver Arista EOS (cEOS-lab) : commandes `| json` -> modèle normalisé (netcheck/model.py).

Champs vérifiés EN DIRECT sur le lab cEOS (image ceos:4.34.8M, EOS 4.34.8M), pas devinés : voir
tests/fixtures/ceos/ (nominal et quatre états dégradés capturés par les six commandes ci-dessous).
Points propres à EOS, constatés sur l'équipement :

- Netmiko `device_type="arista_eos"`, identifiants par défaut de l'image admin / admin (lab).
  La session s'ouvre en MODE UTILISATEUR (invite `r4>`) : `show running-config` y répond « %
  Invalid input (privileged mode required) ». Le collecteur appelle donc la méthode `enable()`
  de Netmiko (NEEDS_ENABLE) -- aucun mot de passe `enable` n'est configuré, admin est privilège
  15 -- et jamais `send_command("enable")`.
- Liste blanche EXACTE (ALLOWED_CLI) : seules ces six chaînes complètes, suffixe `| json`
  compris, peuvent partir vers l'équipement. Un second pipe, une redirection, `tee`, un ajout
  (`>>`) ou toute variante d'espacement sont refusés avant l'envoi.
- Tout se lit sous `vrfs.default` (netcheck ne regarde que la VRF par défaut). Le JSON EOS est
  verbeux ; seuls les champs nécessaires au modèle sont lus.
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
from netcheck.model import BgpPeer, BgpPrefix, DeviceState, Interface, NextHop, OspfNeighbor, Route

# Commande logique du collecteur -> commande EOS réelle. Les noms logiques sont ceux de la liste
# blanche du collecteur (inchangée par ce driver) : seule la traduction est propre à EOS.
_COMMANDS = {
    "show interface json": "show interfaces | json",
    "show ip route json": "show ip route | json",
    "show ip ospf neighbor json": "show ip ospf neighbor | json",
    "show bgp ipv4 unicast summary json": "show ip bgp summary | json",
    "show bgp ipv4 unicast json": "show ip bgp | json",
    "show running-config": "show running-config",
}

# routeType EOS -> `protocol` du modèle (mêmes valeurs que FRR : ospf, bgp, static, connected).
_PROTOCOLS = {"connected": "connected", "static": "static", "dropRoute": "static",
              "eBGP": "bgp", "iBGP": "bgp"}


def _protocol(route_type: str) -> str:
    if route_type.startswith("OSPF"):   # "OSPF" ; les variantes externes n'ont pas été observées
        return "ospf"
    return _PROTOCOLS.get(route_type, route_type.lower() or "?")


class EosDriver(Driver):
    REQUIRED_COMMANDS = list(_COMMANDS)
    NEEDS_ENABLE = True
    ALLOWED_CLI = frozenset(_COMMANDS.values())

    # Phase A (v4) : les règles qui lisent la syntaxe d'EOS vivent dans drivers/eos_rules.py.
    CONFIG_CHECKS = eos_rules.CHECKS
    CONFIG_FILENAMES = ("startup-config",)

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

    @staticmethod
    def _default_vrf(text: str) -> dict:
        """Contenu de `vrfs.default` ({} si absent : protocole non configuré, pas une erreur)."""
        return json.loads(text).get("vrfs", {}).get("default", {})

    # -- Interfaces -----------------------------------------------------------------------
    @staticmethod
    def _parse_interfaces(text: str) -> list[Interface]:
        interfaces = []
        for ifname, attrs in json.loads(text).get("interfaces", {}).items():
            addresses = []
            for entry in attrs.get("interfaceAddress", []):
                primary = entry.get("primaryIp") or {}
                address = primary.get("address")
                if address and address != "0.0.0.0":
                    addresses.append(f"{address}/{primary.get('maskLen', 32)}")
            interfaces.append(Interface(
                name=ifname,
                description=attrs.get("description") or None,   # EOS écrit "" : le modèle veut None
                admin_up=attrs.get("interfaceStatus") != "disabled",
                oper_up=attrs.get("lineProtocolStatus") == "up",
                addresses=addresses,
                is_loopback=(attrs["hardware"] == "loopback") if "hardware" in attrs else None,
            ))
        return interfaces

    # -- Routes -----------------------------------------------------------------------------
    @classmethod
    def _parse_routes(cls, text: str) -> list[Route]:
        routes = []
        for prefix, e in cls._default_vrf(text).get("routes", {}).items():
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

    # -- BGP ----------------------------------------------------------------------------------
    @classmethod
    def _parse_bgp_summary(cls, text: str) -> list[BgpPeer]:
        peers = []
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
            ))
        return peers

    @classmethod
    def _parse_bgp_prefixes(cls, text: str) -> list[BgpPrefix]:
        prefixes = []
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
