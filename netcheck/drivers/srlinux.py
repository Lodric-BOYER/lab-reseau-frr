"""Driver Nokia SR Linux : commandes sr_cli (via la session interactive Netmiko) -> modèle
normalisé (netcheck/model.py).

Champs vérifiés sur le vrai lab (image ghcr.io/nokia/srlinux:26.7.2-519), pas devinés : voir
tests/fixtures/r5/. Différences notables avec FrrDriver, dues à des différences réelles
d'architecture SR Linux (pas des choix arbitraires) :

- Deux datastores CLI distincts : "show" (résumés courts, peu de champs) et "info from state"
  (arbre YANG complet). "show interface | as json" n'expose ni description ni admin-state ;
  "info from state interface * | as json" les expose tous les deux. On utilise donc "info from
  state" pour interfaces et routes, "show" seulement pour les voisins OSPF (le résumé y suffit).
- La RIB SR Linux ne porte pas le next-hop directement sur la route : chaque route référence un
  "next-hop-group" (entier opaque), résolu en DEUX temps -- mais dans la MÊME réponse JSON que
  la table de routage elle-même ("route-table | as json" renvoie aussi, en plus de
  "ipv4-unicast", les tableaux "next-hop-group" et "next-hop" à la racine ; pas besoin d'une
  commande séparée). route.next-hop-group pointe dans "next-hop-group" (indirection, support
  ECMP : un groupe référence une liste de next-hop, un seul élément dans ce lab), dont
  chaque next-hop[].next-hop pointe à son tour dans "next-hop" (la table finale : ip-address +
  subinterface si type=="direct" ; un type "extract" -- trafic vers le CPU, typiquement le
  sous-réseau local d'une interface elle-même -- ou "broadcast" n'a pas d'IP par nature, ce
  n'est pas une erreur). Vérifié en confirmant que la route 10.1.0.0/16 (apprise via OSPF,
  connue pour son antériorité) résout bien vers 10.2.45.1 (r4), jamais vers une IP locale.
- Pas de BGP sur r5 dans ce lab (AS65002 ne parle eBGP qu'entre r3 et r4) : bgp_peers et
  bgp_prefixes sont toujours vides, comme le prévoit Driver pour un équipement sans le protocole.
- "info from running" ne peut pas combiner "interface" et "network-instance" en une seule
  commande (chaque branche racine exige sa propre requête, vérifié en direct) : running_config
  concatène donc DEUX commandes ("show running-config" pour les interfaces, "show ospf
  running-config" pour network-instance/protocols/ospf, Phase D2), séparées par un marqueur de
  section ("# --- <nom> ---") plutôt que bout à bout. Nécessaire car les deux branches
  réutilisent la même syntaxe de bloc "interface <nom> { ... }" avec un sens différent (une
  interface physique d'un côté, une sous-interface dans une zone OSPF de l'autre) : sans
  séparateur explicite, un parseur de règle de conformité pourrait confondre les deux.
- Phase A (sécurité, O1) : deux sections de plus, par le même principe. L'authentification
  OSPF SR Linux ne porte pas de mot de passe inline sur l'interface (contrairement à FRR) :
  l'interface référence une "keychain" nommée, définie à part sous /system authentication --
  d'où une commande dédiée pour vérifier que la keychain référencée existe vraiment (et pas
  seulement que l'interface la mentionne). Une bannière de connexion vit sous /system banner.
  Vérifié en direct que la commande non restreinte ("info from running system") expose la clé
  privée TLS, le hash du mot de passe admin et la communauté SNMP en clair : jamais utilisée,
  au profit de ces deux sous-branches précises.
"""
from __future__ import annotations

import json
import re

from netcheck.confparse import ParsedConfig, combine, make_warning, parse_braces, parse_set
from netcheck.drivers import srlinux_rules
from netcheck.drivers.base import Driver
from netcheck.model import DeviceState, Interface, NextHop, OspfNeighbor, Route

# Nom d'interface loopback SR Linux : motif exact tiré du schéma YANG de l'équipement (affiché
# par sr_cli lui-même dans un message d'erreur de validation), pas une supposition de notre part.
_LOOPBACK_RE = re.compile(r"^lo(0|1[0-9][0-9]|2([0-4][0-9]|5[0-5])|[1-9][0-9]|[1-9])$")

# Les sections de running_config : (nom du marqueur, commande logique dont la sortie la remplit, chemin sous
# lequel « info from running » affiche son contenu -- relativement à ce chemin). Un seul tableau pour
# construire le texte (parse) ET le relire (parse_config), pour qu'ils ne divergent jamais.
_SECTIONS = (
    ("interface", "show running-config", ()),
    ("network-instance default protocols ospf", "show ospf running-config",
     ("network-instance", "default", "protocols", "ospf")),
    ("system authentication", "show system authentication", ("system", "authentication")),
    ("system banner", "show system banner", ("system", "banner")),
)
_SECTION_PREFIX = {name: prefix for name, _, prefix in _SECTIONS}
_MARKER = re.compile(r"# --- (.+) ---")


class SrlinuxDriver(Driver):
    REQUIRED_COMMANDS = [
        "show interface json",
        "show ip route json",
        "show ip ospf neighbor json",
        "show running-config",
        "show ospf running-config",
        "show system authentication",
        "show system banner",
    ]

    _TRANSLATION = {
        "show interface json": "info from state interface * | as json",
        "show ip route json": "info from state network-instance default route-table | as json",
        "show ip ospf neighbor json": "show network-instance default protocols ospf neighbor | as json",
        "show running-config": "info from running interface *",
        "show ospf running-config": "info from running network-instance default protocols ospf",
        "show system authentication": "info from running system authentication",
        "show system banner": "info from running system banner",
    }

    # Phase A (v4) : les règles qui lisent la syntaxe de SR Linux vivent dans drivers/srlinux_rules.py.
    CONFIG_CHECKS = srlinux_rules.CHECKS
    CONFIG_FILENAMES = ("config.cli",)

    def translate(self, command: str) -> str:
        return self._TRANSLATION[command]

    def parse_config(self, running_config: str) -> ParsedConfig:
        """Lit la configuration sous ses trois formes : la sortie du driver (sections séparées par des
        marqueurs, chacune relative à son chemin), une sortie « info from running » seule, ou un fichier
        de démarrage `set / ...`. Les trois donnent la même vue plate de chemins."""
        lines = running_config.splitlines()
        markers = [i for i, line in enumerate(lines) if _MARKER.fullmatch(line.strip())]
        if not markers:
            first = next((s for s in (line.strip() for line in lines) if s and not s.startswith("#")), "")
            return parse_set(running_config) if first.split()[:1] == ["set"] else parse_braces(running_config)

        parts, warnings = [], []
        counts = {"comment": 0, "skipped": 0, "blank": 0}

        def body_text(body: list[str]) -> str:
            # Les lignes vides qui terminent une section seraient perdues par join() puis splitlines() :
            # on les compte ici, pour que chaque ligne du texte reste dans exactement une classe.
            while body and not body[-1].strip():
                body.pop()
                counts["blank"] += 1
            return "\n".join(body)

        if markers[0] > 0:        # des lignes avant le premier marqueur : lues en accolades, sans préfixe
            parts.append((parse_braces(body_text(lines[:markers[0]])), 0))
        for n, start in enumerate(markers):
            end = markers[n + 1] if n + 1 < len(markers) else len(lines)
            name = _MARKER.fullmatch(lines[start].strip()).group(1)
            prefix = _SECTION_PREFIX.get(name)
            if prefix is None:    # une section d'un driver plus récent : lue, mais jamais ignorée en silence
                prefix = ("?", name)
                counts["skipped"] += 1
                warnings.append(make_warning(start + 1, lines[start], "section inconnue de ce driver", False))
            else:
                counts["comment"] += 1
            parts.append((parse_braces(body_text(lines[start + 1:end]), prefix=prefix), start + 1))
        return combine(parts, lines_total=len(lines), counts=counts, warnings=warnings)

    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        running_config = "\n".join(f"# --- {name} ---\n" + raw[command] for name, command, _ in _SECTIONS)
        return DeviceState(
            name=name,
            host=host,
            timestamp=self.now(),
            reachable=True,
            interfaces=self._parse_interfaces(raw["show interface json"]),
            routes=self._parse_routes(raw["show ip route json"]),
            ospf_neighbors=self._parse_ospf(raw["show ip ospf neighbor json"]),
            bgp_peers=[],
            bgp_prefixes=[],
            running_config=running_config,
        )

    # -- Interfaces -----------------------------------------------------------------------
    @staticmethod
    def _parse_interfaces(text: str) -> list[Interface]:
        data = json.loads(text)
        interfaces = []
        for attrs in data.get("interface", []):
            addresses = [
                a["ip-prefix"]
                for sub in attrs.get("subinterface", [])
                for a in sub.get("ipv4", {}).get("address", [])
                if a.get("ip-prefix")
            ]
            interfaces.append(Interface(
                name=attrs["name"],
                description=attrs.get("description"),  # absente si jamais configurée
                admin_up=attrs.get("admin-state") == "enable",
                oper_up=attrs.get("oper-state") == "up",
                addresses=addresses,
                is_loopback=bool(_LOOPBACK_RE.match(attrs["name"])),
            ))
        return interfaces

    # -- Routes -----------------------------------------------------------------------------
    @staticmethod
    def _resolve_nexthop_group(group_id: str | None, groups_by_id: dict, leaves_by_id: dict) -> list[NextHop]:
        """route.next-hop-group -> next-hop-group[] (indirection, 1 membre par groupe dans ce
        lab, plusieurs pour de l'ECMP) -> next-hop[] (table finale). Un membre de type autre
        que "direct" (extract, broadcast) n'a pas d'IP par nature : on laisse ip/interface à
        None plutôt que d'inventer une valeur (voir docstring du module)."""
        group = groups_by_id.get(group_id)
        if group is None:
            return []
        nexthops = []
        for member in group.get("next-hop", []):
            leaf = leaves_by_id.get(member.get("next-hop"), {})
            nexthops.append(NextHop(ip=leaf.get("ip-address"), interface=leaf.get("subinterface")))
        return nexthops

    @staticmethod
    def _parse_routes(text: str) -> list[Route]:
        data = json.loads(text)
        groups_by_id = {g["index"]: g for g in data.get("next-hop-group", [])}
        leaves_by_id = {n["index"]: n for n in data.get("next-hop", [])}

        routes = []
        # IPv4 uniquement (cohérent avec le reste de netcheck, §4 du cahier des charges).
        for r in data.get("ipv4-unicast", {}).get("route", []):
            nexthops = SrlinuxDriver._resolve_nexthop_group(
                r.get("next-hop-group"), groups_by_id, leaves_by_id)
            for nh in nexthops:
                nh.directly_connected = r.get("route-type") in ("local", "host")
            routes.append(Route(
                prefix=r.get("ipv4-prefix", ""),
                protocol=r.get("route-type", "?"),
                metric=r.get("metric", 0),
                # "preference" est l'équivalent SR Linux de la distance administrative FRR
                # (plus petit = préféré) : même rôle, nom différent.
                distance=r.get("preference", 0),
                selected=r.get("active", False),
                nexthops=nexthops,
            ))
        return routes

    # -- OSPF -------------------------------------------------------------------------------
    @staticmethod
    def _parse_ospf(text: str) -> list[OspfNeighbor]:
        neighbors = []
        for instance in json.loads(text).get("instances", []):
            for n in instance.get("neighbors_brief", []):
                # SR Linix renvoie l'état en minuscules ("full") ; OspfNeighbor.is_full teste
                # state.startswith("Full") (convention FRR) : on normalise la casse ici pour
                # que la propriété partagée du modèle fonctionne pour les deux drivers.
                state = n.get("State", "")
                neighbors.append(OspfNeighbor(
                    router_id=n.get("Rtr Id", ""),
                    state=state[:1].upper() + state[1:] if state else state,
                    interface=n.get("Interface-Name", ""),
                ))
        return neighbors
