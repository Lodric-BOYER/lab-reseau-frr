"""Moteur d'assertions d'état attendu (`netcheck assert`, Phase C, SPEC_v3 §6, objectif O2).

Format d'un fichier d'intent (voir aussi le commentaire en tête de intents/lab.yml) :
  id: identifiant court et unique
  description: phrase humaine
  device: équipement sur lequel l'assertion porte (point de départ pour "path")
  type: un des 6 types ci-dessous
  ...  paramètres propres au type (voir chaque évaluateur _check_*)

Toutes les assertions sont évaluées UNIQUEMENT sur le modèle normalisé (model.py), jamais sur
le texte de la config : elles fonctionnent identiquement pour FRR et SR Linux.

Phase B2 (v4) : IPv6 et VRF.
  family: ipv4 | ipv6   (ospf_neighbors : OSPFv2 ou OSPFv3 ; bgp_session : famille de la session, déduite
                         de l'adresse du voisin si absente ; les types de route et `path` la déduisent
                         du préfixe)
  vrf: nom de VRF       (défaut « default » ; `path` reste dans la VRF de départ)
Une assertion qui a besoin d'une section que le relevé ne contient pas (IPv6 d'un relevé de la v0.3.0, BGP de
SR Linux, VRF d'un driver qui ne la lit pas) est NON ÉVALUABLE, avec la raison : jamais OK, jamais ÉCHEC.
Un next-hop IPv6 de lien local (fe80::) est résolu par la PAIRE (adresse, interface de sortie) : l'équipement
qui porte cette adresse sur une interface du même lien. Introuvable ou ambigu : NON ÉVALUABLE.

Sécurité : mêmes principes que compliance.py -- yaml.safe_load exclusivement.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from netcheck import management
from netcheck.model import DEFAULT_VRF, DeviceState, Interface, Route

KNOWN_TYPES = {
    "bgp_session",
    "ospf_neighbors",
    "route_present",
    "route_absent",
    "interface_up",
    "path",
}
REQUIRED_FIELDS = {"id", "description", "device", "type"}

# Profondeur maximale d'un chemin logique (Phase C, protection contre une boucle non détectée
# par ailleurs ou une topologie anormalement longue) -- largement au-dessus de la taille de ce
# lab (5 équipements), jamais une limite réaliste à atteindre légitimement ici.
MAX_PATH_HOPS = 16


class Status(str, Enum):
    OK = "OK"
    ECHEC = "ÉCHEC"
    NON_EVALUABLE = "NON ÉVALUABLE"


@dataclass
class Assertion:
    id: str
    description: str
    device: str
    type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssertionResult:
    assertion: Assertion
    status: Status
    detail: str = ""


# ------------------------------------------------------------------------------------------
# Chargement et validation
# ------------------------------------------------------------------------------------------

def load_intent(path: str | Path) -> list[Assertion]:
    """Charge et valide un fichier d'intent (intents/*.yml)."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"{path} : fichier YAML invalide ou refusé : {e}") from e

    if not data:
        return []
    raw_assertions = data.get("assertions") if isinstance(data, dict) else data
    if raw_assertions is None:
        raise ValueError(f"{path} : clé 'assertions' absente")
    if not isinstance(raw_assertions, list):
        raise ValueError(f"{path} : 'assertions' doit être une liste")

    return validate_assertions(raw_assertions, path)


def validate_assertions(raw_assertions: list[Any], path: Path) -> list[Assertion]:
    """Valide une liste brute d'assertions (déjà lue depuis du YAML) -- partagée avec la
    section `after` d'un fichier --expect (Phase D1), pour que les deux formats ne divergent
    jamais."""
    assertions = [_validate_assertion(raw, index=i, path=path) for i, raw in enumerate(raw_assertions)]
    _check_unique_ids(assertions, path)
    return assertions


# Paramètres obligatoires par type, vérifiés AU CHARGEMENT (Phase D1) et non plus seulement à
# l'évaluation : `guard --expect` ne doit jamais découvrir une assertion `after` mal formée
# APRÈS avoir exécuté le script de changement.
_REQUIRED_PARAMS = {
    "bgp_session": ("neighbor",),
    "ospf_neighbors": ("count",),
    "route_present": ("prefix",),
    "route_absent": ("prefix",),
    "interface_up": ("interface",),
    "path": ("prefix", "via"),
}


FAMILIES = ("ipv4", "ipv6")


def _validate_params(raw: dict, label: str, path: Path) -> None:
    missing = [p for p in _REQUIRED_PARAMS[raw["type"]] if raw.get(p) in (None, "")]
    if missing:
        raise ValueError(
            f"{path} : {label} : paramètre(s) manquant(s) pour le type {raw['type']} : {missing}")
    if "family" in raw and raw["family"] not in FAMILIES:
        raise ValueError(f"{path} : {label} : family doit être 'ipv4' ou 'ipv6' (reçu : {raw['family']!r})")
    if "vrf" in raw and (not isinstance(raw["vrf"], str) or not raw["vrf"]):
        raise ValueError(f"{path} : {label} : vrf doit être un nom de VRF non vide (reçu : {raw['vrf']!r})")
    # Une famille qui contredit le PRÉFIXE serait une assertion qui ne peut jamais dire vrai : refusée au
    # chargement. Pour une session BGP, la famille n'est pas celle de l'adresse du voisin (un voisin IPv6 peut
    # porter la famille IPv4, RFC 5549) : elle n'est pas contrôlée, et sert de défaut quand elle est absente.
    value = raw.get("prefix")
    if "family" in raw and isinstance(value, str):
        try:
            version = ipaddress.ip_network(value, strict=False).version
        except ValueError:
            version = None
        if version is not None and f"ipv{version}" != raw["family"]:
            raise ValueError(f"{path} : {label} : family {raw['family']} contredit prefix {value}")
    if raw["type"] == "path":
        if raw.get("mode", "all") not in ("all", "any"):
            raise ValueError(f"{path} : {label} : mode doit être 'all' ou 'any' (reçu : {raw['mode']!r})")
        if not isinstance(raw["via"], list):
            raise ValueError(f"{path} : {label} : 'via' doit être une liste d'équipements")
        try:
            ipaddress.ip_network(raw["prefix"])
        except ValueError as e:
            raise ValueError(f"{path} : {label} : prefix invalide ({raw['prefix']}) : {e}") from e


def _validate_assertion(raw: Any, index: int, path: Path) -> Assertion:
    label = raw.get("id", f"assertion #{index}") if isinstance(raw, dict) else f"assertion #{index}"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} : {label} : une assertion doit être un objet YAML (clé: valeur)")

    missing = REQUIRED_FIELDS - set(raw)
    if missing:
        raise ValueError(f"{path} : {label} : champ(s) obligatoire(s) manquant(s) : {sorted(missing)}")

    if raw["type"] not in KNOWN_TYPES:
        raise ValueError(
            f"{path} : {label} : type '{raw['type']}' inconnu (attendu : {sorted(KNOWN_TYPES)})"
        )

    _validate_params(raw, label, path)

    params = {k: v for k, v in raw.items() if k not in REQUIRED_FIELDS}
    return Assertion(id=raw["id"], description=raw["description"], device=raw["device"],
                      type=raw["type"], params=params)


def _check_unique_ids(assertions: list[Assertion], path: Path) -> None:
    seen = set()
    for a in assertions:
        if a.id in seen:
            raise ValueError(f"{path} : id d'assertion en double : '{a.id}'")
        seen.add(a.id)


# ------------------------------------------------------------------------------------------
# Évaluation
# ------------------------------------------------------------------------------------------

def evaluate(
    assertions: list[Assertion],
    devices: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
    management_vrfs: set[str] | None = None,
) -> list[AssertionResult]:
    """Applique chaque assertion. `devices` est filtré une seule fois (interfaces/routes de
    management retirées, comme compliance.evaluate) puis passé entier à chaque évaluateur :
    "path" a besoin de tous les équipements pour traverser les sauts, les autres types n'en
    lisent qu'un (assertion.device)."""
    mgmt = set(management_interfaces or ())
    filtered = {name: management.filtered(state, mgmt, set(management_vrfs or ()))
                for name, state in devices.items()}
    return [_EVALUATORS[a.type](a, filtered) for a in assertions]


def verdict(results: list[AssertionResult]) -> tuple[str, int]:
    """Codes retour (§6) : 0 tout OK (NON ÉVALUABLE n'y change rien), 2 au moins un ÉCHEC."""
    if any(r.status == Status.ECHEC for r in results):
        return "ÉCHEC", 2
    return "OK", 0


def _unreachable(assertion: Assertion, devices: dict[str, DeviceState]) -> DeviceState | None:
    """DeviceState de assertion.device si présent et joignable, sinon None (appelant renvoie
    alors NON ÉVALUABLE) -- factorisé, commun aux 5 types à un seul équipement."""
    state = devices.get(assertion.device)
    if state is None or not state.reachable:
        return None
    return state


def _vrf_of(assertion: Assertion) -> str:
    return assertion.params.get("vrf") or DEFAULT_VRF


def _in_vrf(vrf: str) -> str:
    return "" if vrf == DEFAULT_VRF else f" (VRF {vrf})"


def _family_of_prefix(prefix: str) -> str:
    """ipv4 / ipv6 d'après un préfixe ; une valeur illisible reste « ipv4 » (comportement d'avant la phase
    B2 : la recherche exacte ne trouvera rien et l'assertion échouera, comme avant)."""
    try:
        return f"ipv{ipaddress.ip_network(prefix, strict=False).version}"
    except ValueError:
        return "ipv4"


def _missing_section(assertion: Assertion, state: DeviceState, *sections: str) -> AssertionResult | None:
    """NON ÉVALUABLE si une section nécessaire n'a pas été relevée (jamais OK, jamais ÉCHEC), sinon None."""
    for section in sections:
        if not state.has_section(section):
            return AssertionResult(assertion, Status.NON_EVALUABLE, state.why_missing(section))
    return None


def _vrf_sections(vrf: str) -> tuple[str, ...]:
    return () if vrf == DEFAULT_VRF else ("vrf",)


def _same_ip(a: str | None, b: str | None) -> bool:
    """Égalité d'adresses, insensible à la forme d'écriture (IPv6 compressée ou non, casse)."""
    if a is None or b is None:
        return a == b
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def _same_prefix(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b


# ------------------------------------------------------------------------------------------
# bgp_session
# ------------------------------------------------------------------------------------------

def _check_bgp_session(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    neighbor = assertion.params.get("neighbor")
    if not neighbor:
        raise ValueError(f"assertion '{assertion.id}' (bgp_session) : paramètre 'neighbor' manquant")
    expected_state = assertion.params.get("state", "Established")
    min_pfx = assertion.params.get("min_prefixes_received")
    vrf = _vrf_of(assertion)
    family = assertion.params.get("family") or _family_of_prefix(neighbor)

    # Les sessions BGP des VRF autres que default ne sont relevées par aucun driver (section « bgp_vrf »).
    needed = ("bgp_v6" if family == "ipv6" else "bgp_v4",) + (("bgp_vrf",) if vrf != DEFAULT_VRF else ())
    if (missing := _missing_section(assertion, state, *needed)) is not None:
        return missing
    where = f"{assertion.device}{_in_vrf(vrf)}"

    peer = next((p for p in state.bgp_peers
                 if _same_ip(p.neighbor, neighbor) and p.vrf == vrf and p.address_family == family), None)
    if peer is None:
        return AssertionResult(assertion, Status.ECHEC, f"aucune session BGP vers {neighbor} sur {where}")
    if peer.state != expected_state:
        return AssertionResult(assertion, Status.ECHEC,
            f"session BGP {neighbor} sur {where} : état {peer.state}, attendu {expected_state}")
    if min_pfx is not None and peer.pfx_received < min_pfx:
        return AssertionResult(assertion, Status.ECHEC,
            f"session BGP {neighbor} sur {where} : {peer.pfx_received} préfixe(s) "
            f"reçu(s), attendu au moins {min_pfx}")
    return AssertionResult(assertion, Status.OK)


# ------------------------------------------------------------------------------------------
# ospf_neighbors
# ------------------------------------------------------------------------------------------

def _check_ospf_neighbors(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    expected_count = assertion.params.get("count")
    if expected_count is None:
        raise ValueError(f"assertion '{assertion.id}' (ospf_neighbors) : paramètre 'count' manquant")
    expected_state = assertion.params.get("state", "Full")
    family = assertion.params.get("family", "ipv4")
    name = "OSPFv3" if family == "ipv6" else "OSPF"

    if _vrf_of(assertion) != DEFAULT_VRF:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                "les voisins OSPF des VRF autres que default "
                                "ne sont relevés par aucun driver")
    section = "ospf_v3" if family == "ipv6" else "ospf_v2"
    if (missing := _missing_section(assertion, state, section)) is not None:
        return missing
    neighbors = state.ospf6_neighbors if family == "ipv6" else state.ospf_neighbors

    actual = sum(1 for n in neighbors if n.state.startswith(expected_state))
    if actual != expected_count:
        return AssertionResult(assertion, Status.ECHEC,
            f"{assertion.device} : {actual} voisin(s) {name} {expected_state}, "
            f"attendu exactement {expected_count}")
    return AssertionResult(assertion, Status.OK)


# ------------------------------------------------------------------------------------------
# route_present / route_absent (correspondance EXACTE du préfixe, pas de LPM -- voir "path"
# pour la recherche de la route la plus précise)
# ------------------------------------------------------------------------------------------

def _selected_route(state: DeviceState, prefix: str, vrf: str = DEFAULT_VRF) -> Route | None:
    return next((r for r in state.routes
                 if _same_prefix(r.prefix, prefix) and r.vrf == vrf and r.selected), None)


def _route_sections(prefix: str, vrf: str) -> tuple[str, ...]:
    return ("routes_v6" if _family_of_prefix(prefix) == "ipv6" else "routes_v4",) + _vrf_sections(vrf)


def _check_route_present(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    prefix = assertion.params.get("prefix")
    if not prefix:
        raise ValueError(f"assertion '{assertion.id}' (route_present) : paramètre 'prefix' manquant")
    vrf = _vrf_of(assertion)
    if (missing := _missing_section(assertion, state, *_route_sections(prefix, vrf))) is not None:
        return missing
    where = f"{assertion.device}{_in_vrf(vrf)}"

    route = _selected_route(state, prefix, vrf)
    if route is None:
        return AssertionResult(assertion, Status.ECHEC, f"{where} ne connaît pas {prefix}")

    expected_protocol = assertion.params.get("protocol")
    if expected_protocol and route.protocol != expected_protocol:
        return AssertionResult(assertion, Status.ECHEC,
            f"{prefix} sur {where} : protocole {route.protocol}, attendu {expected_protocol}")

    expected_nh = assertion.params.get("next_hop")
    if expected_nh and not any(_same_ip(nh.ip, expected_nh) for nh in route.nexthops):
        return AssertionResult(assertion, Status.ECHEC,
            f"{prefix} sur {where} : next-hop {expected_nh} absent "
            f"(obtenu {[nh.ip for nh in route.nexthops]})")

    expected_if = assertion.params.get("interface")
    if expected_if and not any(nh.interface == expected_if for nh in route.nexthops):
        return AssertionResult(assertion, Status.ECHEC,
            f"{prefix} sur {where} : interface {expected_if} absente "
            f"(obtenu {[nh.interface for nh in route.nexthops]})")

    return AssertionResult(assertion, Status.OK)


def _check_route_absent(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    prefix = assertion.params.get("prefix")
    if not prefix:
        raise ValueError(f"assertion '{assertion.id}' (route_absent) : paramètre 'prefix' manquant")
    vrf = _vrf_of(assertion)
    if (missing := _missing_section(assertion, state, *_route_sections(prefix, vrf))) is not None:
        return missing

    if _selected_route(state, prefix, vrf) is not None:
        return AssertionResult(assertion, Status.ECHEC,
                                f"{assertion.device}{_in_vrf(vrf)} connaît {prefix} "
                                f"alors qu'il ne devrait pas")
    return AssertionResult(assertion, Status.OK)


# ------------------------------------------------------------------------------------------
# interface_up
# ------------------------------------------------------------------------------------------

def _check_interface_up(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    name = assertion.params.get("interface")
    if not name:
        raise ValueError(f"assertion '{assertion.id}' (interface_up) : paramètre 'interface' manquant")
    # Sans `vrf`, l'interface est cherchée par son nom seul (comportement d'avant la phase B2).
    vrf = assertion.params.get("vrf")
    needed = ("interfaces",) + (_vrf_sections(vrf) if vrf else ())
    if (missing := _missing_section(assertion, state, *needed)) is not None:
        return missing

    iface = next((i for i in state.interfaces if i.name == name and (vrf is None or i.vrf == vrf)), None)
    if iface is None:
        return AssertionResult(assertion, Status.ECHEC,
                                f"interface {name} absente sur {assertion.device}"
                                f"{_in_vrf(vrf) if vrf else ''}")
    if not (iface.admin_up and iface.oper_up):
        return AssertionResult(assertion, Status.ECHEC,
            f"interface {name} sur {assertion.device} : admin_up={iface.admin_up}, oper_up={iface.oper_up}")
    return AssertionResult(assertion, Status.OK)


# ------------------------------------------------------------------------------------------
# path -- le type le plus riche (voir la docstring du module et les échanges de conception)
# ------------------------------------------------------------------------------------------

def _canonical(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _ip_to_device(devices: dict[str, DeviceState], vrf: str = DEFAULT_VRF) -> dict[str, set[str]]:
    """{ip: {noms d'équipements}} d'après les interfaces DE LA VRF (déjà filtrées des interfaces de
    management par evaluate()) : IPv4 et IPv6 globales. Plusieurs noms pour une même IP = conflit, résolu
    comme NON ÉVALUABLE au moment du lookup (jamais deviné lequel des deux est le bon). Les adresses de
    lien local n'y sont PAS : elles ne sont pas uniques hors du lien (voir _resolve_link_local)."""
    owners: dict[str, set[str]] = {}
    for name, state in devices.items():
        for iface in state.interfaces:
            if iface.vrf != vrf:
                continue
            for addr in iface.addresses + iface.addresses6:
                try:
                    ip = str(ipaddress.ip_interface(addr).ip)
                except ValueError:
                    continue
                owners.setdefault(ip, set()).add(name)
    return owners


def _most_specific_route(state: DeviceState, target: ipaddress.IPv4Network | ipaddress.IPv6Network,
                         vrf: str = DEFAULT_VRF) -> Route | None:
    """Route sélectionnée de la VRF qui couvre `target` avec le préfixe le plus long (longest prefix
    match) -- ex. r4 atteint les sous-réseaux de l'AS65001 via l'agrégat 10.1.0.0/16, sans
    entrée exacte pour chacun d'eux."""
    best, best_len = None, -1
    for r in state.routes:
        if not r.selected or r.vrf != vrf:
            continue
        try:
            net = ipaddress.ip_network(r.prefix)
        except ValueError:
            continue
        if net.version != target.version:
            continue
        if target.subnet_of(net) and net.prefixlen > best_len:
            best, best_len = r, net.prefixlen
    return best


def _is_blackhole(route: Route) -> bool:
    """Route sélectionnée mais sans next-hop exploitable (Null0 / blackhole / reject) : un
    trou noir, fait observable -- ÉCHEC, jamais NON ÉVALUABLE (voir la docstring du module)."""
    if not route.nexthops:
        return True
    return all(nh.ip is None and nh.interface is None and not nh.directly_connected
               for nh in route.nexthops)


def _is_link_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 6 and addr.is_link_local


def _interface_named(state: DeviceState, name: str | None, vrf: str) -> Interface | None:
    """L'interface de la VRF désignée par un next-hop. SR Linux nomme le next-hop par sa sous-interface
    (`ethernet-1/1.0`) et l'interface par son port (`ethernet-1/1`)."""
    if not name:
        return None
    for i in state.interfaces:
        if i.vrf == vrf and (i.name == name or name.rsplit(".", 1)[0] == i.name):
            return i
    return None


def _networks(iface: Interface) -> list:
    nets = []
    for addr in iface.addresses + iface.addresses6:
        try:
            nets.append(ipaddress.ip_interface(addr).network)
        except ValueError:
            continue
    return nets


def _share_a_link(a: Interface, b: Interface) -> bool:
    """Deux interfaces sont sur le même lien quand une adresse de l'une est dans un réseau de l'autre."""
    def addresses(i):
        out = []
        for addr in i.addresses + i.addresses6:
            try:
                out.append(ipaddress.ip_interface(addr).ip)
            except ValueError:
                continue
        return out
    return any(ip in net for net in _networks(a) for ip in addresses(b) if ip.version == net.version)


def _resolve_link_local(devices: dict[str, DeviceState], current: str, nh,
                        vrf: str) -> tuple[str | None, str]:
    """(équipement, raison). Un next-hop fe80:: se résout par la paire (adresse, interface de sortie) : on
    cherche l'équipement dont une interface PORTE cette adresse ET est sur le même lien que l'interface
    de sortie. L'adresse seule ne suffit jamais (la même fe80:: peut exister sur plusieurs liens). Rien
    ou plusieurs : (None, raison)."""
    here = _interface_named(devices[current], nh.interface, vrf)
    if here is None:
        return None, (f"next-hop {nh.ip} sur {current} : interface de sortie {nh.interface or '?'} "
                      f"introuvable dans le relevé")
    if not _networks(here):
        return None, (f"next-hop {nh.ip} sur {current} : l'interface de sortie {here.name} n'a "
                      f"aucune adresse, le lien est indéterminable")
    target = _canonical(nh.ip)
    found = sorted({
        name for name, state in devices.items() if name != current and state.reachable
        for i in state.interfaces
        if i.vrf == vrf and i.link_local6 and _canonical(i.link_local6) == target and _share_a_link(here, i)
    })
    if not found:
        return None, (f"next-hop {nh.ip} sur {current} ({here.name}) : aucun équipement ne porte cette "
                      f"adresse de lien local sur le même lien")
    if len(found) > 1:
        return None, (f"next-hop {nh.ip} sur {current} ({here.name}) : adresse de lien local portée sur "
                      f"ce lien par plusieurs équipements ({', '.join(found)})")
    return found[0], ""


def _trace(
    devices: dict[str, DeviceState], ip_owners: dict[str, set[str]],
    target: ipaddress.IPv4Network | ipaddress.IPv6Network, current: str, visited: tuple[str, ...],
    vrf: str = DEFAULT_VRF,
) -> list[tuple[str, Any]]:
    """Explore toutes les branches ECMP depuis `current`. Renvoie une liste de
    (nature, donnée) : ("resolved", [séquence de routeurs]) un chemin complet trouvé,
    ("echec", raison) un trou noir (fait observable), ("non_evaluable", raison) une limite de
    la méthode (boucle, profondeur, routeur ou next-hop inconnu, section non relevée)."""
    if current in visited:
        return [("non_evaluable", f"boucle détectée : {' -> '.join(visited + (current,))}")]
    if len(visited) >= MAX_PATH_HOPS:
        return [("non_evaluable", f"profondeur maximale ({MAX_PATH_HOPS} sauts) dépassée")]
    visited = visited + (current,)

    state = devices.get(current)
    if state is None or not state.reachable:
        return [("non_evaluable", f"équipement {current} absent du relevé ou injoignable")]
    section = ("routes_v6" if target.version == 6 else "routes_v4")
    for needed in (section,) + _vrf_sections(vrf) + ("interfaces",):
        if not state.has_section(needed):
            return [("non_evaluable", state.why_missing(needed))]

    route = _most_specific_route(state, target, vrf)
    if route is None:
        return [("echec", f"trou noir sur {current} : aucune route ne couvre {target}")]
    if _is_blackhole(route):
        return [("echec",
                  f"trou noir sur {current} : route {route.prefix} ({route.protocol}) "
                  f"sans next-hop exploitable")]

    if any(nh.directly_connected for nh in route.nexthops):
        return [("resolved", list(visited))]

    outcomes: list[tuple[str, Any]] = []
    for nh in route.nexthops:
        if nh.ip is None:
            outcomes.append(("non_evaluable",
                f"next-hop sans IP exploitable sur {current} (route {route.prefix})"))
            continue
        if _is_link_local(nh.ip):
            nxt, reason = _resolve_link_local(devices, current, nh, vrf)
            if nxt is None:
                outcomes.append(("non_evaluable", reason))
                continue
            outcomes.extend(_trace(devices, ip_owners, target, nxt, visited, vrf))
            continue
        owners = ip_owners.get(_canonical(nh.ip))
        if not owners:
            outcomes.append(("non_evaluable",
                f"next-hop {nh.ip} (sur {current}) ne correspond à aucun équipement connu"))
            continue
        if len(owners) > 1:
            outcomes.append(("non_evaluable",
                f"adresse {nh.ip} portée par plusieurs équipements ({', '.join(sorted(owners))})"))
            continue
        outcomes.extend(_trace(devices, ip_owners, target, next(iter(owners)), visited, vrf))
    return outcomes


def _check_path(assertion: Assertion, devices: dict[str, DeviceState]) -> AssertionResult:
    prefix = assertion.params.get("prefix")
    via = assertion.params.get("via")
    if not prefix or via is None:
        raise ValueError(f"assertion '{assertion.id}' (path) : paramètres 'prefix' et 'via' requis")
    mode = assertion.params.get("mode", "all")
    if mode not in ("all", "any"):
        raise ValueError(
            f"assertion '{assertion.id}' (path) : mode doit être 'all' ou 'any' (reçu : {mode!r})")

    state = _unreachable(assertion, devices)
    if state is None:
        return AssertionResult(assertion, Status.NON_EVALUABLE,
                                f"équipement {assertion.device} absent du relevé ou injoignable")
    try:
        target = ipaddress.ip_network(prefix)
    except ValueError as e:
        raise ValueError(f"assertion '{assertion.id}' (path) : prefix invalide ({prefix}) : {e}") from e

    vrf = _vrf_of(assertion)
    family = assertion.params.get("family")
    if family and family != f"ipv{target.version}":
        raise ValueError(f"assertion '{assertion.id}' (path) : family {family} contredit prefix {prefix}")
    expected = [assertion.device] + list(via)
    ip_owners = _ip_to_device(devices, vrf)
    outcomes = _trace(devices, ip_owners, target, assertion.device, (), vrf)

    resolved = [seq for nature, seq in outcomes if nature == "resolved"]
    echecs = [reason for nature, reason in outcomes if nature == "echec"]
    non_evals = [reason for nature, reason in outcomes if nature == "non_evaluable"]
    matches = [p for p in resolved if p == expected]
    mismatches = [p for p in resolved if p != expected]

    def _mismatch_detail(path: list[str]) -> str:
        return f"attendu {' '.join(expected)}, obtenu {' '.join(path)}"

    if mode == "all":
        if echecs:
            return AssertionResult(assertion, Status.ECHEC, echecs[0])
        if mismatches:
            return AssertionResult(assertion, Status.ECHEC, _mismatch_detail(mismatches[0]))
        if non_evals:
            return AssertionResult(assertion, Status.NON_EVALUABLE, non_evals[0])
        return AssertionResult(assertion, Status.OK)

    # mode == "any"
    if matches:
        return AssertionResult(assertion, Status.OK)
    if non_evals:
        return AssertionResult(assertion, Status.NON_EVALUABLE, non_evals[0])
    if echecs:
        return AssertionResult(assertion, Status.ECHEC, echecs[0])
    if mismatches:
        return AssertionResult(assertion, Status.ECHEC, _mismatch_detail(mismatches[0]))
    return AssertionResult(assertion, Status.NON_EVALUABLE, "aucun chemin n'a pu être résolu")


_EVALUATORS = {
    "bgp_session": _check_bgp_session,
    "ospf_neighbors": _check_ospf_neighbors,
    "route_present": _check_route_present,
    "route_absent": _check_route_absent,
    "interface_up": _check_interface_up,
    "path": _check_path,
}
