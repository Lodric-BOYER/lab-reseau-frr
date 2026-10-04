"""Comparaison de deux snapshots -> liste de Finding, classés par gravité (§5.3).

Douze types de constats, exactement ceux du tableau du cahier des charges :
  CRITIQUE  : session BGP plus Established, voisin OSPF perdu, préfixe injoignable
              (table de routage ou BGP), interface passée down.
  ATTENTION : next-hop modifié (route ou BGP), métrique modifiée, protocole modifié,
              AS-path modifié, nombre de préfixes BGP reçus modifié.
  INFO      : nouvelle route, nouveau voisin (OSPF ou BGP), lignes de config modifiées.

Phase B2 (v4) : les mêmes constats en IPv6 (routes, voisins OSPFv3, BGP `ipv6 unicast`) et par VRF. Une
route est identifiée par (vrf, préfixe) : le même préfixe dans deux VRF = deux routes ; une session BGP par
(vrf, famille, voisin). Un constat dans une VRF autre que `default` le dit (« VRF DEMO »). Une section
relevée d'un seul côté n'est PAS comparée : le diff le dit, il ne déclare jamais « aucun changement » sur
une section qu'il n'a pas pu comparer. Section relevée AVANT et non relevée APRÈS : perte de visibilité,
constat ATTENTION par section et par équipement (une collecte échouée pendant une intervention ne doit jamais
donner OK) ; relevée seulement APRÈS (ancien snapshot) : information. Les routes de lien local
(fe80::/10) ne sont pas comparées : FRR n'en installe qu'une entrée parmi celles des interfaces, au gré
de leur ordre.
"""
from __future__ import annotations

import difflib
import ipaddress
import sys
from dataclasses import dataclass, replace
from enum import IntEnum
from pathlib import Path

from netcheck import management
from netcheck.model import DEFAULT_VRF, DeviceState, Route

AUTOMATION_DIR = Path(__file__).resolve().parent.parent / "automation"
if str(AUTOMATION_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_DIR))
from labtools import clean_config  # noqa: E402  (réutilisé tel quel, cohérent avec drift.py)


class Severity(IntEnum):
    INFO = 1
    ATTENTION = 2
    CRITIQUE = 3


# Catégories de constats réellement produites par compare() ci-dessous. Un critère --expect
# (netcheck/expect.py) ne peut cibler que celles-ci : une faute de frappe dans un fichier
# d'attentes serait sinon un critère inopérant, jamais signalé.
FINDING_CATEGORIES = frozenset({
    "ospf_neighbor", "bgp_session", "bgp_prefix_count", "bgp_prefix", "as_path",
    "next_hop", "route", "metric", "protocol", "interface", "config", "device",
    "ospf6_neighbor", "section",
})


@dataclass
class Finding:
    severity: Severity
    category: str
    device: str
    message: str
    # Phase D1 : identifiant du critère --expect qui a prévu ce constat (None = non prévu).
    # Un constat PRÉVU garde sa gravité d'origine (affichée) mais n'entre plus dans le verdict.
    expected_by: str | None = None


# ------------------------------------------------------------------------------------------
# Comparaison
# ------------------------------------------------------------------------------------------

def compare(
    before: dict[str, DeviceState],
    after: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
    management_vrfs: set[str] | None = None,
) -> list[Finding]:
    """Compare deux ensembles de DeviceState (deux snapshots) et renvoie tous les constats."""
    mgmt = set(management_interfaces or ())
    mgmt_vrfs = set(management_vrfs or ())
    findings: list[Finding] = []

    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if b is None or a is None:
            missing = "après" if a is None else "avant"
            findings.append(Finding(Severity.ATTENTION, "device", name,
                                     f"équipement absent du snapshot {missing}"))
            continue
        if not a.reachable:
            findings.append(Finding(Severity.CRITIQUE, "device", name,
                                     f"équipement injoignable : {a.error}"))
            continue

        b, a = management.filtered(b, mgmt, mgmt_vrfs), management.filtered(a, mgmt, mgmt_vrfs)
        comparable, lost, gained = _comparable_sections(b, a)
        # Une section relevée AVANT et plus APRÈS est une perte de visibilité (souvent une collecte qui a
        # échoué pendant l'intervention) : ATTENTION au moins, par section et par équipement, jamais un OK.
        findings += [
            Finding(Severity.ATTENTION, "section", name,
                    f"section {s} perdue : relevée avant, non relevée après "
                    f"({a.why_missing(s).split(' : ', 1)[-1]})")
            for s in lost
        ]
        # L'inverse (un snapshot d'avant la phase B2 contre un récent) est une information : ce qui est
        # nouveau n'a pas de « avant » à comparer.
        if gained:
            findings.append(Finding(Severity.INFO, "section", name,
                "sections non comparées (relevées seulement après : snapshot d'avant la phase B2 ou driver "
                f"différent) : {', '.join(gained)}"))
        in_scope = _scope_to_comparable(b, a, comparable)
        b, a = in_scope
        if "ospf_v2" in comparable:
            findings += _diff_ospf(name, b.ospf_neighbors, a.ospf_neighbors)
        if "ospf_v3" in comparable:
            findings += _diff_ospf(name, b.ospf6_neighbors, a.ospf6_neighbors, v3=True)
        findings += _diff_bgp_peers(name, b.bgp_peers, a.bgp_peers)
        findings += _diff_bgp_prefixes(name, b.bgp_prefixes, a.bgp_prefixes)
        findings += _diff_routes(name, b.routes, a.routes)
        if "interfaces" in comparable:
            findings += _diff_interfaces(name, b.interfaces, a.interfaces)
        findings += _diff_config(name, b.running_config, a.running_config)

    return findings


# Sections que le diff sait comparer ; « config » est toujours relevée, « bgp_vrf » ne l'est par aucun driver.
_COMPARED = ("interfaces", "routes_v4", "routes_v6", "ospf_v2", "ospf_v3", "bgp_v4", "bgp_v6", "vrf")


def _comparable_sections(b: DeviceState, a: DeviceState) -> tuple[set[str], list[str], list[str]]:
    """(relevées des DEUX côtés, relevées avant mais plus après, relevées seulement après). Une section
    relevée d'aucun côté n'est pas un changement : elle n'est ni comparée ni signalée (le driver ne la
    relève simplement pas)."""
    both = {s for s in _COMPARED if b.has_section(s) and a.has_section(s)}
    lost = [s for s in _COMPARED if b.has_section(s) and not a.has_section(s)]
    gained = [s for s in _COMPARED if a.has_section(s) and not b.has_section(s)]
    return both, lost, gained


def _scope_to_comparable(b: DeviceState, a: DeviceState,
                         comparable: set[str]) -> tuple[DeviceState, DeviceState]:
    """Retire de chaque côté ce qui appartient à une section non comparable (IPv6, VRF autres que default)."""
    def keep_route(r: Route) -> bool:
        family = "routes_v6" if ":" in r.prefix else "routes_v4"
        if family not in comparable:
            return False
        if r.vrf != DEFAULT_VRF and "vrf" not in comparable:
            return False
        return not _is_link_local(r.prefix)

    def scope(s: DeviceState) -> DeviceState:
        return replace(
            s,
            routes=[r for r in s.routes if keep_route(r)],
            interfaces=[i for i in s.interfaces if i.vrf == DEFAULT_VRF or "vrf" in comparable],
            bgp_peers=[p for p in s.bgp_peers
                       if f"bgp_{'v6' if p.address_family == 'ipv6' else 'v4'}" in comparable],
            bgp_prefixes=[p for p in s.bgp_prefixes
                          if f"bgp_{'v6' if ':' in p.prefix else 'v4'}" in comparable],
        )

    return scope(b), scope(a)


def _is_link_local(prefix: str) -> bool:
    try:
        return ipaddress.ip_network(prefix).network_address.is_link_local
    except ValueError:
        return False


def _where(vrf: str) -> str:
    """Suffixe de message : vide pour la VRF default (messages inchangés), « (VRF X) » sinon."""
    return "" if vrf == DEFAULT_VRF else f" (VRF {vrf})"


def verdict(findings: list[Finding]) -> tuple[str, int]:
    """Verdict global (§5.3) : OK/0, ATTENTION/1, ÉCHEC/2 (le pire constat l'emporte).

    Les constats PRÉVUS (Phase D1, expected_by renseigné) sont affichés mais sans effet ici."""
    active = [f for f in findings if f.expected_by is None]
    if any(f.severity == Severity.CRITIQUE for f in active):
        return "ÉCHEC", 2
    if any(f.severity == Severity.ATTENTION for f in active):
        return "ATTENTION", 1
    return "OK", 0


# ------------------------------------------------------------------------------------------
# Un comparateur par type de donnée
# ------------------------------------------------------------------------------------------

def _diff_ospf(device, before, after, v3: bool = False) -> list[Finding]:
    protocol, category = ("OSPFv3", "ospf6_neighbor") if v3 else ("OSPF", "ospf_neighbor")
    full_before = {n.router_id for n in before if n.is_full}
    full_after = {n.router_id for n in after if n.is_full}
    findings = [
        Finding(Severity.CRITIQUE, category, device, f"voisin {protocol} perdu : {rid}")
        for rid in sorted(full_before - full_after)
    ]
    findings += [
        Finding(Severity.INFO, category, device, f"nouveau voisin {protocol} : {rid}")
        for rid in sorted(full_after - full_before)
    ]
    return findings


def _diff_bgp_peers(device, before, after) -> list[Finding]:
    # Identité d'une session : (vrf, famille, voisin) ; le texte des constats de la VRF default est inchangé.
    b = {(p.vrf, p.address_family, p.neighbor): p for p in before}
    a = {(p.vrf, p.address_family, p.neighbor): p for p in after}
    findings = []
    for (vrf, family, ip), pb in b.items():
        pa = a.get((vrf, family, ip))
        where = _where(vrf)
        if pb.state == "Established" and (pa is None or pa.state != "Established"):
            findings.append(Finding(Severity.CRITIQUE, "bgp_session", device,
                f"session BGP {ip}{where} n'est plus Established (état : {pa.state if pa else 'absent'})"))
        elif pa is not None and pb.state == "Established" and pa.state == "Established" \
                and pb.pfx_received != pa.pfx_received:
            findings.append(Finding(Severity.ATTENTION, "bgp_prefix_count", device,
                f"préfixes reçus de {ip}{where} modifiés : {pb.pfx_received} -> {pa.pfx_received}"))
    findings += [
        Finding(Severity.INFO, "bgp_session", device, f"nouveau voisin BGP : {ip}{_where(vrf)}")
        for vrf, family, ip in sorted(set(a) - set(b))
    ]
    return findings


def _diff_bgp_prefixes(device, before, after) -> list[Finding]:
    b = {(p.vrf, p.prefix): p for p in before if p.best}
    a = {(p.vrf, p.prefix): p for p in after if p.best}
    findings = []
    for (vrf, prefix), pb in b.items():
        pa = a.get((vrf, prefix))
        where = _where(vrf)
        if pa is None:
            findings.append(Finding(Severity.CRITIQUE, "bgp_prefix", device,
                                     f"préfixe BGP perdu : {prefix}{where}"))
            continue
        if pb.as_path != pa.as_path:
            findings.append(Finding(Severity.ATTENTION, "as_path", device,
                f"AS-path modifié pour {prefix}{where} : '{pb.as_path}' -> '{pa.as_path}'"))
        if pb.next_hop != pa.next_hop:
            findings.append(Finding(Severity.ATTENTION, "next_hop", device,
                f"next-hop BGP modifié pour {prefix}{where} : {pb.next_hop} -> {pa.next_hop}"))
    findings += [
        Finding(Severity.INFO, "bgp_prefix", device, f"nouveau préfixe BGP : {prefix}{_where(vrf)}")
        for vrf, prefix in sorted(set(a) - set(b))
    ]
    return findings


def _nexthop_key(route: Route) -> frozenset:
    return frozenset((nh.ip or "", nh.interface or "") for nh in route.nexthops)


def _diff_routes(device, before, after) -> list[Finding]:
    # Identité d'une route : (vrf, préfixe).
    b = {(r.vrf, r.prefix): r for r in before if r.selected}
    a = {(r.vrf, r.prefix): r for r in after if r.selected}
    findings = []
    for (vrf, prefix), rb in b.items():
        ra = a.get((vrf, prefix))
        where = _where(vrf)
        if ra is None:
            findings.append(Finding(Severity.CRITIQUE, "route", device,
                                     f"préfixe injoignable : {prefix}{where}"))
            continue
        if _nexthop_key(rb) != _nexthop_key(ra):
            findings.append(Finding(Severity.ATTENTION, "next_hop", device,
                f"next-hop modifié pour {prefix}{where} : {sorted(_nexthop_key(rb))} -> "
                f"{sorted(_nexthop_key(ra))}"))
        if rb.metric != ra.metric:
            findings.append(Finding(Severity.ATTENTION, "metric", device,
                f"métrique modifiée pour {prefix}{where} : {rb.metric} -> {ra.metric}"))
        if rb.protocol != ra.protocol:
            findings.append(Finding(Severity.ATTENTION, "protocol", device,
                f"protocole modifié pour {prefix}{where} : {rb.protocol} -> {ra.protocol}"))
    findings += [
        Finding(Severity.INFO, "route", device, f"nouvelle route : {prefix}{_where(vrf)}")
        for vrf, prefix in sorted(set(a) - set(b))
    ]
    return findings


def _diff_interfaces(device, before, after) -> list[Finding]:
    b = {(i.vrf, i.name): i for i in before}
    a = {(i.vrf, i.name): i for i in after}
    findings = [
        Finding(Severity.CRITIQUE, "interface", device, f"interface {name} passée à l'état down{_where(vrf)}")
        for (vrf, name), ib in b.items()
        if (ia := a.get((vrf, name))) is not None and ib.oper_up and not ia.oper_up
    ]
    # Une interface qui change de VRF n'est ni « disparue » ni « nouvelle » : (vrf, nom) change, le nom reste.
    vrfs_before, vrfs_after = {}, {}
    for vrf, name in b:
        vrfs_before.setdefault(name, set()).add(vrf)
    for vrf, name in a:
        vrfs_after.setdefault(name, set()).add(vrf)
    findings += [
        Finding(Severity.ATTENTION, "interface", device,
                f"interface {name} : VRF modifiée {sorted(vrfs_before[name])} -> {sorted(vrfs_after[name])}")
        for name in sorted(set(vrfs_before) & set(vrfs_after)) if vrfs_before[name] != vrfs_after[name]
    ]
    return findings


def _diff_config(device, before_text, after_text) -> list[Finding]:
    diff = list(difflib.unified_diff(
        clean_config(before_text), clean_config(after_text),
        fromfile="avant", tofile="après", lineterm="", n=2,
    ))
    if not diff:
        return []
    return [Finding(Severity.INFO, "config", device, "\n".join(diff))]
