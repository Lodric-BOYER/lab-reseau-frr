"""Comparaison de deux snapshots -> liste de Finding, classés par gravité (§5.3).

Douze types de constats, exactement ceux du tableau du cahier des charges :
  CRITIQUE  : session BGP plus Established, voisin OSPF perdu, préfixe injoignable
              (table de routage ou BGP), interface passée down.
  ATTENTION : next-hop modifié (route ou BGP), métrique modifiée, protocole modifié,
              AS-path modifié, nombre de préfixes BGP reçus modifié.
  INFO      : nouvelle route, nouveau voisin (OSPF ou BGP), lignes de config modifiées.
"""
from __future__ import annotations

import difflib
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

AUTOMATION_DIR = Path(__file__).resolve().parent.parent / "automation"
if str(AUTOMATION_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_DIR))
from labtools import clean_config  # noqa: E402  (réutilisé tel quel, cohérent avec drift.py)

from netcheck import management
from netcheck.model import DeviceState, Route


class Severity(IntEnum):
    INFO = 1
    ATTENTION = 2
    CRITIQUE = 3


@dataclass
class Finding:
    severity: Severity
    category: str
    device: str
    message: str


# ------------------------------------------------------------------------------------------
# Comparaison
# ------------------------------------------------------------------------------------------

def compare(
    before: dict[str, DeviceState],
    after: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
) -> list[Finding]:
    """Compare deux ensembles de DeviceState (deux snapshots) et renvoie tous les constats."""
    mgmt = set(management_interfaces or ())
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

        b, a = management.filtered(b, mgmt), management.filtered(a, mgmt)
        findings += _diff_ospf(name, b.ospf_neighbors, a.ospf_neighbors)
        findings += _diff_bgp_peers(name, b.bgp_peers, a.bgp_peers)
        findings += _diff_bgp_prefixes(name, b.bgp_prefixes, a.bgp_prefixes)
        findings += _diff_routes(name, b.routes, a.routes)
        findings += _diff_interfaces(name, b.interfaces, a.interfaces)
        findings += _diff_config(name, b.running_config, a.running_config)

    return findings


def verdict(findings: list[Finding]) -> tuple[str, int]:
    """Verdict global (§5.3) : OK/0, ATTENTION/1, ÉCHEC/2 (le pire constat l'emporte)."""
    if any(f.severity == Severity.CRITIQUE for f in findings):
        return "ÉCHEC", 2
    if any(f.severity == Severity.ATTENTION for f in findings):
        return "ATTENTION", 1
    return "OK", 0


# ------------------------------------------------------------------------------------------
# Un comparateur par type de donnée
# ------------------------------------------------------------------------------------------

def _diff_ospf(device, before, after) -> list[Finding]:
    full_before = {n.router_id for n in before if n.is_full}
    full_after = {n.router_id for n in after if n.is_full}
    findings = [
        Finding(Severity.CRITIQUE, "ospf_neighbor", device, f"voisin OSPF perdu : {rid}")
        for rid in sorted(full_before - full_after)
    ]
    findings += [
        Finding(Severity.INFO, "ospf_neighbor", device, f"nouveau voisin OSPF : {rid}")
        for rid in sorted(full_after - full_before)
    ]
    return findings


def _diff_bgp_peers(device, before, after) -> list[Finding]:
    b = {p.neighbor: p for p in before}
    a = {p.neighbor: p for p in after}
    findings = []
    for ip, pb in b.items():
        pa = a.get(ip)
        if pb.state == "Established" and (pa is None or pa.state != "Established"):
            findings.append(Finding(Severity.CRITIQUE, "bgp_session", device,
                f"session BGP {ip} n'est plus Established (état : {pa.state if pa else 'absent'})"))
        elif pa is not None and pb.state == "Established" and pa.state == "Established" \
                and pb.pfx_received != pa.pfx_received:
            findings.append(Finding(Severity.ATTENTION, "bgp_prefix_count", device,
                f"préfixes reçus de {ip} modifiés : {pb.pfx_received} -> {pa.pfx_received}"))
    findings += [
        Finding(Severity.INFO, "bgp_session", device, f"nouveau voisin BGP : {ip}")
        for ip in sorted(set(a) - set(b))
    ]
    return findings


def _diff_bgp_prefixes(device, before, after) -> list[Finding]:
    b = {p.prefix: p for p in before if p.best}
    a = {p.prefix: p for p in after if p.best}
    findings = []
    for prefix, pb in b.items():
        pa = a.get(prefix)
        if pa is None:
            findings.append(Finding(Severity.CRITIQUE, "bgp_prefix", device,
                                     f"préfixe BGP perdu : {prefix}"))
            continue
        if pb.as_path != pa.as_path:
            findings.append(Finding(Severity.ATTENTION, "as_path", device,
                f"AS-path modifié pour {prefix} : '{pb.as_path}' -> '{pa.as_path}'"))
        if pb.next_hop != pa.next_hop:
            findings.append(Finding(Severity.ATTENTION, "next_hop", device,
                f"next-hop BGP modifié pour {prefix} : {pb.next_hop} -> {pa.next_hop}"))
    findings += [
        Finding(Severity.INFO, "bgp_prefix", device, f"nouveau préfixe BGP : {prefix}")
        for prefix in sorted(set(a) - set(b))
    ]
    return findings


def _nexthop_key(route: Route) -> frozenset:
    return frozenset((nh.ip or "", nh.interface or "") for nh in route.nexthops)


def _diff_routes(device, before, after) -> list[Finding]:
    b = {r.prefix: r for r in before if r.selected}
    a = {r.prefix: r for r in after if r.selected}
    findings = []
    for prefix, rb in b.items():
        ra = a.get(prefix)
        if ra is None:
            findings.append(Finding(Severity.CRITIQUE, "route", device,
                                     f"préfixe injoignable : {prefix}"))
            continue
        if _nexthop_key(rb) != _nexthop_key(ra):
            findings.append(Finding(Severity.ATTENTION, "next_hop", device,
                f"next-hop modifié pour {prefix} : {sorted(_nexthop_key(rb))} -> {sorted(_nexthop_key(ra))}"))
        if rb.metric != ra.metric:
            findings.append(Finding(Severity.ATTENTION, "metric", device,
                f"métrique modifiée pour {prefix} : {rb.metric} -> {ra.metric}"))
        if rb.protocol != ra.protocol:
            findings.append(Finding(Severity.ATTENTION, "protocol", device,
                f"protocole modifié pour {prefix} : {rb.protocol} -> {ra.protocol}"))
    findings += [
        Finding(Severity.INFO, "route", device, f"nouvelle route : {prefix}")
        for prefix in sorted(set(a) - set(b))
    ]
    return findings


def _diff_interfaces(device, before, after) -> list[Finding]:
    b = {i.name: i for i in before}
    a = {i.name: i for i in after}
    return [
        Finding(Severity.CRITIQUE, "interface", device, f"interface {name} passée à l'état down")
        for name, ib in b.items()
        if (ia := a.get(name)) is not None and ib.oper_up and not ia.oper_up
    ]


def _diff_config(device, before_text, after_text) -> list[Finding]:
    diff = list(difflib.unified_diff(
        clean_config(before_text), clean_config(after_text),
        fromfile="avant", tofile="après", lineterm="", n=2,
    ))
    if not diff:
        return []
    return [Finding(Severity.INFO, "config", device, "\n".join(diff))]
