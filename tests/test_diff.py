"""Tests de diff.py : un cas par type de constat (§6), le verdict et le code retour, plus deux
scénarios sur les fixtures dégradées capturées sur le vrai lab (lien OSPF coupé, session BGP
coupée) — demandés explicitement après la validation de la phase 1.
"""
from pathlib import Path

import pytest

from netcheck import diff
from netcheck.diff import Finding, Severity
from netcheck.drivers.frr import FrrDriver
from netcheck.model import BgpPeer, BgpPrefix, DeviceState, Interface, NextHop, OspfNeighbor, Route

FIXTURES = Path(__file__).resolve().parent / "fixtures"

ALL_COMMANDS = {
    "show interface json": "interface.json",
    "show ip route json": "route.json",
    "show ip ospf neighbor json": "ospf_neighbor.json",
    "show bgp ipv4 unicast summary json": "bgp_summary.json",
    "show bgp ipv4 unicast json": "bgp_prefixes.json",
    "show running-config": "running_config.txt",
}


def read(router: str, filename: str) -> str:
    return (FIXTURES / router / filename).read_text(encoding="utf-8")


def read_degraded(filename: str) -> str:
    return (FIXTURES / "degraded" / filename).read_text(encoding="utf-8")


def state(name: str = "r1", **kw) -> DeviceState:
    defaults = dict(host="10.0.0.1", timestamp="2026-01-01T00:00:00+00:00", reachable=True)
    return DeviceState(name=name, **{**defaults, **kw})


def route(prefix, protocol="ospf", metric=20, nexthop_ip="10.1.13.2", nexthop_if="eth2", selected=True):
    return Route(prefix=prefix, protocol=protocol, metric=metric, distance=110, selected=selected,
                 nexthops=[NextHop(ip=nexthop_ip, interface=nexthop_if)])


# -- OSPF -------------------------------------------------------------------------------------
def test_ospf_neighbor_lost_is_critical():
    before = state(ospf_neighbors=[OspfNeighbor("10.1.255.3", "Full/-", "eth2:10.1.13.1")])
    after = state(ospf_neighbors=[])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.CRITIQUE, "ospf_neighbor", "r1", "voisin OSPF perdu : 10.1.255.3")]


def test_ospf_new_neighbor_is_info():
    before = state(ospf_neighbors=[])
    after = state(ospf_neighbors=[OspfNeighbor("10.1.255.2", "Full/-", "eth1:10.1.12.1")])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.INFO, "ospf_neighbor", "r1", "nouveau voisin OSPF : 10.1.255.2")]


# -- Sessions BGP -------------------------------------------------------------------------------
def test_bgp_session_lost_is_critical():
    before = state(bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 2, 2)])
    after = state(bgp_peers=[BgpPeer("172.16.34.2", 65002, "Idle", 0, 0)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.CRITIQUE, "bgp_session", "r3",
        "session BGP 172.16.34.2 n'est plus Established (état : Idle)")]


def test_bgp_pfx_received_changed_is_attention():
    before = state(bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 2, 2)])
    after = state(bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 1, 2)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.ATTENTION, "bgp_prefix_count", "r3",
        "préfixes reçus de 172.16.34.2 modifiés : 2 -> 1")]


def test_bgp_new_peer_is_info():
    before = state(bgp_peers=[])
    after = state(bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 2, 2)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.INFO, "bgp_session", "r3", "nouveau voisin BGP : 172.16.34.2")]


# -- Préfixes BGP -------------------------------------------------------------------------------
def test_bgp_prefix_lost_is_critical():
    before = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002", "172.16.34.2", True)])
    after = state(bgp_prefixes=[])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.CRITIQUE, "bgp_prefix", "r3", "préfixe BGP perdu : 192.168.2.0/24")]


def test_bgp_as_path_changed_is_attention():
    before = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002", "172.16.34.2", True)])
    after = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002 65002", "172.16.34.2", True)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.ATTENTION, "as_path", "r3",
        "AS-path modifié pour 192.168.2.0/24 : '65002' -> '65002 65002'")]


def test_bgp_next_hop_changed_is_attention():
    before = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002", "172.16.34.2", True)])
    after = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002", "172.16.34.6", True)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.ATTENTION, "next_hop", "r3",
        "next-hop BGP modifié pour 192.168.2.0/24 : 172.16.34.2 -> 172.16.34.6")]


def test_bgp_new_prefix_is_info():
    before = state(bgp_prefixes=[])
    after = state(bgp_prefixes=[BgpPrefix("192.168.2.0/24", "65002", "172.16.34.2", True)])
    findings = diff.compare({"r3": before}, {"r3": after})
    assert findings == [Finding(Severity.INFO, "bgp_prefix", "r3", "nouveau préfixe BGP : 192.168.2.0/24")]


# -- Table de routage ---------------------------------------------------------------------------
def test_route_unreachable_is_critical():
    before = state(routes=[route("192.168.2.0/24")])
    after = state(routes=[])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.CRITIQUE, "route", "r1", "préfixe injoignable : 192.168.2.0/24")]


def test_route_next_hop_changed_is_attention():
    before = state(routes=[route("192.168.2.0/24", nexthop_ip="10.1.13.2", nexthop_if="eth2")])
    after = state(routes=[route("192.168.2.0/24", nexthop_ip="10.1.12.2", nexthop_if="eth1")])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert len(findings) == 1 and findings[0].severity == Severity.ATTENTION and findings[0].category == "next_hop"


def test_route_metric_changed_is_attention():
    before = state(routes=[route("192.168.2.0/24", metric=20)])
    after = state(routes=[route("192.168.2.0/24", metric=30)])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.ATTENTION, "metric", "r1",
        "métrique modifiée pour 192.168.2.0/24 : 20 -> 30")]


def test_route_protocol_changed_is_attention():
    before = state(routes=[route("192.168.2.0/24", protocol="ospf")])
    after = state(routes=[route("192.168.2.0/24", protocol="bgp")])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.ATTENTION, "protocol", "r1",
        "protocole modifié pour 192.168.2.0/24 : ospf -> bgp")]


def test_route_new_is_info():
    before = state(routes=[])
    after = state(routes=[route("192.168.2.0/24")])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.INFO, "route", "r1", "nouvelle route : 192.168.2.0/24")]


# -- Interfaces -----------------------------------------------------------------------------------
def test_interface_down_is_critical():
    before = state(interfaces=[Interface("eth2", "vers-r3", True, True, ["10.1.13.1/30"])])
    after = state(interfaces=[Interface("eth2", "vers-r3", False, False, ["10.1.13.1/30"])])
    findings = diff.compare({"r1": before}, {"r1": after})
    assert findings == [Finding(Severity.CRITIQUE, "interface", "r1", "interface eth2 passée à l'état down")]


# -- Configuration --------------------------------------------------------------------------------
def test_config_diff_is_info():
    before = state(running_config="interface eth1\n ip ospf cost 10\nexit\n")
    after = state(running_config="interface eth1\n ip ospf cost 50\nexit\n")
    findings = diff.compare({"r2": before}, {"r2": after})
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO and findings[0].category == "config"
    assert "+ ip ospf cost 50" in findings[0].message


# -- Verdict et code retour -------------------------------------------------------------------------
@pytest.mark.parametrize("findings,expected", [
    ([], ("OK", 0)),
    ([Finding(Severity.INFO, "route", "r1", "x")], ("OK", 0)),
    ([Finding(Severity.ATTENTION, "metric", "r1", "x")], ("ATTENTION", 1)),
    ([Finding(Severity.CRITIQUE, "route", "r1", "x")], ("ÉCHEC", 2)),
    ([Finding(Severity.INFO, "route", "r1", "x"), Finding(Severity.CRITIQUE, "route", "r1", "y")], ("ÉCHEC", 2)),
])
def test_verdict(findings, expected):
    assert diff.verdict(findings) == expected


# -- Filtrage des interfaces de management (ajustement demandé après la validation du plan) ---------
def test_management_interface_and_its_subnet_are_ignored():
    mgmt_iface = Interface("eth0", None, True, True, ["172.20.20.11/24"])
    mgmt_route = route("172.20.20.0/24", protocol="connected", nexthop_ip=None, nexthop_if="eth0")
    before = state(interfaces=[mgmt_iface], routes=[mgmt_route])
    after = state(interfaces=[], routes=[])  # eth0 "coupée" : sans le filtre, 2 constats CRITIQUE

    findings = diff.compare({"r1": before}, {"r1": after}, management_interfaces={"eth0"})
    assert findings == []


# -- Scénarios sur fixtures réelles ------------------------------------------------------------------
def _parse(router: str, overrides: dict[str, str] | None = None) -> DeviceState:
    """Construit un DeviceState avec toutes les commandes nominales de <router>, sauf celles
    remplacées explicitement par 'overrides' (contenu déjà lu, pas un nom de fichier)."""
    overrides = overrides or {}
    raw = {cmd: overrides.get(cmd, read(router, fname)) for cmd, fname in ALL_COMMANDS.items()}
    return FrrDriver().parse(raw, name=router, host="172.20.20.1")


def test_diff_fixture_ospf_link_cut():
    """r1 : nominal (2 voisins OSPF Full) vs lien r1-r3 physiquement coupé."""
    before = _parse("r1")
    after = _parse("r1", overrides={
        "show interface json": read_degraded("r1_interface_down.json"),
        "show ip ospf neighbor json": read_degraded("r1_ospf_neighbor_down.json"),
    })

    findings = diff.compare({"r1": before}, {"r1": after})
    label, code = diff.verdict(findings)

    assert (label, code) == ("ÉCHEC", 2)
    assert any(f.severity == Severity.CRITIQUE and f.category == "ospf_neighbor"
               and "10.1.255.3" in f.message for f in findings)
    assert any(f.severity == Severity.CRITIQUE and f.category == "interface"
               and "eth2" in f.message for f in findings)


def test_diff_fixture_bgp_session_cut():
    """r3 : nominal (BGP Established, 2 préfixes) vs session eBGP coupée côté r4."""
    before = _parse("r3")
    after = _parse("r3", overrides={
        "show bgp ipv4 unicast summary json": read_degraded("r3_bgp_summary_down.json"),
    })

    findings = diff.compare({"r3": before}, {"r3": after})
    label, code = diff.verdict(findings)

    assert (label, code) == ("ÉCHEC", 2)
    assert any(f.severity == Severity.CRITIQUE and f.category == "bgp_session"
               and "172.16.34.2" in f.message and "Idle" in f.message for f in findings)
