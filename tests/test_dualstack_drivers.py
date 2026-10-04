"""Phase B2 : les trois drivers lisent IPv6, les VRF et OSPFv3 sur les relevés RÉELS des labs en double pile.

Relevés : tests/fixtures/dualstack/{frr,mixed,ceos}/ (voir tests/dualstack_support.py). Quand un test doit
fabriquer un cas que le lab ne produit pas (une sortie vide, une commande inconnue), il part d'un relevé
réel et dit ce qu'il change : jamais de JSON inventé de toutes pièces.
"""
import copy
import json
from pathlib import Path

import dualstack_support as ds
import pytest

from netcheck import collector
from netcheck.drivers.eos import EosDriver
from netcheck.drivers.frr import FrrDriver
from netcheck.drivers.srlinux import SrlinuxDriver

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def without(lab, router, command):
    """Le relevé réel d'un routeur, SANS la sortie d'une commande (commande non exécutée)."""
    raw = ds.load_raw(lab, router)
    del raw["commands"][command]
    return ds.parse(raw, router)


# ------------------------------------------------------------------------------------------
# Liste blanche et traductions
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("driver_cls", [FrrDriver, EosDriver, SrlinuxDriver])
def test_every_command_of_every_driver_is_on_the_logical_whitelist(driver_cls):
    assert set(driver_cls.REQUIRED_COMMANDS) <= collector.ALLOWED_COMMANDS


@pytest.mark.parametrize("driver_cls", [FrrDriver, EosDriver, SrlinuxDriver])
def test_no_translated_command_can_change_anything(driver_cls):
    driver = driver_cls()
    for command in driver.REQUIRED_COMMANDS:
        cli = driver.translate(command)
        forbidden_words = ("configure", "conf t", " write", "copy ", "reload", " > ", ">>", "commit",
                           "delete", "set /")
        for forbidden in forbidden_words:
            assert forbidden not in cli, (command, cli)
        assert cli.split()[0] in ("vtysh", "show", "info"), cli


def test_frr_translations_cover_all_vrfs_and_name_ospfv3_ospf6():
    t = FrrDriver().translate
    assert t("show ip route json") == "vtysh -c 'show ip route vrf all json'"
    assert t("show ipv6 route json") == "vtysh -c 'show ipv6 route vrf all json'"
    assert t("show ipv6 ospf neighbor json") == "vtysh -c 'show ipv6 ospf6 neighbor json'"
    assert t("show bgp ipv6 unicast summary json") == "vtysh -c 'show bgp ipv6 unicast summary json'"
    assert t("show interface json") == "vtysh -c 'show interface json'"      # contient déjà IPv6 et vrfName


def test_srlinux_translations_read_every_network_instance():
    t = SrlinuxDriver().translate
    assert t("show ip route json") == "info from state network-instance * route-table | as json"
    assert t("show vrf json") == "info from state network-instance * interface * | as json"
    assert "show ipv6 route json" not in SrlinuxDriver.REQUIRED_COMMANDS      # la même table contient IPv6


# ------------------------------------------------------------------------------------------
# FRR
# ------------------------------------------------------------------------------------------

def test_frr_reads_all_sections_on_the_dualstack_lab():
    r2 = ds.load_lab("frr")["r2"]
    assert r2.collected == ["interfaces", "routes_v4", "routes_v6", "vrf", "ospf_v2", "ospf_v3", "bgp_v4",
                            "bgp_v6",
                            "config"]
    assert r2.section_errors == {} and not r2.has_section("bgp_vrf")


def test_frr_interfaces_carry_ipv6_link_local_and_vrf_and_hide_the_vrf_device():
    r2 = ds.load_lab("frr")["r2"]
    by_name = {i.name: i for i in r2.interfaces}
    # `DEMO` (le périphérique VRF) n'y est pas.
    assert set(by_name) == {"dum-demo", "eth0", "eth1", "eth2", "lo"}
    assert by_name["eth1"].addresses6 == ["2001:db8:1:12::3/127"]
    assert by_name["eth1"].addresses == ["10.1.12.2/30"]
    assert by_name["lo"].addresses6 == ["2001:db8:1:ff::2/128"]
    assert by_name["eth1"].link_local6.startswith("fe80::") and "/" not in by_name["eth1"].link_local6
    assert by_name["eth1"].vrf == "default"
    assert (by_name["dum-demo"].vrf, by_name["dum-demo"].addresses, by_name["dum-demo"].addresses6) == (
        "DEMO", ["10.99.2.1/24"], ["2001:db8:99::1/64"])
    # Le lien local n'est jamais dans la liste des adresses globales.
    assert not any(a.startswith("fe80") for i in r2.interfaces for a in i.addresses6)


def test_frr_routes_of_each_vrf_are_read_and_the_same_prefix_in_two_vrfs_is_two_routes():
    r2 = ds.load_lab("frr")["r2"]
    demo = {(r.prefix, r.protocol) for r in r2.routes if r.vrf == "DEMO"}
    assert demo == {("10.99.2.0/24", "connected"), ("10.99.2.1/32", "local"), ("10.99.9.0/24", "static"),
                    ("2001:db8:99::/64", "connected"), ("2001:db8:99::1/128", "local"),
                    ("2001:db8:99:9::/64", "static"), ("fe80::/64", "connected")}
    # fe80::/64 existe dans default ET dans DEMO : deux routes, identifiées par (vrf, préfixe).
    assert {r.vrf for r in r2.routes if r.prefix == "fe80::/64"} == {"default", "DEMO"}
    blackhole = next(r for r in r2.routes if r.vrf == "DEMO" and r.prefix == "2001:db8:99:9::/64")
    assert [(n.ip, n.interface, n.directly_connected) for n in blackhole.nexthops] == [(None, None, False)]
    # Aucune route de la VRF DEMO ne fuit dans default.
    leaked = [r for r in r2.routes
              if r.vrf == "default" and r.prefix.startswith(("10.99.", "2001:db8:99:"))]
    assert not leaked


def test_frr_ipv6_next_hops_are_link_local_with_their_outgoing_interface():
    r1 = ds.load_lab("frr")["r1"]
    route = next(r for r in r1.routes if r.prefix == "2001:db8:a2::/64" and r.selected)
    assert route.protocol == "ospf6" and route.vrf == "default"
    assert all(n.ip.startswith("fe80::") and n.interface == "eth2" for n in route.nexthops)


def test_frr_ospfv3_neighbors_and_bgp_ipv6():
    lab = ds.load_lab("frr")
    r3 = lab["r3"]
    assert [(n.router_id, n.state, n.interface) for n in r3.ospf6_neighbors] == [
        ("10.1.255.1", "Full", "eth1"), ("10.1.255.2", "Full", "eth2")]
    assert all(n.is_full for n in r3.ospf6_neighbors)
    assert len(r3.ospf_neighbors) == 2                                         # l'OSPFv2 reste à part
    peers = {(p.neighbor, p.address_family): p for p in r3.bgp_peers}
    assert peers[("172.16.34.2", "ipv4")].state == "Established"
    v6 = peers[("2001:db8:34::3", "ipv6")]
    assert (v6.remote_as, v6.state, v6.pfx_received, v6.vrf) == (65002, "Established", 2, "default")
    prefixes = {p.prefix: p for p in r3.bgp_prefixes if ":" in p.prefix}
    remote = prefixes["2001:db8:2::/48"]
    assert (remote.as_path, remote.next_hop) == ("65002", "2001:db8:34::3")
    assert prefixes["2001:db8:1::/48"].as_path == ""                           # origine locale


def test_frr_section_read_but_empty_is_not_a_section_that_was_not_read():
    # r2 n'a pas de BGP : FRR répond `{}` (résumé) et `{"warning": "Default BGP instance not found"}` (table).
    raw = ds.load_raw("frr", "r2")["commands"]
    assert json.loads(raw["show bgp ipv6 unicast summary json"]) == {}
    assert "warning" in json.loads(raw["show bgp ipv6 unicast json"])
    r2 = ds.load_lab("frr")["r2"]
    assert r2.has_section("bgp_v4") and r2.has_section("bgp_v6")
    assert r2.bgp_peers == [] and r2.bgp_prefixes == []
    # La commande non exécutée, elle, donne une section NON relevée, avec sa raison.
    missing = without("frr", "r2", "show bgp ipv6 unicast json")
    assert not missing.has_section("bgp_v6") and missing.has_section("bgp_v4")
    assert "commande non exécutée" in missing.section_errors["bgp_v6"]
    assert missing.bgp_peers == []


def test_frr_an_unknown_command_answer_is_a_section_not_read_never_an_empty_one():
    # Modification d'un relevé réel : la sortie OSPFv3 est remplacée par la réponse de vtysh quand ospf6d ne
    # tourne pas (message de vtysh, non relevé sur ce lab : ospf6d y est toujours actif).
    unknown = "% Unknown command: show ipv6 ospf6 neighbor json"
    state = ds.parse_with("frr", "r1", {"show ipv6 ospf neighbor json": unknown})
    assert not state.has_section("ospf_v3") and state.ospf6_neighbors == []
    assert "pas du JSON" in state.section_errors["ospf_v3"]
    assert state.has_section("ospf_v2") and len(state.ospf_neighbors) == 2


def test_frr_pre_b2_route_output_is_default_vrf_only_and_vrf_is_not_collected():
    # Sortie de `show ip route json`, d'avant la phase B2.
    legacy_routes = (FIXTURES / "r3" / "route.json").read_text(encoding="utf-8")
    state = ds.parse_with("frr", "r3", {"show ip route json": legacy_routes})
    assert state.has_section("routes_v4") and not state.has_section("vrf")
    assert {r.vrf for r in state.routes if ":" not in r.prefix} == {"default"}
    assert "VRF default" in state.section_errors["vrf"]


# ------------------------------------------------------------------------------------------
# EOS
# ------------------------------------------------------------------------------------------

def test_eos_reads_all_sections_and_ipv6_interfaces():
    r4 = ds.load_lab("ceos")["r4"]
    assert r4.section_errors == {} and {"routes_v6", "ospf_v3", "bgp_v6", "vrf"} <= set(r4.collected)
    by_name = {i.name: i for i in r4.interfaces}
    # `address` + `subnet` : « 2001:db8:34::3 » dans « 2001:db8:34::2/127 » donne /127.
    assert by_name["Ethernet1"].addresses6 == ["2001:db8:34::3/127"]
    assert by_name["Ethernet2"].addresses6 == ["2001:db8:2:45::2/127"]
    assert by_name["Loopback0"].addresses6 == ["2001:db8:2:ff::4/128"]
    assert by_name["Ethernet1"].link_local6.startswith("fe80::")
    assert by_name["Management0"].link_local6 is None
    assert {i.vrf for i in r4.interfaces} == {"default"}
    assert by_name["Ethernet1"].addresses == ["172.16.34.2/30"]                # l'IPv4 d'avant, inchangée


def test_eos_ipv6_routes_protocols_and_blackhole():
    r4 = ds.load_lab("ceos")["r4"]
    by_prefix = {r.prefix: r for r in r4.routes if ":" in r.prefix}
    # « ospf » en minuscules côté IPv6.
    assert by_prefix["2001:db8:a2::/64"].protocol == "ospf"
    assert by_prefix["2001:db8:1::/48"].protocol == "bgp"
    assert by_prefix["2001:db8:2::/48"].protocol == "static"
    assert [(n.ip, n.interface, n.directly_connected) for n in by_prefix["2001:db8:2::/48"].nexthops] == [
        (None, None, False)]    # Null0 : trou noir, même signature que FRR
    nh = by_prefix["2001:db8:a2::/64"].nexthops[0]
    assert nh.ip.startswith("fe80::") and nh.interface == "Ethernet2"


def test_eos_ospfv3_and_bgp_ipv6():
    r4 = ds.load_lab("ceos")["r4"]
    assert [(n.router_id, n.state, n.interface) for n in r4.ospf6_neighbors] == [
        ("10.2.255.5", "Full/-", "Ethernet2")]
    peers = {(p.neighbor, p.address_family): p for p in r4.bgp_peers}
    v6 = peers[("2001:db8:34::2", "ipv6")]
    assert (v6.remote_as, v6.state, v6.pfx_received) == (65001, "Established", 2)
    local = next(p for p in r4.bgp_prefixes if p.prefix == "2001:db8:2::/48")
    assert (local.as_path, local.next_hop, local.best) == ("", "", True)       # origine locale, comme l'IPv4


def test_eos_routes_and_interfaces_of_a_real_temporary_vrf():
    # Relevé réel pris sur r4 pendant une VRF temporaire TMPVRF (Loopback99, routes IPv4 et IPv6), retirée
    # ensuite.
    raw = ds.load_raw("ceos", "r4_tmpvrf")["commands"]
    state = ds.parse_with("ceos", "r4", raw)
    lo = [i for i in state.interfaces if i.name == "Loopback99"]
    assert [(i.vrf, i.addresses, i.addresses6, i.is_loopback) for i in lo] == [
        ("TMPVRF", ["10.99.4.1/32"], ["2001:db8:99:4::1/128"], True)]
    assert {i.vrf for i in state.interfaces if i.name != "Loopback99"} == {"default"}
    tmp = {(r.prefix, r.protocol) for r in state.routes if r.vrf == "TMPVRF"}
    assert tmp == {("10.99.4.1/32", "connected"), ("10.99.9.0/24", "static"),
                   ("2001:db8:99:4::1/128", "connected"), ("2001:db8:99:9::/64", "static")}
    assert not [r for r in state.routes if r.vrf == "default" and "99" in r.prefix]
    blackhole = next(r for r in state.routes if r.vrf == "TMPVRF" and r.prefix == "10.99.9.0/24")
    assert [(n.ip, n.interface) for n in blackhole.nexthops] == [(None, None)]


def test_eos_section_read_but_empty_is_not_a_section_that_was_not_read():
    # Modification d'un relevé réel : la structure vient de la sortie réelle de `show ipv6 bgp summary |
    # json`, dont on retire les pairs (un EOS sans session IPv6 : forme non relevée en direct, ce lab n'en a
    # pas).
    raw = ds.load_raw("ceos", "r4")["commands"]
    summary = json.loads(raw["show bgp ipv6 unicast summary json"])
    summary["vrfs"]["default"]["peers"] = {}
    table = json.loads(raw["show bgp ipv6 unicast json"])
    table["vrfs"]["default"]["bgpRouteEntries"] = {}
    state = ds.parse_with("ceos", "r4", {"show bgp ipv6 unicast summary json": json.dumps(summary),
                                         "show bgp ipv6 unicast json": json.dumps(table)})
    assert state.has_section("bgp_v6") and not [p for p in state.bgp_peers if p.address_family == "ipv6"]
    assert not [p for p in state.bgp_prefixes if ":" in p.prefix]
    assert state.has_section("bgp_v4") and any(p.address_family == "ipv4" for p in state.bgp_peers)
    # Et sans la commande : section non relevée.
    missing = without("ceos", "r4", "show bgp ipv6 unicast summary json")
    assert not missing.has_section("bgp_v6") and "commande non exécutée" in missing.section_errors["bgp_v6"]


def test_eos_without_the_vrf_command_reads_every_interface_in_default_and_says_vrf_is_missing():
    state = without("ceos", "r4", "show vrf json")
    assert {i.vrf for i in state.interfaces} == {"default"} and not state.has_section("vrf")


def test_eos_non_json_ospfv3_answer_is_a_section_not_read():
    state = ds.parse_with("ceos", "r4", {"show ipv6 ospf neighbor json": "% IPv6 routing not enabled"})
    assert not state.has_section("ospf_v3") and state.ospf6_neighbors == []


# ------------------------------------------------------------------------------------------
# SR Linux
# ------------------------------------------------------------------------------------------

def test_srlinux_sections_never_include_bgp():
    r5 = ds.load_lab("mixed")["r5"]
    assert set(r5.collected) == {"interfaces", "routes_v4", "routes_v6", "ospf_v2", "ospf_v3", "vrf",
                                 "config"}
    assert not r5.has_section("bgp_v4") and not r5.has_section("bgp_v6")
    assert r5.bgp_peers == [] and r5.bgp_prefixes == []


def test_srlinux_interfaces_ipv6_and_vrf():
    r5 = ds.load_lab("mixed")["r5"]
    by_name = {i.name: i for i in r5.interfaces}
    e1 = by_name["ethernet-1/1"]
    assert (e1.vrf, e1.addresses, e1.addresses6) == ("default", ["10.2.45.2/30"], ["2001:db8:2:45::3/127"])
    assert e1.link_local6.startswith("fe80::")
    assert by_name["lo0"].addresses6 == ["2001:db8:2:ff::5/128"]
    assert by_name["mgmt0"].vrf == "mgmt" and by_name["mgmt0"].addresses == ["172.20.21.15/24"]
    assert by_name["ethernet-1/3"].vrf == "default" and by_name["ethernet-1/3"].addresses == []


def test_srlinux_routes_of_every_network_instance_ipv4_and_ipv6():
    r5 = ds.load_lab("mixed")["r5"]
    assert {r.vrf for r in r5.routes} == {"default", "mgmt"}
    v6 = {r.prefix: r for r in r5.routes if r.vrf == "default" and ":" in r.prefix}
    # « ospfv3 » côté SR Linux, « ospf6 » côté FRR.
    assert v6["2001:db8:1::/48"].protocol == "ospfv3"
    nh = v6["2001:db8:1::/48"].nexthops[0]
    assert nh.ip.startswith("fe80::") and nh.interface == "ethernet-1/1.0"
    lan = v6["2001:db8:a2::/64"]
    assert lan.protocol == "local" and lan.nexthops[0].directly_connected
    assert any(r.vrf == "mgmt" and r.prefix == "0.0.0.0/0" for r in r5.routes)
    assert not [r for r in r5.routes if r.vrf == "default" and r.prefix.startswith("172.20.21.")]


def test_srlinux_ospfv2_and_ospfv3_neighbors_are_kept_apart():
    r5 = ds.load_lab("mixed")["r5"]
    assert [(n.router_id, n.state) for n in r5.ospf_neighbors] == [("10.2.255.4", "Full")]
    assert [(n.router_id, n.state) for n in r5.ospf6_neighbors] == [("10.2.255.4", "Full")]


def test_srlinux_subinterfaces_in_two_vrfs_give_one_interface_per_vrf():
    # Modification d'un relevé réel : on ajoute une sous-interface 1 (adresses d'exemple) à ethernet-1/1 et
    # on la place dans une autre instance réseau ; le lab n'a qu'une sous-interface par port.
    raw = ds.load_raw("mixed", "r5")["commands"]
    itf = json.loads(raw["show interface json"])
    e1 = next(i for i in itf["interface"] if i["name"] == "ethernet-1/1")
    extra = copy.deepcopy(e1["subinterface"][0])
    extra["index"] = 1
    extra["ipv4"]["address"] = [{"ip-prefix": "192.0.2.1/30"}]
    extra["ipv6"]["address"] = [{"ip-prefix": "2001:db8:ffff::1/127", "status": "preferred"}]
    e1["subinterface"].append(extra)
    members = json.loads(raw["show vrf json"])
    bleu = {"name": "BLEU", "interface": [{"name": "ethernet-1/1.1", "oper-state": "up"}]}
    members["network-instance"].append(bleu)
    state = ds.parse_with("mixed", "r5", {"show interface json": json.dumps(itf),
                                          "show vrf json": json.dumps(members)})
    ports = [i for i in state.interfaces if i.name == "ethernet-1/1"]
    assert sorted((i.vrf, tuple(i.addresses), tuple(i.addresses6)) for i in ports) == [
        ("BLEU", ("192.0.2.1/30",), ("2001:db8:ffff::1/127",)),
        ("default", ("10.2.45.2/30",), ("2001:db8:2:45::3/127",))]


def test_srlinux_pre_b2_captures_read_ipv6_as_empty_and_vrf_as_not_collected():
    # Captures RÉELLES d'avant la phase B (tests/fixtures/r5/) : la table de routage ne contient aucune
    # route IPv6 (section relevée, vide) et la commande des VRF n'existait pas (section non relevée).
    f = FIXTURES / "r5"
    cmds = {
        "show interface json": (f / "interface.json").read_text(encoding="utf-8"),
        "show ip route json": (f / "route.json").read_text(encoding="utf-8"),
        "show ip ospf neighbor json": (f / "ospf_neighbor.json").read_text(encoding="utf-8"),
        "show running-config": (f / "running_config.txt").read_text(encoding="utf-8"),
        "show ospf running-config": (f / "ospf_running_config.txt").read_text(encoding="utf-8"),
        "show system authentication": (f / "system_authentication.txt").read_text(encoding="utf-8"),
        "show system banner": (f / "system_banner.txt").read_text(encoding="utf-8"),
    }
    state = SrlinuxDriver().parse(cmds, "r5", "h")
    assert state.has_section("routes_v6") and not [r for r in state.routes if ":" in r.prefix]
    assert state.has_section("ospf_v3") and state.ospf6_neighbors == []
    assert not state.has_section("vrf") and "commande non exécutée" in state.section_errors["vrf"]
    assert {r.vrf for r in state.routes} == {"default"}
