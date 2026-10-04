"""Phase B2 : `diff` en IPv6 et par VRF (identité d'une route = (vrf, préfixe)), sections comparées ou non.

États : relevés réels des labs en double pile (tests/dualstack_support.py) ; chaque test dit ce qu'il modifie.
"""
import copy

import dualstack_support as ds

from netcheck import diff, guard, monitor
from netcheck.diff import Severity
from netcheck.model import SECTIONS, BgpPeer, DeviceState, Route

MGMT = {"eth0"}


def lab(name="frr"):
    return ds.load_lab(name)


def findings(before, after, **kw):
    return diff.compare(before, after, MGMT, **kw)


def messages(fs):
    return [(f.severity.name, f.category, f.device, f.message) for f in fs]


# ------------------------------------------------------------------------------------------
# Identité (vrf, préfixe)
# ------------------------------------------------------------------------------------------

def test_a_route_lost_only_in_a_vrf_is_reported_in_that_vrf():
    before, after = lab(), lab()
    after["r2"].routes = [r for r in after["r2"].routes
                          if not (r.vrf == "DEMO" and r.prefix == "2001:db8:99:9::/64")]
    assert messages(findings(before, after)) == [
        ("CRITIQUE", "route", "r2", "préfixe injoignable : 2001:db8:99:9::/64 (VRF DEMO)")]


def test_the_same_prefix_in_two_vrfs_is_two_routes():
    before, after = lab(), lab()
    route = next(r for r in before["r2"].routes if r.vrf == "DEMO" and r.prefix == "10.99.9.0/24")
    # Avant : la route n'existe que dans DEMO. Après : elle existe aussi dans default, avec un autre next-hop.
    twin = copy.deepcopy(route)
    twin.vrf = "default"
    after["r2"].routes.append(twin)
    assert messages(findings(before, after)) == [("INFO", "route", "r2", "nouvelle route : 10.99.9.0/24")]
    # Et si la route de default disparaît seule, celle de DEMO ne la masque pas.
    both = lab()
    both["r2"].routes.append(copy.deepcopy(twin))
    gone = lab()
    gone["r2"].routes.append(copy.deepcopy(twin))
    gone["r2"].routes = [r for r in gone["r2"].routes
                         if not (r.vrf == "default" and r.prefix == "10.99.9.0/24")]
    assert messages(findings(both, gone)) == [
        ("CRITIQUE", "route", "r2", "préfixe injoignable : 10.99.9.0/24")]


def test_next_hop_and_metric_changes_name_the_vrf_when_it_is_not_default():
    before, after = lab(), lab()
    route = next(r for r in after["r2"].routes if r.vrf == "DEMO" and r.prefix == "2001:db8:99::/64")
    route.metric = 77
    route.protocol = "static"
    fs = findings(before, after)
    assert {(f.severity, f.category) for f in fs} == {
        (Severity.ATTENTION, "metric"), (Severity.ATTENTION, "protocol")}
    assert all(f.message.endswith("(VRF DEMO) : " + f.message.split(" : ", 1)[1]) or "(VRF DEMO)" in f.message
               for f in fs)


def test_a_new_route_in_a_vrf_is_info_and_names_the_vrf():
    before, after = lab(), lab()
    extra = copy.deepcopy(next(r for r in after["r2"].routes if r.vrf == "DEMO"))
    extra.prefix = "2001:db8:99:77::/64"
    after["r2"].routes.append(extra)
    assert messages(findings(before, after)) == [
        ("INFO", "route", "r2", "nouvelle route : 2001:db8:99:77::/64 (VRF DEMO)")]


def test_an_interface_that_changes_vrf_is_neither_gone_nor_new():
    before, after = lab(), lab()
    next(i for i in after["r2"].interfaces if i.name == "dum-demo").vrf = "AUTRE"
    fs = findings(before, after)
    assert messages(fs) == [
        ("ATTENTION", "interface", "r2", "interface dum-demo : VRF modifiée ['DEMO'] -> ['AUTRE']")]


def test_an_interface_down_in_a_vrf_is_critical_and_names_the_vrf():
    before, after = lab(), lab()
    next(i for i in after["r2"].interfaces if i.name == "dum-demo").oper_up = False
    assert messages(findings(before, after)) == [
        ("CRITIQUE", "interface", "r2", "interface dum-demo passée à l'état down (VRF DEMO)")]


# ------------------------------------------------------------------------------------------
# OSPFv3 et BGP IPv6
# ------------------------------------------------------------------------------------------

def test_a_lost_ospfv3_neighbor_is_critical_and_says_ospfv3():
    before, after = lab(), lab()
    after["r1"].ospf6_neighbors = after["r1"].ospf6_neighbors[:1]
    fs = findings(before, after)
    assert [(f.severity.name, f.category, f.message) for f in fs] == [
        ("CRITIQUE", "ospf6_neighbor", "voisin OSPFv3 perdu : 10.1.255.3")]
    assert "ospf6_neighbor" in diff.FINDING_CATEGORIES


def test_a_new_ospfv3_neighbor_is_info_and_ospfv2_stays_separate():
    before, after = lab(), lab()
    before["r1"].ospf6_neighbors = before["r1"].ospf6_neighbors[:1]
    fs = findings(before, after)
    assert [(f.severity.name, f.category, f.message) for f in fs] == [
        ("INFO", "ospf6_neighbor", "nouveau voisin OSPFv3 : 10.1.255.3")]


def test_ipv6_bgp_session_down_is_critical_and_the_ipv4_session_is_untouched():
    before, after = lab(), lab()
    peer = next(p for p in after["r3"].bgp_peers if p.address_family == "ipv6")
    peer.state = "Active"
    fs = findings(before, after)
    assert messages(fs) == [("CRITIQUE", "bgp_session", "r3",
                             "session BGP 2001:db8:34::3 n'est plus Established (état : Active)")]


def test_ipv6_prefix_count_and_prefix_loss():
    before, after = lab(), lab()
    next(p for p in after["r3"].bgp_peers if p.address_family == "ipv6").pfx_received = 1
    after["r3"].bgp_prefixes = [p for p in after["r3"].bgp_prefixes if p.prefix != "2001:db8:a2::/64"]
    fs = findings(before, after)
    assert {(f.severity.name, f.category) for f in fs} == {
        ("ATTENTION", "bgp_prefix_count"), ("CRITIQUE", "bgp_prefix")}
    assert any(f.message == "préfixe BGP perdu : 2001:db8:a2::/64" for f in fs)


def test_the_same_neighbor_text_in_two_families_is_two_sessions():
    a = DeviceState(name="x", host="h", timestamp="t", reachable=True, collected=list(SECTIONS))
    b = copy.deepcopy(a)
    a.bgp_peers = [BgpPeer("10.0.0.1", 1, "Established", 1, 1, address_family="ipv4")]
    b.bgp_peers = [BgpPeer("10.0.0.1", 1, "Established", 1, 1, address_family="ipv4"),
                   BgpPeer("10.0.0.1", 1, "Established", 1, 1, address_family="ipv6")]
    assert messages(diff.compare({"x": a}, {"x": b})) == [
        ("INFO", "bgp_session", "x", "nouveau voisin BGP : 10.0.0.1")]


def test_ipv6_route_next_hop_change_is_attention():
    before, after = lab(), lab()
    route = next(r for r in after["r1"].routes if r.prefix == "2001:db8:a2::/64" and r.selected)
    route.nexthops[0].interface = "eth9"
    fs = findings(before, after)
    assert [(f.severity.name, f.category) for f in fs] == [("ATTENTION", "next_hop")]


def test_link_local_routes_are_not_compared():
    before, after = lab(), lab()
    for r in after["r2"].routes:
        if r.prefix == "fe80::/64":
            # FRR n'installe qu'une entrée parmi celles des interfaces : instable.
            r.selected = not r.selected
    assert findings(before, after) == []


# ------------------------------------------------------------------------------------------
# Sections comparées ou non
# ------------------------------------------------------------------------------------------

def test_a_section_collected_on_one_side_only_is_never_compared_as_no_change():
    before, after = lab(), lab()
    before["r1"].collected = None                       # relevé d'avant la phase B2 : sections de la v0.3.0
    before["r1"].ospf6_neighbors, before["r1"].section_errors = [], {}
    fs = findings(before, after)
    assert [(f.severity.name, f.category, f.device) for f in fs] == [("INFO", "section", "r1")]
    assert "routes_v6, ospf_v3, bgp_v6, vrf" in fs[0].message
    # Aucune route IPv6 « nouvelle », aucun voisin OSPFv3 « nouveau », aucune route de VRF « nouvelle ».
    assert diff.verdict(fs) == ("OK", 0)


def test_a_section_seen_before_and_lost_after_is_attention_per_section_and_per_device():
    before, after = lab(), lab()
    after["r2"].collected = None            # relevé « après » réduit aux sections de la v0.3.0
    after["r2"].section_errors = {}
    fs = findings(before, after)
    assert [(f.severity.name, f.category, f.device) for f in fs] == [("ATTENTION", "section", "r2")] * 4
    assert [f.message.split()[1] for f in fs] == ["routes_v6", "ospf_v3", "bgp_v6", "vrf"]
    assert not any(f.severity == Severity.CRITIQUE for f in fs)      # pas de « préfixe injoignable » fantôme
    assert diff.verdict(fs) == ("ATTENTION", 1)


def test_a_failed_collection_during_an_intervention_is_never_ok_in_diff_guard_and_monitor():
    # Cas réel d'une intervention : la commande BGP IPv6 de r3 n'a pas pu être exécutée APRÈS le changement.
    before, after = lab(), lab()
    after["r3"] = _without("frr", "r3", "show bgp ipv6 unicast json")
    fs = findings(before, after)
    assert [(f.severity.name, f.category, f.device) for f in fs] == [("ATTENTION", "section", "r3")]
    assert "section bgp_v6 perdue : relevée avant, non relevée après" in fs[0].message
    assert "commande non exécutée" in fs[0].message
    label, code = diff.verdict(fs)
    assert (label, code) == ("ATTENTION", 1)
    # guard : jamais SUCCESS ; avec --rollback-on attention, le retour arrière se déclenche.
    assert guard.outcome(code, False, False, False) == ("ATTENTION", 1)
    assert guard.rollback_reasons(code, guard.ScriptResult(0), "attention")
    assert not guard.rollback_reasons(code, guard.ScriptResult(0), "echec")
    # monitor : statut ATTENTION, avec la perte de section dans l'alerte.
    status, contributions = monitor.diff_outcome(fs)
    assert status == monitor.ATTENTION and [c.category for c in contributions] == ["section"]
    results = {name: (True, state) for name, state in after.items()}
    evaluation = monitor.evaluate(results, before, {"eth0"}, None, None)
    assert evaluation.status == monitor.ATTENTION
    assert any(c.category == "section" and c.device == "r3" for c in evaluation.contributions)


def test_several_lost_sections_on_several_devices_give_one_finding_each():
    before, after = lab(), lab()
    after["r3"] = _without("frr", "r3", "show bgp ipv6 unicast json")
    after["r1"] = _without("frr", "r1", "show ipv6 ospf neighbor json")
    fs = findings(before, after)
    assert sorted((f.device, f.message.split()[1]) for f in fs) == [("r1", "ospf_v3"), ("r3", "bgp_v6")]


def _without(lab_name, router, command):
    raw = ds.load_raw(lab_name, router)
    del raw["commands"][command]
    return ds.parse(raw, router)


def test_a_v030_snapshot_against_a_new_one_compares_ipv4_and_says_what_it_skipped():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent / "fixtures" / "snapshot_v030" / "frr"
    old = {f.stem: DeviceState.from_dict(json.loads(f.read_text(encoding="utf-8")))
           for f in sorted(root.glob("r*.json"))}
    new = lab()
    fs = diff.compare(old, new, MGMT)
    sections = [f for f in fs if f.category == "section"]
    assert {f.device for f in sections} == {"r1", "r2", "r3", "r4", "r5"}
    assert all(f.severity == Severity.INFO for f in sections)
    # Rien de ce qui est IPv6 ou VRF n'est dit « nouveau » : ce n'était pas comparable. (Le diff TEXTUEL des
    # configurations, lui, dit bien que les fichiers ont changé : la double pile y a ajouté des lignes.)
    mentions = [f for f in fs if f.category not in ("section", "config")
                and ("2001:db8" in f.message or "VRF" in f.message)]
    assert not mentions


def test_a_section_collected_on_neither_side_is_not_a_change():
    mixed = lab("mixed")
    assert not mixed["r5"].has_section("bgp_v4")
    assert diff.compare(mixed, lab("mixed"), {"eth0", "mgmt0"}, {"mgmt"}) == []


def test_the_vrf_section_gates_non_default_vrf_routes_and_interfaces():
    before, after = lab(), lab()
    after["r2"].collected = [s for s in after["r2"].collected if s != "vrf"]
    # Le driver n'a lu que la VRF default.
    after["r2"].routes = [r for r in after["r2"].routes if r.vrf == "default"]
    fs = findings(before, after)
    assert [(f.severity.name, f.category) for f in fs] == [("ATTENTION", "section")]
    assert "section vrf perdue" in fs[0].message


def test_management_vrf_changes_are_ignored_when_declared_and_seen_otherwise():
    before, after = lab("mixed"), lab("mixed")
    route = next(r for r in after["r5"].routes if r.vrf == "mgmt" and r.prefix == "0.0.0.0/0")
    route.nexthops[0].ip = "172.20.21.99"
    mgmt = {"eth0", "mgmt0"}
    assert diff.compare(before, after, mgmt, {"mgmt"}) == []
    seen = diff.compare(before, after, mgmt)
    assert [(f.category, "VRF mgmt" in f.message) for f in seen] == [("next_hop", True)]


def test_routes_as_before_b2_give_the_same_messages_in_the_default_vrf():
    before = DeviceState(name="x", host="h", timestamp="t", reachable=True,
                         routes=[Route("10.0.0.0/8", "ospf", 10, 110, True)])
    after = copy.deepcopy(before)
    after.routes = []
    assert messages(diff.compare({"x": before}, {"x": after})) == [
        ("CRITIQUE", "route", "x", "préfixe injoignable : 10.0.0.0/8")]
