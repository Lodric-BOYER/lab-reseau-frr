"""Phase B2 : `assert` en IPv6 et par VRF, `path` en IPv6 (next-hops de lien local), validation des
paramètres.

États : relevés réels des trois labs en double pile (tests/dualstack_support.py). Un test qui modifie un
état le dit.
"""
import copy
from pathlib import Path

import dualstack_support as ds
import pytest

from netcheck import assertions
from netcheck.assertions import Assertion, Status


def run(devices, kind, device, **params):
    a = Assertion(id="t", description="t", device=device, type=kind, params=params)
    return assertions.evaluate([a], devices)[0]


def path(devices, device, prefix, via, **extra):
    return run(devices, "path", device, prefix=prefix, via=via, mode="all", **extra)


FRR, MIXED, CEOS = "frr", "mixed", "ceos"


# ------------------------------------------------------------------------------------------
# bgp_session, ospf_neighbors, route_present / route_absent, interface_up en IPv6 et par VRF
# ------------------------------------------------------------------------------------------

def test_bgp_session_ipv6_nominal_and_the_family_is_deduced_from_the_neighbor():
    lab = ds.load_lab(FRR)
    result = run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3", min_prefixes_received=2)
    assert result.status == Status.OK
    assert run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3", family="ipv6").status == Status.OK
    # Forme d'écriture libre de l'adresse du voisin.
    assert run(lab, "bgp_session", "r3", neighbor="2001:DB8:34:0::3").status == Status.OK
    wrong = run(lab, "bgp_session", "r3", neighbor="2001:db8:34::99")
    assert wrong.status == Status.ECHEC and "aucune session BGP vers 2001:db8:34::99" in wrong.detail


def test_bgp_session_ipv6_down_is_an_echec_not_a_non_evaluable():
    lab = ds.load_lab(FRR)
    next(p for p in lab["r3"].bgp_peers if p.address_family == "ipv6").state = "Active"
    result = run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3")
    assert result.status == Status.ECHEC and "état Active" in result.detail
    # L'IPv4 n'est pas touchée.
    assert run(lab, "bgp_session", "r3", neighbor="172.16.34.2").status == Status.OK


def test_bgp_session_in_a_vrf_is_not_evaluable_since_no_driver_collects_it():
    for lab_name in (FRR, MIXED, CEOS):
        result = run(ds.load_lab(lab_name), "bgp_session", "r3", neighbor="2001:db8:34::3", vrf="DEMO")
        assert result.status == Status.NON_EVALUABLE and "bgp_vrf" in result.detail


def test_bgp_session_ipv6_on_eos():
    lab = ds.load_lab(CEOS)
    result = run(lab, "bgp_session", "r4", neighbor="2001:db8:34::2", min_prefixes_received=2)
    assert result.status == Status.OK


def test_ospf_neighbors_family_ipv6_counts_ospfv3_apart_from_ospfv2():
    lab = ds.load_lab(FRR)
    assert run(lab, "ospf_neighbors", "r3", family="ipv6", count=2).status == Status.OK
    assert run(lab, "ospf_neighbors", "r3", count=2).status == Status.OK
    result = run(lab, "ospf_neighbors", "r3", family="ipv6", count=1)
    assert result.status == Status.ECHEC and "OSPFv3" in result.detail
    lab["r3"].ospf6_neighbors.pop()                       # un voisin OSPFv3 perdu : l'OSPFv2 reste à 2
    assert run(lab, "ospf_neighbors", "r3", family="ipv6", count=2).status == Status.ECHEC
    assert run(lab, "ospf_neighbors", "r3", count=2).status == Status.OK


@pytest.mark.parametrize(("lab_name", "device"), [(MIXED, "r5"), (CEOS, "r4")])
def test_ospf_neighbors_family_ipv6_on_srlinux_and_eos(lab_name, device):
    lab = ds.load_lab(lab_name)
    assert run(lab, "ospf_neighbors", device, family="ipv6", count=1).status == Status.OK


def test_ospf_neighbors_in_a_vrf_is_not_evaluable():
    result = run(ds.load_lab(FRR), "ospf_neighbors", "r3", count=2, vrf="DEMO")
    assert result.status == Status.NON_EVALUABLE


def test_route_present_ipv6_protocol_interface_and_next_hop_written_any_way():
    lab = ds.load_lab(FRR)
    result = run(lab, "route_present", "r1", prefix="2001:db8:a2::/64", protocol="ospf6", interface="eth2")
    assert result.status == Status.OK
    r1 = lab["r1"]
    nh = next(r for r in r1.routes if r.prefix == "2001:db8:a2::/64" and r.selected).nexthops[0].ip
    result = run(lab, "route_present", "r1", prefix="2001:DB8:A2:0::/64", next_hop=nh.upper())
    assert result.status == Status.OK
    assert run(lab, "route_present", "r1", prefix="2001:db8:a2::/64", protocol="bgp").status == Status.ECHEC
    result = run(lab, "route_present", "r1", prefix="2001:db8:a2::/64", next_hop="fe80::dead")
    assert result.status == Status.ECHEC
    assert run(lab, "route_present", "r1", prefix="2001:db8:ffff::/64").status == Status.ECHEC


def test_route_absent_ipv6_exact_prefix_only():
    lab = ds.load_lab(FRR)
    # Atteint par l'agrégat seulement.
    assert run(lab, "route_absent", "r4", prefix="2001:db8:1:12::/127").status == Status.OK
    assert run(lab, "route_absent", "r4", prefix="2001:db8:1::/48").status == Status.ECHEC


@pytest.mark.parametrize(("lab_name", "device", "protocol"), [
    (FRR, "r4", "static"), (CEOS, "r4", "static"), (MIXED, "r5", "ospfv3")])
def test_route_present_ipv6_protocol_names_per_driver(lab_name, device, protocol):
    prefix = "2001:db8:1::/48" if protocol == "ospfv3" else "2001:db8:2::/48"
    result = run(ds.load_lab(lab_name), "route_present", device, prefix=prefix, protocol=protocol)
    assert result.status == Status.OK


def test_route_in_a_vrf_is_found_in_that_vrf_only():
    lab = ds.load_lab(FRR)
    result = run(lab, "route_present", "r2", prefix="2001:db8:99:9::/64", vrf="DEMO", protocol="static")
    assert result.status == Status.OK
    assert run(lab, "route_present", "r2", prefix="10.99.9.0/24", vrf="DEMO").status == Status.OK
    # La même route n'existe pas dans default : une route = (vrf, préfixe).
    assert run(lab, "route_present", "r2", prefix="2001:db8:99:9::/64").status == Status.ECHEC
    assert run(lab, "route_absent", "r2", prefix="2001:db8:99:9::/64").status == Status.OK
    assert run(lab, "route_absent", "r2", prefix="2001:db8:99:9::/64", vrf="DEMO").status == Status.ECHEC
    assert run(lab, "route_present", "r2", prefix="2001:db8:99:9::/64", vrf="INCONNUE").status == Status.ECHEC


def test_route_in_a_vrf_on_eos_with_a_real_temporary_vrf():
    raw = ds.load_raw(CEOS, "r4_tmpvrf")["commands"]
    state = ds.parse_with(CEOS, "r4", raw)
    lab = {"r4": state}
    result = run(lab, "route_present", "r4", prefix="10.99.9.0/24", vrf="TMPVRF", protocol="static")
    assert result.status == Status.OK
    assert run(lab, "route_present", "r4", prefix="2001:db8:99:4::1/128", vrf="TMPVRF").status == Status.OK
    # Pas dans la VRF default.
    assert run(lab, "route_absent", "r4", prefix="10.99.9.0/24").status == Status.OK
    assert run(lab, "interface_up", "r4", interface="Loopback99", vrf="TMPVRF").status == Status.OK
    assert run(lab, "interface_up", "r4", interface="Loopback99", vrf="default").status == Status.ECHEC
    # Le nom seul : comme avant la phase B2.
    assert run(lab, "interface_up", "r4", interface="Loopback99").status == Status.OK


def test_interface_up_by_name_alone_still_works_and_vrf_is_optional():
    lab = ds.load_lab(FRR)
    assert run(lab, "interface_up", "r2", interface="eth1").status == Status.OK
    assert run(lab, "interface_up", "r2", interface="dum-demo", vrf="DEMO").status == Status.OK
    assert run(lab, "interface_up", "r2", interface="dum-demo", vrf="default").status == Status.ECHEC


# ------------------------------------------------------------------------------------------
# Sections : relevée mais vide ≠ non relevée
# ------------------------------------------------------------------------------------------

def test_empty_but_collected_gives_echec_and_not_collected_gives_non_evaluable_on_frr():
    lab = ds.load_lab(FRR)
    # r2 n'a pas de BGP IPv6 : section relevée, vide -> « aucune session » (ÉCHEC, un fait observable).
    assert run(lab, "bgp_session", "r2", neighbor="2001:db8:34::3").status == Status.ECHEC
    lab["r2"].collected.remove("bgp_v6")
    result = run(lab, "bgp_session", "r2", neighbor="2001:db8:34::3")
    assert result.status == Status.NON_EVALUABLE and "bgp_v6" in result.detail


def test_empty_but_collected_gives_echec_and_not_collected_gives_non_evaluable_on_eos():
    lab = ds.load_lab(CEOS)
    peers = [p for p in lab["r4"].bgp_peers if p.address_family == "ipv6"]
    for p in peers:
        lab["r4"].bgp_peers.remove(p)
    assert run(lab, "bgp_session", "r4", neighbor="2001:db8:34::2").status == Status.ECHEC
    lab["r4"].collected.remove("bgp_v6")
    assert run(lab, "bgp_session", "r4", neighbor="2001:db8:34::2").status == Status.NON_EVALUABLE


def test_empty_but_collected_gives_echec_and_not_collected_gives_non_evaluable_on_srlinux():
    lab = ds.load_lab(MIXED)
    # SR Linux : les routes IPv6 sont relevées ; une route absente est un ÉCHEC...
    assert run(lab, "route_present", "r5", prefix="2001:db8:ffff::/64").status == Status.ECHEC
    # ... alors que le BGP n'est jamais relevé : NON ÉVALUABLE, jamais « aucune session ».
    assert run(lab, "bgp_session", "r5", neighbor="10.2.45.1").status == Status.NON_EVALUABLE
    lab["r5"].collected.remove("routes_v6")
    result = run(lab, "route_present", "r5", prefix="2001:db8:ffff::/64")
    assert result.status == Status.NON_EVALUABLE and "routes_v6" in result.detail


def test_vrf_assertions_need_the_vrf_section_on_every_driver():
    for lab_name, device in ((FRR, "r2"), (MIXED, "r5"), (CEOS, "r4")):
        lab = ds.load_lab(lab_name)
        lab[device].collected.remove("vrf")
        for kind, params in (("route_present", {"prefix": "10.99.9.0/24", "vrf": "DEMO"}),
                             ("route_absent", {"prefix": "10.99.9.0/24", "vrf": "DEMO"}),
                             ("interface_up", {"interface": "eth1", "vrf": "DEMO"})):
            assert run(lab, kind, device, **params).status == Status.NON_EVALUABLE, (lab_name, kind)


def test_an_unreachable_device_is_still_not_evaluable():
    lab = ds.load_lab(FRR)
    lab["r3"].reachable = False
    assert run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3").status == Status.NON_EVALUABLE


# ------------------------------------------------------------------------------------------
# path en IPv6 : nominal, trou noir Null0, lien local
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("lab_name", "prefix", "start", "via"), [
    (FRR, "2001:db8:a2::/64", "r1", ["r3", "r4", "r5"]),
    (FRR, "2001:db8:a1::/64", "r5", ["r4", "r3", "r1"]),
    (MIXED, "2001:db8:a2::/64", "r1", ["r3", "r4", "r5"]),
    (MIXED, "2001:db8:a1::/64", "r5", ["r4", "r3", "r1"]),
    (CEOS, "2001:db8:a2::/64", "r1", ["r3", "r4", "r5"]),
    (CEOS, "2001:db8:a1::/64", "r5", ["r4", "r3", "r1"]),
    (CEOS, "2001:db8:a1::/64", "r4", ["r3", "r1"]),
])
def test_ipv6_path_nominal_through_link_local_next_hops(lab_name, prefix, start, via):
    lab = ds.load_lab(lab_name)
    result = path(lab, start, prefix, via)
    assert result.status == Status.OK, result.detail


def test_ipv6_path_crosses_the_vendor_boundaries_with_different_interface_names():
    # r5 (SR Linux) nomme son next-hop par sous-interface « ethernet-1/1.0 », r4 (FRR) a « eth2 » : même lien.
    lab = ds.load_lab(MIXED)
    route = next(r for r in lab["r5"].routes if r.prefix == "2001:db8:a1::/64" and r.vrf == "default")
    nh = route.nexthops[0]
    assert nh.interface == "ethernet-1/1.0" and nh.ip.startswith("fe80::")
    assert path(lab, "r5", "2001:db8:a1::/64", ["r4", "r3", "r1"]).status == Status.OK


def test_ipv6_path_wrong_expected_hops_is_an_echec_with_the_real_path():
    result = path(ds.load_lab(FRR), "r1", "2001:db8:a2::/64", ["r2", "r3", "r4", "r5"])
    assert result.status == Status.ECHEC and "attendu r1 r2 r3 r4 r5, obtenu r1 r3 r4 r5" in result.detail


@pytest.mark.parametrize("lab_name", [FRR, CEOS])
def test_ipv6_blackhole_on_the_null0_aggregate_of_r4(lab_name):
    # 2001:db8:2:99::/64 n'a pas de route plus précise : r4 la couvre par l'agrégat 2001:db8:2::/48 vers
    # Null0.
    result = path(ds.load_lab(lab_name), "r3", "2001:db8:2:99::/64", ["r4"])
    assert result.status == Status.ECHEC
    assert "trou noir sur r4" in result.detail and "2001:db8:2::/48" in result.detail


def test_ipv6_blackhole_when_no_route_covers_the_prefix():
    result = path(ds.load_lab(FRR), "r1", "2001:db8:dead::/64", ["r3"])
    assert result.status == Status.ECHEC and "aucune route ne couvre" in result.detail


def test_link_local_next_hop_is_resolved_by_address_and_outgoing_interface_never_by_address_alone():
    lab = ds.load_lab(FRR)
    # r2 porte, sur son lien vers r1, la MÊME adresse de lien local que r4 sur son lien vers r3. L'adresse
    # seule désignerait deux équipements ; avec l'interface de sortie (lien r3-r4), seul r4 est sur ce lien.
    r4_eth1 = next(i for i in lab["r4"].interfaces if i.name == "eth1")
    next(i for i in lab["r2"].interfaces if i.name == "eth1").link_local6 = r4_eth1.link_local6
    assert path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"]).status == Status.OK


def test_link_local_next_hop_not_found_on_the_link_is_not_evaluable_with_the_reason():
    lab = ds.load_lab(FRR)
    next(i for i in lab["r4"].interfaces if i.name == "eth1").link_local6 = None
    result = path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"])
    assert result.status == Status.NON_EVALUABLE
    assert "aucun équipement ne porte cette adresse de lien local sur le même lien" in result.detail
    assert "sur r3 (eth3)" in result.detail


def test_link_local_address_carried_by_two_devices_on_the_same_link_is_ambiguous():
    lab = ds.load_lab(FRR)
    twin = copy.deepcopy(lab["r4"])
    twin.name = "r4bis"
    # Un second équipement sur le lien r3-r4, avec la même fe80:: et les mêmes adresses.
    lab["r4bis"] = twin
    result = path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"])
    assert result.status == Status.NON_EVALUABLE
    assert "plusieurs équipements (r4, r4bis)" in result.detail


def test_link_local_next_hop_with_an_unknown_outgoing_interface_is_not_evaluable():
    lab = ds.load_lab(FRR)
    for route in lab["r1"].routes:
        if route.prefix == "2001:db8:a2::/64" and route.selected:
            route.nexthops[0].interface = "ethX"
    result = path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"])
    assert result.status == Status.NON_EVALUABLE and "interface de sortie ethX introuvable" in result.detail


def test_link_local_next_hop_on_an_interface_without_any_address_cannot_tell_the_link():
    lab = ds.load_lab(FRR)
    eth2 = next(i for i in lab["r1"].interfaces if i.name == "eth2")
    eth2.addresses, eth2.addresses6 = [], []
    result = path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"])
    assert result.status == Status.NON_EVALUABLE and "lien est indéterminable" in result.detail


def test_global_ipv6_next_hop_is_resolved_by_its_owner():
    # Sur r3 (FRR), la route BGP vers r4 a un next-hop de lien local ; sur r4 (EOS), celle vers r3 a un
    # next-hop GLOBAL (2001:db8:34::2) : résolu par le propriétaire de l'adresse.
    lab = ds.load_lab(CEOS)
    nh = next(r for r in lab["r4"].routes if r.prefix == "2001:db8:a1::/64").nexthops[0]
    assert nh.ip == "2001:db8:34::2"
    assert path(lab, "r4", "2001:db8:a1::/64", ["r3", "r1"]).status == Status.OK


def test_path_needs_the_ipv6_routes_of_every_device_it_crosses():
    lab = ds.load_lab(FRR)
    lab["r4"].collected.remove("routes_v6")
    result = path(lab, "r1", "2001:db8:a2::/64", ["r3", "r4", "r5"])
    assert result.status == Status.NON_EVALUABLE and "routes_v6" in result.detail and "r4" in result.detail


def test_path_stays_in_the_vrf_of_the_start():
    lab = ds.load_lab(FRR)
    # Dans la VRF DEMO de r2 : la route de rejet du lab (2001:db8:99:9::/64) est un trou noir ; le
    # sous-réseau connecté est atteint directement.
    blackhole = path(lab, "r2", "2001:db8:99:9::/64", [], vrf="DEMO")
    assert blackhole.status == Status.ECHEC and "trou noir sur r2" in blackhole.detail
    assert path(lab, "r2", "2001:db8:99::/64", [], vrf="DEMO").status == Status.OK
    # Le même préfixe dans la VRF default n'existe pas : aucune route (la VRF de départ est respectée).
    other = path(lab, "r2", "2001:db8:99::/64", [])
    assert other.status == Status.ECHEC and "aucune route ne couvre" in other.detail
    assert path(lab, "r2", "10.99.9.0/24", [], vrf="DEMO").status == Status.ECHEC            # IPv4 aussi


def test_an_address_owned_in_another_vrf_is_not_an_owner_for_the_path():
    lab = ds.load_lab(FRR)
    # Modification d'un relevé réel : r2 porte, DANS LA VRF DEMO, l'adresse IPv4 de r4 vers r3. Dans la VRF
    # de départ (default), seul r4 la porte : le chemin se résout ; sans le filtre par VRF il serait ambigu.
    r4_addr = next(i.addresses[0] for i in lab["r4"].interfaces if i.name == "eth1")
    demo = next(i for i in lab["r2"].interfaces if i.name == "dum-demo")
    demo.addresses = [r4_addr]
    assert path(lab, "r1", "192.168.2.0/24", ["r3", "r4", "r5"]).status == Status.OK


def test_path_in_a_vrf_needs_the_vrf_section():
    lab = ds.load_lab(FRR)
    lab["r2"].collected.remove("vrf")
    assert path(lab, "r2", "2001:db8:99::/64", [], vrf="DEMO").status == Status.NON_EVALUABLE


def test_ipv4_paths_are_unchanged_on_the_dualstack_labs():
    for lab_name, via in ((FRR, ["r3", "r4", "r5"]), (MIXED, ["r3", "r4", "r5"]), (CEOS, ["r3", "r4", "r5"])):
        assert path(ds.load_lab(lab_name), "r1", "192.168.2.0/24", via).status == Status.OK, lab_name


# ------------------------------------------------------------------------------------------
# Validation des paramètres au chargement
# ------------------------------------------------------------------------------------------

COMMON = "id: a, description: d"


def _load(tmp_path: Path, body: str):
    f = tmp_path / "intent.yml"
    f.write_text("assertions:\n" + body, encoding="utf-8")
    return assertions.load_intent(f)


def test_a_bgp_family_is_not_checked_against_the_neighbor_address(tmp_path):
    # Un voisin IPv6 peut porter la famille IPv4 (RFC 8950) : `family: ipv4` y reste valide.
    loaded = _load(tmp_path, """
  - {id: a, description: d, device: r3, type: bgp_session, neighbor: "2001:db8:34::3", family: ipv4}
""")
    assert loaded[0].params["family"] == "ipv4"


def test_the_family_of_a_bgp_session_selects_the_session_for_a_neighbor_in_both_families():
    # Modification d'un relevé réel : le voisin IPv6 de r3 est aussi activé dans la famille IPv4 (RFC 8950),
    # en état différent (Idle) : la famille demandée choisit la session.
    lab = ds.load_lab(FRR)
    v6 = next(p for p in lab["r3"].bgp_peers if p.address_family == "ipv6")
    twin = copy.deepcopy(v6)
    twin.address_family, twin.state = "ipv4", "Idle"
    lab["r3"].bgp_peers.append(twin)
    assert run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3", family="ipv6").status == Status.OK
    result = run(lab, "bgp_session", "r3", neighbor="2001:db8:34::3", family="ipv4")
    assert result.status == Status.ECHEC and "état Idle" in result.detail


def test_family_and_vrf_are_accepted_when_valid(tmp_path):
    loaded = _load(tmp_path, """
  - {id: a, description: d, device: r3, type: bgp_session, neighbor: "2001:db8:34::3", family: ipv6}
  - {id: b, description: d, device: r2, type: route_present, prefix: "10.99.9.0/24", vrf: DEMO}
  - {id: c, description: d, device: r1, type: ospf_neighbors, count: 2, family: ipv6}
""")
    assert [a.params.get("family") for a in loaded] == ["ipv6", None, "ipv6"]


BGP = "device: r3, type: bgp_session"
ROUTE = "device: r3, type: route_present"


@pytest.mark.parametrize(("fields", "message"), [
    (f'{BGP}, neighbor: "2001:db8::1", family: v6', "family doit être"),
    (f'{ROUTE}, prefix: "10.0.0.0/8", family: ipv6', "contredit prefix"),
    ('device: r1, type: path, prefix: "2001:db8::/32", via: [], family: ipv4', "contredit prefix"),
    (f'{ROUTE}, prefix: "10.0.0.0/8", vrf: ""', "vrf doit être"),
    (f'{ROUTE}, prefix: "10.0.0.0/8", vrf: 12', "vrf doit être"),
])
def test_invalid_family_or_vrf_is_refused_at_load(tmp_path, fields, message):
    with pytest.raises(ValueError, match=message):
        _load(tmp_path, f"  - {{{COMMON}, {fields}}}\n")


def test_the_shipped_intents_load_and_pass_offline_on_the_matching_dualstack_labs():
    root = Path(__file__).resolve().parent.parent / "intents"
    for intent, lab_name in (("lab.yml", FRR), ("lab-multivendor.yml", MIXED), ("lab-ceos.yml", CEOS)):
        loaded = assertions.load_intent(root / intent)
        results = assertions.evaluate(loaded, ds.load_lab(lab_name), {"eth0", "mgmt0", "Management0"},
                                       {"mgmt"})
        assert [r.assertion.id for r in results if r.status != Status.OK] == [], intent
        ipv6_ids = ("bgp6", "ospf6", "route6", "chemin6", "vrf-demo")
        assert sum(1 for a in loaded if a.id.startswith(ipv6_ids)) >= 5, intent
