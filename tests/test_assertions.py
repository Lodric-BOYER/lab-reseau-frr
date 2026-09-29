"""Tests du moteur d'assertions d'état attendu (`netcheck assert`, Phase C, SPEC_v3 §6) :
  - chargement sûr (yaml.safe_load) et validation du schéma ;
  - un cas vrai, un cas faux et un cas non évaluable par type ;
  - "path" en détail : longest prefix match, trou noir, ECMP (all/any), boucle, profondeur
    maximale, next-hop inconnu, adresse IP portée par plusieurs équipements.

Les DeviceState sont construits directement (comme test_diff.py) : ce module travaille sur le
modèle déjà normalisé, jamais sur du texte brut d'équipement -- rien à capturer en fixture ici.
"""
from pathlib import Path

import pytest

from netcheck import assertions
from netcheck.assertions import Assertion, Status, evaluate, load_intent, verdict
from netcheck.model import BgpPeer, DeviceState, Interface, NextHop, OspfNeighbor, Route


def state(name="r1", *, interfaces=None, routes=None, ospf_neighbors=None, bgp_peers=None,
          reachable=True) -> DeviceState:
    return DeviceState(name=name, host="10.0.0.1", timestamp="2026-01-01T00:00:00+00:00",
                        reachable=reachable, interfaces=interfaces or [], routes=routes or [],
                        ospf_neighbors=ospf_neighbors or [], bgp_peers=bgp_peers or [])


def iface(name, *addresses) -> Interface:
    return Interface(name=name, description=None, admin_up=True, oper_up=True, addresses=list(addresses))


def route(prefix, protocol="ospf", selected=True, nexthops=None) -> Route:
    return Route(prefix=prefix, protocol=protocol, metric=0, distance=0, selected=selected,
                 nexthops=nexthops or [])


def nh(ip=None, interface=None, directly_connected=False) -> NextHop:
    return NextHop(ip=ip, interface=interface, directly_connected=directly_connected)


def dc_nh(ip="192.168.3.1", interface="eth9") -> NextHop:
    """Next-hop directement connecté, raccourci utilisé par les scénarios "path" ci-dessous."""
    return NextHop(ip=ip, interface=interface, directly_connected=True)


def assertion(type_, device="r1", **params) -> Assertion:
    return Assertion(id="test", description="test", device=device, type=type_, params=params)


# ------------------------------------------------------------------------------------------
# Chargement et validation du schéma
# ------------------------------------------------------------------------------------------

def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "intent.yml"
    p.write_text(text, encoding="utf-8")
    return p


def test_malicious_python_tag_is_refused(tmp_path):
    malicious = tmp_path / "intent.yml"
    malicious.write_text(
        "assertions:\n"
        "  - id: evil\n    description: x\n    device: r1\n"
        "    type: !!python/object/apply:os.system [\"echo pwned\"]\n",
        encoding="utf-8",
    )
    with pytest.raises((ValueError, Exception)):
        load_intent(malicious)


def test_missing_required_field_is_rejected(tmp_path):
    path = _write(tmp_path, "assertions:\n  - id: x\n    description: y\n    device: r1\n")
    with pytest.raises(ValueError, match="type"):
        load_intent(path)


def test_unknown_type_is_rejected(tmp_path):
    path = _write(tmp_path,
        "assertions:\n  - id: x\n    description: y\n    device: r1\n    type: reboot_router\n")
    with pytest.raises(ValueError, match="type"):
        load_intent(path)


def test_duplicate_id_is_rejected(tmp_path):
    text = (
        "assertions:\n"
        "  - id: dup\n    description: a\n    device: r1\n    type: interface_up\n    interface: eth1\n"
        "  - id: dup\n    description: b\n    device: r1\n    type: interface_up\n    interface: eth2\n"
    )
    with pytest.raises(ValueError, match="dup"):
        load_intent(_write(tmp_path, text))


def test_params_captured_correctly(tmp_path):
    path = _write(tmp_path,
        "assertions:\n  - id: x\n    description: y\n    device: r1\n"
        "    type: bgp_session\n    neighbor: 1.2.3.4\n    min_prefixes_received: 2\n")
    a = load_intent(path)[0]
    assert a.params == {"neighbor": "1.2.3.4", "min_prefixes_received": 2}


def test_intents_lab_files_load_and_cover_every_type():
    for name in ("lab.yml", "lab-multivendor.yml"):
        path = Path(__file__).resolve().parent.parent / "intents" / name
        loaded = load_intent(path)
        assert len(loaded) >= 6
        assert {a.type for a in loaded} == assertions.KNOWN_TYPES


# ------------------------------------------------------------------------------------------
# bgp_session
# ------------------------------------------------------------------------------------------

def test_bgp_session_ok():
    devices = {"r3": state("r3", bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 2, 2)])}
    a = assertion("bgp_session", device="r3", neighbor="172.16.34.2", min_prefixes_received=2)
    assert evaluate([a], devices)[0].status == Status.OK


def test_bgp_session_echec_wrong_state():
    devices = {"r3": state("r3", bgp_peers=[BgpPeer("172.16.34.2", 65002, "Active", 0, 0)])}
    a = assertion("bgp_session", device="r3", neighbor="172.16.34.2")
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC and "Active" in r.detail


def test_bgp_session_echec_not_enough_prefixes():
    devices = {"r3": state("r3", bgp_peers=[BgpPeer("172.16.34.2", 65002, "Established", 1, 2)])}
    a = assertion("bgp_session", device="r3", neighbor="172.16.34.2", min_prefixes_received=2)
    assert evaluate([a], devices)[0].status == Status.ECHEC


def test_bgp_session_non_evaluable_when_device_absent():
    a = assertion("bgp_session", device="r3", neighbor="172.16.34.2")
    r = evaluate([a], {})[0]
    assert r.status == Status.NON_EVALUABLE


def test_bgp_session_non_evaluable_when_unreachable():
    devices = {"r3": state("r3", reachable=False)}
    a = assertion("bgp_session", device="r3", neighbor="172.16.34.2")
    assert evaluate([a], devices)[0].status == Status.NON_EVALUABLE


# ------------------------------------------------------------------------------------------
# ospf_neighbors
# ------------------------------------------------------------------------------------------

def test_ospf_neighbors_ok():
    devices = {"r1": state("r1", ospf_neighbors=[
        OspfNeighbor("10.1.255.2", "Full/-", "eth1"), OspfNeighbor("10.1.255.3", "Full/-", "eth2"),
    ])}
    a = assertion("ospf_neighbors", device="r1", count=2)
    assert evaluate([a], devices)[0].status == Status.OK


def test_ospf_neighbors_echec_wrong_count():
    devices = {"r1": state("r1", ospf_neighbors=[OspfNeighbor("10.1.255.2", "Full/-", "eth1")])}
    a = assertion("ospf_neighbors", device="r1", count=2)
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC and "1 voisin" in r.detail


def test_ospf_neighbors_non_evaluable():
    a = assertion("ospf_neighbors", device="r9", count=2)
    assert evaluate([a], {})[0].status == Status.NON_EVALUABLE


# ------------------------------------------------------------------------------------------
# route_present / route_absent (correspondance exacte du préfixe)
# ------------------------------------------------------------------------------------------

def test_route_present_ok():
    devices = {"r1": state("r1", routes=[
        route("192.168.2.0/24", protocol="ospf", nexthops=[nh(ip="10.1.13.2", interface="eth2")]),
    ])}
    a = assertion("route_present", device="r1", prefix="192.168.2.0/24", protocol="ospf",
                  next_hop="10.1.13.2", interface="eth2")
    assert evaluate([a], devices)[0].status == Status.OK


def test_route_present_echec_absent():
    devices = {"r1": state("r1", routes=[])}
    a = assertion("route_present", device="r1", prefix="192.168.2.0/24")
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC and "192.168.2.0/24" in r.detail


def test_route_present_echec_wrong_protocol():
    devices = {"r1": state("r1", routes=[route("192.168.2.0/24", protocol="static")])}
    a = assertion("route_present", device="r1", prefix="192.168.2.0/24", protocol="ospf")
    assert evaluate([a], devices)[0].status == Status.ECHEC


def test_route_present_ignores_non_selected_route():
    devices = {"r1": state("r1", routes=[route("192.168.2.0/24", selected=False)])}
    a = assertion("route_present", device="r1", prefix="192.168.2.0/24")
    assert evaluate([a], devices)[0].status == Status.ECHEC


def test_route_absent_ok():
    devices = {"r4": state("r4", routes=[])}
    a = assertion("route_absent", device="r4", prefix="10.1.12.0/30")
    assert evaluate([a], devices)[0].status == Status.OK


def test_route_absent_echec():
    devices = {"r4": state("r4", routes=[route("10.1.12.0/30")])}
    a = assertion("route_absent", device="r4", prefix="10.1.12.0/30")
    assert evaluate([a], devices)[0].status == Status.ECHEC


def test_route_absent_exact_match_only_aggregate_does_not_count():
    # r4 atteint 10.1.12.0/30 par l'agrégat 10.1.0.0/16 (pas d'entrée exacte) : route_absent
    # vérifie une correspondance EXACTE, donc reste OK malgré la joignabilité réelle.
    devices = {"r4": state("r4", routes=[route("10.1.0.0/16")])}
    a = assertion("route_absent", device="r4", prefix="10.1.12.0/30")
    assert evaluate([a], devices)[0].status == Status.OK


# ------------------------------------------------------------------------------------------
# interface_up
# ------------------------------------------------------------------------------------------

def test_interface_up_ok():
    devices = {"r4": state("r4", interfaces=[iface("eth2", "10.2.45.1/30")])}
    a = assertion("interface_up", device="r4", interface="eth2")
    assert evaluate([a], devices)[0].status == Status.OK


def test_interface_up_echec_down():
    down = Interface(name="eth2", description=None, admin_up=True, oper_up=False, addresses=["10.2.45.1/30"])
    devices = {"r4": state("r4", interfaces=[down])}
    a = assertion("interface_up", device="r4", interface="eth2")
    assert evaluate([a], devices)[0].status == Status.ECHEC


def test_interface_up_echec_absent():
    devices = {"r4": state("r4", interfaces=[])}
    a = assertion("interface_up", device="r4", interface="eth2")
    assert evaluate([a], devices)[0].status == Status.ECHEC


# ------------------------------------------------------------------------------------------
# path : topologie r1 -> r2 -> r3 (+ lien direct r1 -> r3 pour les tests ECMP)
# ------------------------------------------------------------------------------------------

TARGET = "192.168.3.0/24"


def _linear_topology():
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.2", interface="eth1")])])
    r2 = state("r2", interfaces=[iface("eth1", "10.0.12.2/30"), iface("eth2", "10.0.23.2/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.23.3", interface="eth2")])])
    r3 = state("r3", interfaces=[iface("eth1", "10.0.23.3/30")],
               routes=[route(TARGET, nexthops=[dc_nh(interface="eth2")])])
    return {"r1": r1, "r2": r2, "r3": r3}


def test_path_ok_linear():
    devices = _linear_topology()
    a = assertion("path", device="r1", prefix=TARGET, via=["r2", "r3"])
    assert evaluate([a], devices)[0].status == Status.OK


def test_path_echec_wrong_sequence_message_shows_computed_path():
    devices = _linear_topology()
    a = assertion("path", device="r1", prefix=TARGET, via=["r3"])  # attendu r1 r3, reel r1 r2 r3
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC
    assert r.detail == "attendu r1 r3, obtenu r1 r2 r3"


def test_path_longest_prefix_match():
    # r4 (ici "r1" du test) n'a pas d'entree exacte pour TARGET, seulement un agregat plus
    # large qui le couvre : le calcul doit utiliser cet agregat (LPM), pas echouer.
    devices = {
        "r1": state("r1", interfaces=[iface("eth1", "10.0.12.1/30")],
                    routes=[route("192.168.0.0/16", nexthops=[nh(ip="10.0.12.2", interface="eth1")])]),
        "r2": state("r2", interfaces=[iface("eth1", "10.0.12.2/30")],
                    routes=[route("192.168.0.0/16", nexthops=[dc_nh(interface="eth2")])]),
    }
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    assert evaluate([a], devices)[0].status == Status.OK


def test_path_longest_prefix_match_picks_the_most_specific_of_several():
    # Deux routes couvrent TARGET (/16 et /20) : le calcul doit suivre la plus specifique (/20),
    # pas la premiere trouvee ni la plus large.
    devices = {
        "r1": state("r1", interfaces=[iface("eth1", "10.0.12.1/30"), iface("eth2", "10.0.13.1/30")],
                    routes=[
                        route("192.168.0.0/16", nexthops=[nh(ip="10.0.12.2", interface="eth1")]),
                        route("192.168.0.0/20", nexthops=[nh(ip="10.0.13.2", interface="eth2")]),
                    ]),
        "r2": state("r2", interfaces=[iface("eth1", "10.0.13.2/30")],
                    routes=[route("192.168.0.0/20", nexthops=[dc_nh(interface="eth2")])]),
    }
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    assert evaluate([a], devices)[0].status == Status.OK


def test_path_echec_blackhole_no_route_at_all():
    devices = {"r1": state("r1", routes=[])}
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC and "trou noir" in r.detail


def test_path_echec_blackhole_null0():
    # ip=None, interface=None : signature d'une route de rejet (Null0/blackhole).
    devices = {"r1": state("r1", routes=[route(TARGET, protocol="static", nexthops=[nh()])])}
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC and "trou noir" in r.detail and "static" in r.detail


def test_path_non_evaluable_unknown_next_hop():
    devices = {"r1": state("r1", routes=[route(TARGET, nexthops=[nh(ip="10.9.9.9", interface="eth1")])])}
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], devices)[0]
    assert r.status == Status.NON_EVALUABLE and "10.9.9.9" in r.detail


def test_path_non_evaluable_router_absent_from_snapshot():
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.2", interface="eth1")])])
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], {"r1": r1})[0]  # r2 absent du dict de peripheriques
    assert r.status == Status.NON_EVALUABLE


def test_path_non_evaluable_loop_detected():
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.2", interface="eth1")])])
    r2 = state("r2", interfaces=[iface("eth1", "10.0.12.2/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.1", interface="eth1")])])  # boucle vers r1
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], {"r1": r1, "r2": r2})[0]
    assert r.status == Status.NON_EVALUABLE and "boucle" in r.detail


def test_path_non_evaluable_max_depth_exceeded():
    # Chaine lineaire de MAX_PATH_HOPS + 2 routeurs, sans boucle ni trou noir : doit s'arreter
    # sur la protection de profondeur, pas boucler indefiniment.
    n = assertions.MAX_PATH_HOPS + 2
    devices = {}
    for i in range(n):
        name = f"r{i}"
        this_ip, next_ip = f"10.0.{i}.1", f"10.0.{i}.2"
        if i < n - 1:
            ifaces = [iface(f"eth{i}", f"{this_ip}/30")]
            routes = [route(TARGET, nexthops=[nh(ip=next_ip, interface=f"eth{i}")])]
        else:
            ifaces, routes = [], [route(TARGET, nexthops=[dc_nh(ip="9.9.9.9")])]
        devices[name] = state(name, interfaces=ifaces, routes=routes)
    # Connecte les interfaces successives : r(i).eth(i) porte l'IP que r(i-1) vise comme next-hop.
    for i in range(1, n):
        devices[f"r{i}"].interfaces.append(iface(f"eth{i}in", f"10.0.{i - 1}.2/30"))
    a = assertion("path", device="r0", prefix=TARGET, via=[f"r{i}" for i in range(1, n)])
    r = evaluate([a], devices)[0]
    assert r.status == Status.NON_EVALUABLE and "profondeur" in r.detail


def test_path_duplicate_ip_is_non_evaluable():
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.2", interface="eth1")])])
    r2 = state("r2", interfaces=[iface("eth1", "10.0.12.2/30")])
    r2b = state("r2b", interfaces=[iface("eth1", "10.0.12.2/30")])  # meme IP que r2 : conflit
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], {"r1": r1, "r2": r2, "r2b": r2b})[0]
    assert r.status == Status.NON_EVALUABLE and "plusieurs équipements" in r.detail


def _ecmp_topology():
    # r1 a deux next-hops pour TARGET : via r2 (branche "r1 r2 r3", conforme à via=["r2"]) et
    # directement vers r3 (branche "r1 r3", pas conforme).
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30"), iface("eth2", "10.0.13.1/30")],
               routes=[route(TARGET, nexthops=[
                   nh(ip="10.0.12.2", interface="eth1"), nh(ip="10.0.13.3", interface="eth2"),
               ])])
    r2 = state("r2", interfaces=[iface("eth1", "10.0.12.2/30")],
               routes=[route(TARGET, nexthops=[dc_nh(interface="eth9")])])
    r3 = state("r3", interfaces=[iface("eth1", "10.0.13.3/30")],
               routes=[route(TARGET, nexthops=[dc_nh(interface="eth9")])])
    return {"r1": r1, "r2": r2, "r3": r3}


def test_path_ecmp_mode_all_fails_on_a_single_mismatching_branch():
    # mode=all doit echouer des qu'une branche (ici "r1 r3") ne correspond pas a via=["r2"].
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"], mode="all")
    r = evaluate([a], _ecmp_topology())[0]
    assert r.status == Status.ECHEC


def test_path_ecmp_mode_any_succeeds_if_one_branch_matches():
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"], mode="any")
    r = evaluate([a], _ecmp_topology())[0]
    assert r.status == Status.OK


def test_path_mode_defaults_to_all():
    devices = _linear_topology()
    a = assertion("path", device="r1", prefix=TARGET, via=["r3"])  # pas de mode explicite
    assert "mode" not in a.params
    r = evaluate([a], devices)[0]
    assert r.status == Status.ECHEC  # "all" implicite : le seul chemin reel (via r2) ne correspond pas


def test_path_invalid_mode_raises():
    devices = _linear_topology()
    a = assertion("path", device="r1", prefix=TARGET, via=["r2", "r3"], mode="somewhere")
    with pytest.raises(ValueError, match="mode"):
        evaluate([a], devices)


def test_path_non_evaluable_when_start_device_unreachable():
    devices = {"r1": state("r1", reachable=False)}
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    assert evaluate([a], devices)[0].status == Status.NON_EVALUABLE


# ------------------------------------------------------------------------------------------
# Verdict / code retour (§6)
# ------------------------------------------------------------------------------------------

def _result(status: Status) -> assertions.AssertionResult:
    return assertions.AssertionResult(assertion=assertion("interface_up", interface="eth1"), status=status)


@pytest.mark.parametrize("statuses,expected", [
    ([], ("OK", 0)),
    ([Status.OK], ("OK", 0)),
    ([Status.OK, Status.NON_EVALUABLE], ("OK", 0)),   # NON EVALUABLE seul ne change pas le code
    ([Status.ECHEC], ("ÉCHEC", 2)),
    ([Status.OK, Status.ECHEC, Status.NON_EVALUABLE], ("ÉCHEC", 2)),
])
def test_verdict(statuses, expected):
    assert verdict([_result(s) for s in statuses]) == expected


# ------------------------------------------------------------------------------------------
# Filtrage des interfaces de management (partagé avec diff/compliance)
# ------------------------------------------------------------------------------------------

def test_path_ignores_management_interfaces_for_ip_lookup():
    # Une IP de management partagée ne doit jamais servir de saut logique.
    r1 = state("r1", interfaces=[iface("eth1", "10.0.12.1/30"), iface("mgmt0", "172.20.20.11/24")],
               routes=[route(TARGET, nexthops=[nh(ip="10.0.12.2", interface="eth1")])])
    r2 = state("r2", interfaces=[iface("eth1", "10.0.12.2/30"), iface("mgmt0", "172.20.20.12/24")],
               routes=[route(TARGET, nexthops=[dc_nh(interface="eth9")])])
    a = assertion("path", device="r1", prefix=TARGET, via=["r2"])
    r = evaluate([a], {"r1": r1, "r2": r2}, management_interfaces={"mgmt0"})[0]
    assert r.status == Status.OK
