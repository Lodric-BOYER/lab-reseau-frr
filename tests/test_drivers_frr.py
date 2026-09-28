"""Tests du driver FRR : normalisation des 5 types de données collectées.

Fixtures capturées sur le vrai lab (tests/fixtures/), pas inventées (§6 du cahier des charges) :
r1 (routeur interne, sans BGP), r3 et r4 (bordure eBGP, un côté de chaque AS), plus deux cas
dégradés (tests/fixtures/degraded/) : lien OSPF coupé et session BGP coupée.
"""
from pathlib import Path

from netcheck.drivers.frr import FrrDriver

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def read(router: str, filename: str) -> str:
    return (FIXTURES / router / filename).read_text(encoding="utf-8")


def test_parse_interfaces_r1():
    driver = FrrDriver()
    interfaces = driver._parse_interfaces(read("r1", "interface.json"))
    by_name = {i.name: i for i in interfaces}

    assert by_name["eth1"].description == "vers-r2"
    assert by_name["eth1"].admin_up is True
    assert by_name["eth1"].oper_up is True
    assert "10.1.12.1/30" in by_name["eth1"].addresses
    assert all(":" not in a for a in by_name["eth1"].addresses)  # pas d'IPv6

    # eth0 (management) n'a pas de description dans FRR : ne doit pas planter, reste à None.
    assert by_name["eth0"].description is None

    # is_loopback (v2, O3) : lu depuis le champ JSON "type" de FRR, jamais None pour ce driver.
    assert by_name["lo"].is_loopback is True
    assert by_name["eth0"].is_loopback is False
    assert by_name["eth1"].is_loopback is False


def test_parse_routes_ecmp_and_missing_selected_key():
    driver = FrrDriver()
    routes = driver._parse_routes(read("r1", "route.json"))
    ecmp = [r for r in routes if r.prefix == "10.1.23.0/30"]
    assert len(ecmp) == 1
    assert len(ecmp[0].nexthops) == 2  # ECMP via r2 et r3
    assert ecmp[0].selected is True

    # Une route candidate non installée n'a pas la clé "selected" dans le JSON brut (absente,
    # pas à false) : elle doit être normalisée à False, jamais lever de KeyError.
    assert all(isinstance(r.selected, bool) for r in routes)


def test_parse_ospf_neighbors_full():
    driver = FrrDriver()
    neighbors = driver._parse_ospf(read("r1", "ospf_neighbor.json"))
    assert len(neighbors) == 2
    assert all(n.is_full for n in neighbors)
    assert all(n.state == "Full/-" for n in neighbors)


def test_parse_interface_admin_down_has_no_operational_status_key():
    # Quand une interface est coupée (admin down), FRR omet complètement la clé
    # "operationalStatus" au lieu de la mettre à "down" : .get() doit rester sûr.
    driver = FrrDriver()
    text = (FIXTURES / "degraded" / "r1_interface_down.json").read_text(encoding="utf-8")
    interfaces = {i.name: i for i in driver._parse_interfaces(text)}
    assert interfaces["eth2"].admin_up is False
    assert interfaces["eth2"].oper_up is False
    assert interfaces["eth1"].oper_up is True  # les autres interfaces restent up
    # "type" reste présent même admin down : is_loopback ne doit jamais devenir None ici.
    assert interfaces["eth2"].is_loopback is False


def test_parse_ospf_neighbors_degraded():
    driver = FrrDriver()
    text = (FIXTURES / "degraded" / "r1_ospf_neighbor_down.json").read_text(encoding="utf-8")
    neighbors = driver._parse_ospf(text)
    assert len(neighbors) == 1  # lien vers r3 coupé : seul r2 reste voisin
    assert neighbors[0].is_full


def test_parse_bgp_summary_established():
    driver = FrrDriver()
    peers = driver._parse_bgp_summary(read("r3", "bgp_summary.json"))
    assert len(peers) == 1
    peer = peers[0]
    assert peer.neighbor == "172.16.34.2"
    assert peer.state == "Established"
    assert peer.pfx_received == 2
    assert peer.remote_as == 65002


def test_parse_bgp_summary_degraded():
    driver = FrrDriver()
    text = (FIXTURES / "degraded" / "r3_bgp_summary_down.json").read_text(encoding="utf-8")
    peers = driver._parse_bgp_summary(text)
    assert peers[0].state != "Established"


def test_parse_bgp_prefixes_local_vs_received():
    driver = FrrDriver()
    prefixes = driver._parse_bgp_prefixes(read("r3", "bgp_prefixes.json"))
    by_prefix = {p.prefix: p for p in prefixes}

    local = by_prefix["10.1.0.0/16"]
    assert local.as_path == ""  # origine locale : pas d'AS-path
    assert local.best is True

    received = by_prefix["10.2.0.0/16"]
    assert received.as_path == "65002"
    assert received.next_hop == "172.16.34.2"


def test_parse_bgp_absent_on_router_without_bgp_configured():
    # r1 n'a pas de "router bgp" configuré : FRR renvoie "{}" (aucune clé "peers") pour le
    # résumé, et {"warning": "..."} (aucune clé "routes") pour les préfixes. Ne doit pas planter.
    driver = FrrDriver()
    assert driver._parse_bgp_summary(read("r1", "bgp_summary.json")) == []
    assert driver._parse_bgp_prefixes(read("r1", "bgp_prefixes.json")) == []


def test_parse_full_device_state():
    driver = FrrDriver()
    raw = {
        cmd: read("r3", fname)
        for cmd, fname in {
            "show interface json": "interface.json",
            "show ip route json": "route.json",
            "show ip ospf neighbor json": "ospf_neighbor.json",
            "show bgp ipv4 unicast summary json": "bgp_summary.json",
            "show bgp ipv4 unicast json": "bgp_prefixes.json",
            "show running-config": "running_config.txt",
        }.items()
    }
    state = driver.parse(raw, name="r3", host="172.20.20.13")

    assert state.reachable is True
    assert state.name == "r3"
    assert len(state.bgp_peers) == 1
    assert "router bgp 65001" in state.running_config
