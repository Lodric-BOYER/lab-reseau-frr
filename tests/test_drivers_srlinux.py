"""Tests du driver SR Linux : normalisation des données collectées sur r5 (Phase D1).

Fixtures capturées sur le vrai lab (tests/fixtures/r5/ et tests/fixtures/degraded/), via une
vraie session Netmiko (device_type "nokia_srl", confirmé en direct) -- jamais inventées, comme
pour FrrDriver. r5 ne parle pas BGP dans ce lab (AS65002 : eBGP seulement entre r3 et r4).
"""
from pathlib import Path

from netcheck.drivers.srlinux import SrlinuxDriver
from netcheck.model import NextHop

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def read(router: str, filename: str) -> str:
    return (FIXTURES / router / filename).read_text(encoding="utf-8")


def test_parse_interfaces_r5():
    driver = SrlinuxDriver()
    interfaces = driver._parse_interfaces(read("r5", "interface.json"))
    by_name = {i.name: i for i in interfaces}

    assert by_name["ethernet-1/1"].admin_up is True
    assert by_name["ethernet-1/1"].oper_up is True
    assert "10.2.45.2/30" in by_name["ethernet-1/1"].addresses

    # Jamais configurée sur ce lab : ne doit pas planter, reste à None (comme FRR sur eth0).
    assert by_name["ethernet-1/1"].description is None

    # is_loopback (motif YANG confirmé sur l'équipement, pas une supposition).
    assert by_name["lo0"].is_loopback is True
    assert by_name["ethernet-1/1"].is_loopback is False
    assert by_name["mgmt0"].is_loopback is False

    # 60 interfaces au total : le châssis expose tous les ports physiques, pas seulement
    # ceux câblés dans ce lab (comportement réel constaté, pas un bug de parsing).
    assert len(interfaces) == 60


def test_parse_routes_resolves_two_level_nexthop_indirection():
    # route.next-hop-group -> next-hop-group[] (indirection ECMP) -> next-hop[] (table finale).
    # Vérifié sur une route OSPF (10.1.0.0/16, apprise depuis r4) : elle doit résoudre vers
    # 10.2.45.1 (r4), jamais vers une IP locale de r5 -- c'est l'anomalie réelle rencontrée et
    # diagnostiquée en direct avant de comprendre qu'il fallait les DEUX tables enchaînées.
    driver = SrlinuxDriver()
    routes = driver._parse_routes(read("r5", "route.json"))
    by_prefix = {r.prefix: r for r in routes}

    remote = by_prefix["10.1.0.0/16"]
    assert remote.protocol == "ospfv2"
    assert remote.selected is True
    assert remote.nexthops == [NextHop(ip="10.2.45.1", interface="ethernet-1/1.0", directly_connected=False)]


def test_parse_routes_local_and_host_marked_directly_connected():
    driver = SrlinuxDriver()
    routes = driver._parse_routes(read("r5", "route.json"))
    by_prefix = {r.prefix: r for r in routes}

    local = by_prefix["192.168.2.0/24"]
    assert local.protocol == "local"
    assert local.nexthops[0].directly_connected is True
    assert local.nexthops[0].ip == "192.168.2.1"


def test_parse_routes_preference_maps_to_distance():
    # "preference" SR Linux == distance administrative FRR (plus petit = préféré), nom différent.
    driver = SrlinuxDriver()
    routes = driver._parse_routes(read("r5", "route.json"))
    ospf_route = next(r for r in routes if r.protocol == "ospfv2")
    assert ospf_route.distance == 150


def test_parse_ospf_neighbor_full_state_normalized_to_frr_convention():
    # SR Linux renvoie l'état en minuscules ("full") ; OspfNeighbor.is_full teste
    # state.startswith("Full") (convention FRR) : le driver doit normaliser la casse.
    driver = SrlinuxDriver()
    neighbors = driver._parse_ospf(read("r5", "ospf_neighbor.json"))
    assert len(neighbors) == 1
    assert neighbors[0].state == "Full"
    assert neighbors[0].is_full is True
    assert neighbors[0].router_id == "10.2.255.4"
    assert neighbors[0].interface == "ethernet-1/1.0"


def test_parse_ospf_neighbor_degraded_link_down():
    driver = SrlinuxDriver()
    text = (FIXTURES / "degraded" / "r5_ospf_neighbor_down.json").read_text(encoding="utf-8")
    neighbors = driver._parse_ospf(text)
    assert neighbors == []  # unique lien coupé : plus aucun voisin


def test_parse_interface_admin_down_degraded():
    driver = SrlinuxDriver()
    text = (FIXTURES / "degraded" / "r5_interface_down.json").read_text(encoding="utf-8")
    interfaces = {i.name: i for i in driver._parse_interfaces(text)}
    assert interfaces["ethernet-1/1"].admin_up is False
    assert interfaces["ethernet-1/1"].oper_up is False


def test_parse_full_device_state_no_bgp():
    driver = SrlinuxDriver()
    raw = {
        cmd: read("r5", fname)
        for cmd, fname in {
            "show interface json": "interface.json",
            "show ip route json": "route.json",
            "show ip ospf neighbor json": "ospf_neighbor.json",
            "show running-config": "running_config.txt",
            "show ospf running-config": "ospf_running_config.txt",
        }.items()
    }
    state = driver.parse(raw, name="r5", host="172.20.21.15")

    assert state.reachable is True
    assert state.name == "r5"
    # state.driver reste "frr" (défaut du modèle) ici : c'est collector.collect() qui le
    # renseigne d'après l'inventaire, pas driver.parse() -- voir test_collector.py.
    assert any(n.is_full for n in state.ospf_neighbors)
    # r5 ne parle pas BGP dans ce lab : listes vides, jamais une erreur (contrat de Driver).
    assert state.bgp_peers == []
    assert state.bgp_prefixes == []
    assert "interface ethernet-1/1" in state.running_config
    # Phase D2 : deux commandes concaténées avec des marqueurs de section (jamais bout à bout,
    # les deux réutilisent la syntaxe "interface <nom> { ... }" avec un sens différent).
    assert "# --- interface ---" in state.running_config
    assert "# --- network-instance default protocols ospf ---" in state.running_config
    assert "interface-type point-to-point" in state.running_config
