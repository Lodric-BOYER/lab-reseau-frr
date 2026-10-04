"""Phase B2 : modèle IPv6 / VRF, sections collectées, compatibilité d'un snapshot v0.3.0, filtrage du
management.

Relevés réels des labs en double pile (tests/fixtures/dualstack/) et un vrai snapshot v0.3.0 du lab mixte
(tests/fixtures/snapshot_v030/ : `frr` = lab FRR nominal, `mixte` = lab mixte dont r5 est SR Linux ; écrits
par netcheck 0.3.0 avant toute modification de la phase B).
"""
import copy
import json
from pathlib import Path

import dualstack_support as ds
import pytest
import yaml

from netcheck import assertions, diff, inventory, management
from netcheck.assertions import Assertion, Status
from netcheck.model import DEFAULT_VRF, LEGACY_SECTIONS, SECTIONS, DeviceState

LEGACY_ROOT = Path(__file__).resolve().parent / "fixtures" / "snapshot_v030"
LEGACY_DIR = LEGACY_ROOT / "frr"      # lab FRR nominal, 5 routeurs FRR
REPO = Path(__file__).resolve().parent.parent


def legacy(lab: str = "frr") -> dict[str, DeviceState]:
    """Chargement comme `snapshot.load` : DeviceState.from_dict sur chaque <équipement>.json."""
    return {f.stem: DeviceState.from_dict(json.loads(f.read_text(encoding="utf-8")))
            for f in sorted((LEGACY_ROOT / lab).glob("r*.json"))}


def run(devices, kind, device, **params):
    a = Assertion(id="t", description="t", device=device, type=kind, params=params)
    return assertions.evaluate([a], devices)[0]


# ------------------------------------------------------------------------------------------
# Compatibilité ascendante : un snapshot v0.3.0 se charge
# ------------------------------------------------------------------------------------------

def test_a_v030_snapshot_loads_and_is_read_as_the_default_vrf():
    for lab in ("frr", "mixte"):
        _check_legacy(legacy(lab), lab)


def _check_legacy(states, lab):
    assert set(states) == {"r1", "r2", "r3", "r4", "r5"}
    assert json.loads((LEGACY_ROOT / lab / "meta.json").read_text())["netcheck_version"] == "0.3.0"
    for state in states.values():
        assert state.collected is None and state.section_errors == {} and state.ospf6_neighbors == []
        assert {r.vrf for r in state.routes} == {DEFAULT_VRF}
        assert {i.vrf for i in state.interfaces} == {DEFAULT_VRF}
        assert all(i.addresses6 == [] and i.link_local6 is None for i in state.interfaces)
        assert all(p.vrf == DEFAULT_VRF and p.address_family == "ipv4" for p in state.bgp_peers)


def test_a_v030_snapshot_has_exactly_the_v030_sections_of_its_driver():
    states = legacy("mixte")
    for name in ("r1", "r2", "r3", "r4"):          # FRR
        assert {s for s in SECTIONS if states[name].has_section(s)} == set(LEGACY_SECTIONS)
    # SR Linux ne relevait déjà aucune session BGP : section absente, pas « vide ».
    assert {s for s in SECTIONS if states["r5"].has_section(s)} == set(LEGACY_SECTIONS) - {"bgp_v4"}
    assert states["r5"].driver == "srlinux"


@pytest.mark.parametrize("missing", ["routes_v6", "ospf_v3", "bgp_v6", "vrf", "bgp_vrf"])
def test_ipv6_and_vrf_are_not_collected_in_a_v030_snapshot(missing):
    state = legacy()["r3"]
    assert not state.has_section(missing)
    assert "avant la phase B2" in state.why_missing(missing)


def test_assertions_needing_ipv6_or_vrf_are_not_evaluable_on_a_v030_snapshot_never_ok():
    states = legacy()
    cases = [
        ("bgp_session", "r3", {"neighbor": "2001:db8:34::3"}),
        ("ospf_neighbors", "r1", {"family": "ipv6", "count": 2}),
        ("route_present", "r1", {"prefix": "2001:db8:a2::/64"}),
        ("route_absent", "r4", {"prefix": "2001:db8:1:12::/127"}),
        ("route_present", "r2", {"prefix": "10.99.9.0/24", "vrf": "DEMO"}),
        ("interface_up", "r2", {"interface": "dum-demo", "vrf": "DEMO"}),
        ("path", "r1", {"prefix": "2001:db8:a2::/64", "via": ["r3", "r4", "r5"]}),
    ]
    for kind, device, params in cases:
        result = run(states, kind, device, **params)
        assert result.status == Status.NON_EVALUABLE, (kind, params, result)
        assert "non relevée" in result.detail
    # ... et l'IPv4 d'avant se lit comme avant.
    assert run(states, "route_present", "r1", prefix="192.168.2.0/24", protocol="ospf").status == Status.OK
    assert run(states, "bgp_session", "r3", neighbor="172.16.34.2").status == Status.OK


def test_srlinux_bgp_is_not_collected_so_a_bgp_assertion_on_r5_is_not_evaluable():
    new = ds.load_lab("mixed")
    for states in (legacy("mixte"), new):
        result = run(states, "bgp_session", "r5", neighbor="10.2.45.1")
        assert result.status == Status.NON_EVALUABLE
    assert "le driver ne la relève pas" in new["r5"].why_missing("bgp_v4")


def test_a_state_built_by_hand_without_collected_keeps_the_pre_b2_behaviour():
    state = DeviceState(name="rx", host="x", timestamp="t", reachable=True)
    assert state.collected is None and state.has_section("bgp_v4") and state.has_section("routes_v4")
    # Aucune session : ÉCHEC comme avant (section relevée, vide), pas NON ÉVALUABLE.
    assert run({"rx": state}, "bgp_session", "rx", neighbor="10.0.0.1").status == Status.ECHEC


def test_unknown_section_name_is_an_error():
    with pytest.raises(ValueError, match="section inconnue"):
        legacy()["r1"].has_section("routes_v7")


@pytest.mark.parametrize("lab", ["frr", "mixed", "ceos"])
def test_a_new_snapshot_round_trips_through_json_with_its_sections(lab):
    for name, state in ds.load_lab(lab).items():
        again = DeviceState.from_dict(json.loads(json.dumps(state.to_dict())))
        assert again == state, name
        assert again.collected == state.collected and again.ospf6_neighbors == state.ospf6_neighbors


# ------------------------------------------------------------------------------------------
# Filtrage du management étendu aux VRF
# ------------------------------------------------------------------------------------------

def test_the_management_vrf_of_srlinux_is_excluded_like_mgmt0():
    r5 = ds.load_lab("mixed")["r5"]
    assert {i.vrf for i in r5.interfaces if i.name == "mgmt0"} == {"mgmt"}
    assert any(r.vrf == "mgmt" for r in r5.routes)

    only_names = management.filtered(r5, {"eth0", "mgmt0"})
    assert all(i.name != "mgmt0" for i in only_names.interfaces)
    # Sans la VRF déclarée, ses routes restent : la route par défaut DHCP de mgmt n'est pas un sous-réseau
    # de mgmt0.
    assert any(r.vrf == "mgmt" and r.prefix == "0.0.0.0/0" for r in only_names.routes)

    both = management.filtered(r5, {"eth0", "mgmt0"}, {"mgmt"})
    assert all(i.vrf != "mgmt" for i in both.interfaces)
    assert all(r.vrf != "mgmt" for r in both.routes)
    assert {r.vrf for r in both.routes} == {DEFAULT_VRF}


def test_an_interface_of_a_management_vrf_is_excluded_even_if_its_name_is_not_declared():
    r5 = ds.load_lab("mixed")["r5"]
    # Modification d'un relevé réel : une interface de plus dans l'instance mgmt, sous un nom non déclaré.
    extra = copy.deepcopy(next(i for i in r5.interfaces if i.name == "mgmt0"))
    extra.name = "mgmt9"
    r5.interfaces.append(extra)
    assert any(i.name == "mgmt9" for i in management.filtered(r5, {"mgmt0"}).interfaces)
    assert not any(i.name == "mgmt9" for i in management.filtered(r5, {"mgmt0"}, {"mgmt"}).interfaces)


def test_a_management_subnet_is_only_excluded_in_the_vrf_of_the_management_interface():
    r5 = ds.load_lab("mixed")["r5"]
    twin = copy.deepcopy(r5.routes[0])
    # Même préfixe que le sous-réseau de mgmt0, dans une autre VRF.
    twin.prefix, twin.vrf = "172.20.21.0/24", "autre"
    r5.routes.append(twin)
    kept = management.filtered(r5, {"mgmt0"})
    assert any(r.vrf == "autre" and r.prefix == "172.20.21.0/24" for r in kept.routes)


def test_the_inventory_declares_management_vrfs():
    inv = inventory.load(path=REPO / "automation" / "inventory-multivendor.yml")
    assert inv.management_vrfs == ["mgmt"] and "mgmt0" in inv.management_interfaces
    assert inventory.load(path=REPO / "automation" / "inventory.yml").management_vrfs == []


def test_management_vrfs_key_is_read_from_the_inventory_file(tmp_path):
    f = tmp_path / "inv.yml"
    f.write_text(yaml.safe_dump({"routers": {"r1": {"host": "h", "username": "u", "password": "p"}},
                                 "management_interfaces": ["eth0"], "management_vrfs": ["MGMT", "oob"]}))
    assert inventory.load(path=f).management_vrfs == ["MGMT", "oob"]


@pytest.mark.parametrize(("lab", "mgmt", "mgmt_vrfs"), [
    ("frr", {"eth0"}, set()),
    ("mixed", {"eth0", "mgmt0"}, {"mgmt"}),
    ("ceos", {"eth0", "Management0"}, set()),
])
def test_two_reads_of_the_same_lab_give_an_empty_diff_after_the_widening(lab, mgmt, mgmt_vrfs):
    before, after = ds.load_lab(lab), ds.load_lab(lab)
    assert diff.compare(before, after, mgmt, mgmt_vrfs) == []


def test_assertions_ignore_the_management_vrf_too():
    states = ds.load_lab("mixed")
    a = Assertion("t", "t", "r5", "route_present", {"prefix": "172.20.21.0/24", "vrf": "mgmt"})
    assert assertions.evaluate([a], states)[0].status == Status.OK            # sans filtre : la route existe
    filtered = assertions.evaluate([a], states, {"eth0", "mgmt0"}, {"mgmt"})[0]
    assert filtered.status == Status.ECHEC                                      # avec : exclue comme mgmt0
