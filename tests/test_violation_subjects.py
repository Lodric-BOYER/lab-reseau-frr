"""Phase B3 : chaque règle dit sur QUEL objet porte sa violation (`Violation.subject`).

Les dérogations visent des paires (équipement, objet) en correspondance exacte : sans objet exact et
stable, une violation ne peut pas être couverte. Un test par kind de règle, sur des configurations réelles
(tests/fixtures/ live_dualstack/) mutées pour provoquer la violation. Le dernier test échoue si un kind est
ajouté sans test.
"""
import re

import dualstack_support as ds
import pytest
from test_ipv6_rules import cfg, once

from netcheck import compliance, management
from netcheck.model import DeviceState
from netcheck.ruletypes import Rule


def rule(kind: str, severity: str = "haute", **params) -> Rule:
    return Rule(id=f"t-{kind}", description="t", severity=severity, applies_to="all", kind=kind,
                params=params)


def state(driver: str, text: str, name: str = "r3") -> DeviceState:
    return DeviceState(name=name, host="-", timestamp="", reachable=True, driver=driver, running_config=text)


def frr(text: str, name: str = "r3") -> DeviceState:
    return state("frr", text, name)


def eos(text: str, name: str = "r4") -> DeviceState:
    return state("eos", text, name)


def srl(text: str, name: str = "r5") -> DeviceState:
    return state("srlinux", text, name)


def drop(text: str, fragment: str) -> str:
    """Retire l'UNIQUE ligne qui contient ce fragment."""
    lines = text.split("\n")
    hits = [i for i, line in enumerate(lines) if fragment in line]
    assert len(hits) == 1, (fragment, len(hits))
    del lines[hits[0]]
    return "\n".join(lines)


def subjects_of(kind: str, st: DeviceState, **params) -> list[str | None]:
    return [v.subject for v in compliance.check_one(rule(kind, **params), st)]


COVERED: set[str] = set()


def subject_test(kind: str):
    """Enregistre, à l'import, le kind que ce test couvre : le garde-fou final n'en dépend ni de l'ordre ni
    de la sélection des tests."""
    COVERED.add(kind)
    return lambda fn: fn


# ------------------------------------------------------------------------------------------
# FRR
# ------------------------------------------------------------------------------------------

@subject_test("bgp_neighbor_inbound_policy")
def test_subject_bgp_neighbor_inbound_policy():
    text = drop(cfg("frr_r3.txt"), "neighbor 172.16.34.2 route-map RM-EBGP-IN in")
    assert subjects_of("bgp_neighbor_inbound_policy", frr(text)) == ["172.16.34.2"]


@subject_test("bgp_neighbor_outbound_policy")
def test_subject_bgp_neighbor_outbound_policy():
    text = drop(cfg("frr_r3.txt"), "neighbor 2001:db8:34::3 route-map RM6-EBGP-OUT out")
    assert subjects_of("bgp_neighbor_outbound_policy", frr(text)) == ["2001:db8:34::3"]


@subject_test("ospf_passive_on_interfaces")
def test_subject_ospf_passive_on_interfaces():
    r1 = ds.load_lab("frr")["r1"]
    eth1 = next(i for i in r1.interfaces if i.name == "eth1")
    assert eth1.description
    r1.running_config = cfg("frr_r1.txt")
    assert subjects_of("ospf_passive_on_interfaces", r1, pattern=re.escape(eth1.description)) == ["eth1"]


@subject_test("ospf_authentication_required")
def test_subject_ospf_authentication_required():
    lines = cfg("frr_r1.txt").split("\n")
    idx = next(i for i, line in enumerate(lines) if "ip ospf message-digest-key 1 md5 lab-ospf-r1r2" in line)
    assert lines[idx - 1].strip() == "ip ospf authentication message-digest"
    del lines[idx - 1:idx + 1]
    assert subjects_of("ospf_authentication_required", frr("\n".join(lines), "r1")) == ["eth1"]


@subject_test("ospf6_authentication_required")
def test_subject_ospf6_authentication_required():
    assert subjects_of("ospf6_authentication_required", frr(cfg("frr_r4.txt"), "r4")) == ["eth2"]


@subject_test("bgp_neighbor_password_required")
def test_subject_bgp_neighbor_password_required():
    text = drop(cfg("frr_r3.txt"), "neighbor 2001:db8:34::3 password")
    assert subjects_of("bgp_neighbor_password_required", frr(text)) == ["2001:db8:34::3"]


@subject_test("bgp_neighbor_maximum_prefix_required")
def test_subject_bgp_neighbor_maximum_prefix_required():
    text = drop(cfg("frr_r3.txt"), "neighbor 172.16.34.2 maximum-prefix")
    assert subjects_of("bgp_neighbor_maximum_prefix_required", frr(text)) == ["172.16.34.2"]


@subject_test("bgp_neighbor_ttl_security_required")
def test_subject_bgp_neighbor_ttl_security_required():
    text = drop(cfg("frr_r3.txt"), "neighbor 172.16.34.2 ttl-security hops 1")
    assert subjects_of("bgp_neighbor_ttl_security_required", frr(text)) == ["172.16.34.2"]


@subject_test("bgp_neighbor_no_default_route_policy")
def test_subject_bgp_neighbor_no_default_route_policy():
    text = once(cfg("frr_r3.txt"), "ipv6 prefix-list PL6-EBGP-IN seq 20 permit 2001:db8:a2::/64\n",
                "ipv6 prefix-list PL6-EBGP-IN seq 20 permit 2001:db8:a2::/64\n"
                "ipv6 prefix-list PL6-EBGP-IN seq 30 permit ::/0\n")
    assert subjects_of("bgp_neighbor_no_default_route_policy", frr(text)) == ["2001:db8:34::3"]


@subject_test("bgp_neighbor_no_own_prefixes_policy")
def test_subject_bgp_neighbor_no_own_prefixes_policy():
    text = once(cfg("frr_r3.txt"), "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n",
                "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n"
                "ip prefix-list PL-EBGP-IN seq 30 permit 10.1.0.0/16\n")
    assert subjects_of("bgp_neighbor_no_own_prefixes_policy", frr(text)) == ["172.16.34.2"]


# ------------------------------------------------------------------------------------------
# EOS
# ------------------------------------------------------------------------------------------

@subject_test("eos_ospf_authentication_required")
def test_subject_eos_ospf_authentication_required_both_forms():
    base = cfg("eos_r4.txt")
    no_mode = drop(drop(base, "ip ospf authentication message-digest"), "ip ospf message-digest-key 1 md5")
    assert subjects_of("eos_ospf_authentication_required", eos(no_mode, "r4")) == ["Ethernet2"]
    no_key = drop(base, "ip ospf message-digest-key 1 md5")      # mode sans clé : seconde forme de violation
    found = compliance.check_one(rule("eos_ospf_authentication_required"), eos(no_key, "r4"))
    assert [(v.subject, "aucune clé md5" in v.detail) for v in found] == [("Ethernet2", True)]


@subject_test("eos_ospf6_authentication_required")
def test_subject_eos_ospf6_authentication_required():
    assert subjects_of("eos_ospf6_authentication_required", eos(cfg("eos_r4.txt"), "r4")) == ["Ethernet2"]


@subject_test("eos_bgp_neighbor_password_required")
def test_subject_eos_bgp_neighbor_password_required():
    text = drop(cfg("eos_r4.txt"), "neighbor 2001:db8:34::2 password")
    assert subjects_of("eos_bgp_neighbor_password_required", eos(text, "r4")) == ["2001:db8:34::2"]


@subject_test("eos_bgp_neighbor_ttl_security_required")
def test_subject_eos_bgp_neighbor_ttl_security_required():
    text = drop(cfg("eos_r4.txt"), "neighbor 172.16.34.1 ttl maximum-hops")
    assert subjects_of("eos_bgp_neighbor_ttl_security_required", eos(text, "r4")) == ["172.16.34.1"]


@subject_test("eos_bgp_neighbor_maximum_routes_required")
def test_subject_eos_bgp_neighbor_maximum_routes_required_missing_and_zero():
    missing = drop(cfg("eos_r4.txt"), "neighbor 172.16.34.1 maximum-routes")
    assert subjects_of("eos_bgp_neighbor_maximum_routes_required", eos(missing, "r4")) == ["172.16.34.1"]
    zero = re.sub(r"(neighbor 172\.16\.34\.1 maximum-routes) \d+", r"\1 0", cfg("eos_r4.txt"))
    found = compliance.check_one(rule("eos_bgp_neighbor_maximum_routes_required"), eos(zero, "r4"))
    assert [(v.subject, "illimité" in v.detail) for v in found] == [("172.16.34.1", True)]


@pytest.mark.parametrize(("block", "subject"), [
    ("management api http-commands\n   no shutdown\n", "http-commands"),
    ("management api gnmi\n   transport grpc default\n", "gnmi"),
    ("management api netconf\n   transport ssh default\n", "netconf"),
])
@subject_test("eos_management_api_disabled")
def test_subject_eos_management_api_disabled(block, subject):
    text = cfg("eos_r4.txt").rstrip("\n") + "\n" + block
    assert subjects_of("eos_management_api_disabled", eos(text, "r4")) == [subject]


# ------------------------------------------------------------------------------------------
# SR Linux
# ------------------------------------------------------------------------------------------

@subject_test("srlinux_interface_mtu_margin")
def test_subject_srlinux_interface_mtu_margin():
    text = ("set / interface ethernet-1/9 mtu 1500\n"
            "set / interface ethernet-1/9 subinterface 0 ip-mtu 1500\n")
    assert subjects_of("srlinux_interface_mtu_margin", srl(text, "r5"), margin=14) == ["ethernet-1/9"]


@subject_test("srlinux_ospf_interface_type_point_to_point")
def test_subject_srlinux_ospf_interface_type_point_to_point():
    head, marker, tail = cfg("srl_r5.txt").partition("    instance v3 {")
    text = once(head, "                interface-type point-to-point\n", "") + marker + tail
    assert subjects_of("srlinux_ospf_interface_type_point_to_point", srl(text, "r5")) == ["ethernet-1/1.0"]


@pytest.mark.parametrize(("mutation", "expected"), [
    ("none", "aucune keychain référencée"), ("unknown", "introuvable sous /system authentication"),
    ("wrong", "qui n'est pas de type ospf")])
@subject_test("srlinux_ospf_authentication_required")
def test_subject_srlinux_ospf_authentication_required_three_forms(mutation, expected):
    text = cfg("srl_r5.txt")
    ref = "                authentication {\n                    keychain kc-ospf-r4r5\n                }\n"
    if mutation == "none":
        text = once(text, ref, "")
    elif mutation == "unknown":
        text = once(text, ref, ref.replace("kc-ospf-r4r5", "kc-absente"))
    else:
        text = once(text, "        type ospf\n", "        type isis\n")
    found = compliance.check_one(rule("srlinux_ospf_authentication_required"), srl(text, "r5"))
    assert [(v.subject, expected in v.detail) for v in found] == [("ethernet-1/1.0", True)]


@subject_test("srlinux_ospf6_authentication_required")
def test_subject_srlinux_ospf6_authentication_required():
    assert subjects_of("srlinux_ospf6_authentication_required", srl(cfg("srl_r5.txt"), "r5")) \
        == ["ethernet-1/1.0"]


@subject_test("srlinux_login_banner_present")
def test_subject_srlinux_login_banner_present():
    text = drop(cfg("srl_r5.txt"), "login-banner")
    assert subjects_of("srlinux_login_banner_present", srl(text, "r5")) == ["login-banner"]


# ------------------------------------------------------------------------------------------
# Kinds neutres du moteur
# ------------------------------------------------------------------------------------------

@subject_test("line_present")
def test_subject_line_present_is_the_pattern():
    pattern = "^service password-encryption$"
    assert "service password-encryption" not in cfg("frr_r3.txt")
    assert subjects_of("line_present", frr(cfg("frr_r3.txt")), pattern=pattern) == [pattern]


@subject_test("line_absent")
def test_subject_line_absent_is_the_masked_line_never_the_secret():
    text = cfg("frr_r3.txt") + "enable password MonSecretDeLab\n"
    found = compliance.check_one(rule("line_absent", pattern=r"^\s*(enable )?password\s"), frr(text))
    assert len(found) == 1 and found[0].subject is not None
    assert "MonSecretDeLab" not in found[0].subject and "password" in found[0].subject


@subject_test("interface_description_required")
def test_subject_interface_description_required_is_the_interface_name():
    r2 = management.filtered(ds.load_lab("frr")["r2"], {"eth0"})       # eth0 : management, comme `check`
    assert subjects_of("interface_description_required", r2) == []        # relevé réel : toutes décrites
    # Modification d'un relevé réel : eth1 perd sa description.
    next(i for i in r2.interfaces if i.name == "eth1").description = None
    assert subjects_of("interface_description_required", r2) == ["eth1"]


# ------------------------------------------------------------------------------------------
# Garde-fou : un kind sans test d'objet fait échouer ce fichier
# ------------------------------------------------------------------------------------------

def test_every_known_kind_has_a_subject_test():
    # Un kind ajouté à un driver (ou au moteur) sans test d'objet apparaît ici.
    assert compliance.known_kinds() - COVERED == set()
    assert COVERED - compliance.known_kinds() == set()
