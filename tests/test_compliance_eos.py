"""Règles de conformité propres à Arista EOS (Phase F, `drivers: [eos]`) sur des configurations
RÉELLES de cEOS 4.34.8M (tests/fixtures/ceos/). Les variantes dégradées sont des modifications
textuelles minimales de la vraie running-config, pas des configurations inventées de toutes pièces.
"""
import re
from dataclasses import replace
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.drivers.eos import EosDriver
from netcheck.model import DeviceState

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "ceos"
MGMT = {"eth0", "Management0"}
SECURITY = compliance.load_rules(ROOT / "netcheck" / "rules" / "security.yml")
DEFAULT = compliance.load_rules(ROOT / "netcheck" / "rules" / "default.yml")
EOS_RULE_IDS = {
    "eos-ospf-authentification-message-digest", "eos-ebgp-authentification-tcp-md5",
    "eos-ebgp-gtsm-ttl-maximum-hops", "eos-ebgp-maximum-routes", "eos-api-gestion-exposee",
}


def real_config(scenario: str = "r4") -> str:
    return (FIXTURES / scenario / "running_config.txt").read_text(encoding="utf-8")


def device(running_config: str, driver: str = "eos") -> DeviceState:
    return DeviceState(name="r4", host="172.20.22.14", timestamp="t", reachable=True,
                       running_config=running_config, driver=driver)


def violations_of(rule_id: str, config: str) -> list[str]:
    rules = [r for r in SECURITY if r.id == rule_id]
    found, _ = compliance.evaluate(rules, {"r4": device(config)}, management_interfaces=MGMT)
    return [v.detail for v in found]


def without(config: str, pattern: str) -> str:
    """La vraie config, privée des lignes qui correspondent à `pattern` (au moins une)."""
    kept = [line for line in config.splitlines() if not re.search(pattern, line)]
    assert len(kept) < len(config.splitlines()), f"motif sans effet : {pattern}"
    return "\n".join(kept) + "\n"


# ------------------------------------------------------------------------------------------
# Configuration nominale : tout est conforme
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", sorted(EOS_RULE_IDS))
def test_nominal_real_config_is_compliant(rule_id):
    assert violations_of(rule_id, real_config()) == []


def test_all_eos_rules_exist_with_the_eos_driver_and_a_category():
    rules = {r.id: r for r in SECURITY}
    assert EOS_RULE_IDS <= set(rules)
    for rule_id in EOS_RULE_IDS:
        assert rules[rule_id].drivers == ["eos"], rule_id
        assert rules[rule_id].category in {"ospf", "bgp", "acces"}
    assert len(EOS_RULE_IDS) >= 2 and "eos-api-gestion-exposee" in EOS_RULE_IDS


def test_frr_and_srlinux_rules_are_not_applicable_on_eos_and_never_a_false_violation():
    everything = DEFAULT + SECURITY
    violations, not_applicable = compliance.evaluate(
        everything, {"r4": device(real_config())}, management_interfaces=MGMT)
    assert violations == [], [(v.rule.id, v.detail) for v in violations]
    skipped = {n.rule.id for n in not_applicable}
    for rule in everything:
        if rule.drivers and "eos" not in rule.drivers:
            assert rule.id in skipped, f"{rule.id} devrait être « non applicable » sur EOS"
    assert not (skipped & EOS_RULE_IDS), "les règles EOS s'appliquent à un routeur EOS"


def test_eos_rules_are_not_applicable_on_frr_and_srlinux_devices():
    for driver in ("frr", "srlinux"):
        violations, not_applicable = compliance.evaluate(
            SECURITY, {"r4": device(real_config(), driver=driver)}, management_interfaces=MGMT)
        assert not [v for v in violations if v.rule.id in EOS_RULE_IDS]
        assert EOS_RULE_IDS <= {n.rule.id for n in not_applicable}


def test_universal_description_rule_works_on_eos_data_with_management0_filtered():
    raw = {c: (FIXTURES / "r4" / f).read_text(encoding="utf-8") for c, f in {
        "show interface json": "interface.json", "show ip route json": "route.json",
        "show ip ospf neighbor json": "ospf_neighbor.json",
        "show bgp ipv4 unicast summary json": "bgp_summary.json",
        "show bgp ipv4 unicast json": "bgp_prefixes.json",
        "show running-config": "running_config.txt"}.items()}
    state = EosDriver().parse(raw, "r4", "172.20.22.14")
    state.driver = "eos"
    rule = [r for r in DEFAULT if r.id == "interface-avec-description"]
    assert compliance.evaluate(rule, {"r4": state}, management_interfaces=MGMT)[0] == []
    # Sans le filtre de management, Management0 (sans description) serait signalée : le filtre
    # fait bien son travail pour EOS comme pour eth0 côté FRR.
    flagged = compliance.evaluate(rule, {"r4": state}, management_interfaces=set())[0]
    assert [v.detail for v in flagged if "Management0" in v.detail]
    # Loopback0 (hardware: loopback) n'est jamais exigée, grâce à is_loopback.
    assert not [v for v in flagged if "Loopback0" in v.detail]


# ------------------------------------------------------------------------------------------
# OSPF
# ------------------------------------------------------------------------------------------

def test_ospf_without_authentication_mode_is_a_violation():
    config = without(real_config(), r"ip ospf authentication message-digest")
    found = violations_of("eos-ospf-authentification-message-digest", config)
    assert found == ["interface Ethernet2 : adjacence OSPF active sans authentification message-digest"]


def test_ospf_mode_without_key_is_a_violation():
    config = without(real_config(), r"ip ospf message-digest-key")
    found = violations_of("eos-ospf-authentification-message-digest", config)
    assert found == ["interface Ethernet2 : message-digest activé mais aucune clé md5 configurée"]


def test_passive_interfaces_need_no_authentication():
    # Ethernet1 et Loopback0 sont OSPF mais passives : jamais de violation (comme sur FRR).
    config = real_config()
    assert "passive-interface Ethernet1" in config and "passive-interface Loopback0" in config
    assert violations_of("eos-ospf-authentification-message-digest", config) == []


def test_an_interface_losing_its_passive_status_must_then_be_authenticated():
    config = without(real_config(), r"passive-interface Ethernet1")
    found = violations_of("eos-ospf-authentification-message-digest", config)
    assert found == ["interface Ethernet1 : adjacence OSPF active sans authentification message-digest"]


def test_passive_interface_default_with_exception():
    config = real_config()
    config = config.replace("   passive-interface Ethernet1\n   passive-interface Loopback0\n",
                            "   passive-interface default\n   no passive-interface Ethernet2\n")
    assert "passive-interface default" in config
    assert violations_of("eos-ospf-authentification-message-digest", config) == []
    unauthenticated = without(config, r"ip ospf authentication message-digest")
    assert len(violations_of("eos-ospf-authentification-message-digest", unauthenticated)) == 1


def test_no_ospf_at_all_means_nothing_to_check():
    assert violations_of("eos-ospf-authentification-message-digest", "hostname r4\n!\nip routing\n") == []


# ------------------------------------------------------------------------------------------
# BGP
# ------------------------------------------------------------------------------------------

def test_bgp_without_password_is_a_violation():
    config = without(real_config(), r"neighbor 172\.16\.34\.1 password")
    assert violations_of("eos-ebgp-authentification-tcp-md5", config) == [
        "voisin eBGP 172.16.34.1 sans authentification TCP-MD5 (mot de passe)"]


def test_bgp_without_ttl_maximum_hops_is_a_violation():
    config = without(real_config(), r"ttl maximum-hops")
    assert violations_of("eos-ebgp-gtsm-ttl-maximum-hops", config) == [
        "voisin eBGP 172.16.34.1 sans GTSM (ttl maximum-hops)"]


def test_bgp_without_maximum_routes_is_a_violation():
    config = without(real_config(), r"maximum-routes")
    assert violations_of("eos-ebgp-maximum-routes", config) == [
        "voisin eBGP 172.16.34.1 sans limite maximum-routes"]


def test_maximum_routes_zero_means_unlimited_and_is_not_a_limit():
    config = real_config().replace("maximum-routes 10", "maximum-routes 0")
    found = violations_of("eos-ebgp-maximum-routes", config)
    assert len(found) == 1 and "illimité" in found[0]


def test_maximum_routes_with_options_is_still_a_limit():
    config = real_config().replace(
        "maximum-routes 10", "maximum-routes 10 warning-limit 80 percent")
    assert violations_of("eos-ebgp-maximum-routes", config) == []


def test_ibgp_neighbors_are_out_of_scope():
    config = real_config().replace(
        "neighbor 172.16.34.1 remote-as 65001", "neighbor 172.16.34.1 remote-as 65002")
    for rule_id in ("eos-ebgp-authentification-tcp-md5", "eos-ebgp-gtsm-ttl-maximum-hops",
                    "eos-ebgp-maximum-routes"):
        assert violations_of(rule_id, without(config, r"password|ttl maximum-hops|maximum-routes")) == []


def test_no_bgp_at_all_means_nothing_to_check():
    for rule_id in ("eos-ebgp-authentification-tcp-md5", "eos-ebgp-gtsm-ttl-maximum-hops",
                    "eos-ebgp-maximum-routes"):
        assert violations_of(rule_id, "hostname r4\n") == []


def test_the_maximum_routes_rule_documents_the_difference_with_frr_maximum_prefix():
    rule = next(r for r in SECURITY if r.id == "eos-ebgp-maximum-routes")
    for fragment in ("n'est PAS strictement équivalent", "maximum-prefix", "avant la politique d'entrée",
                     "ACCEPTÉS après filtre", "maximum-prefix N force", "Idle(MaxPath)",
                     "clear ip bgp <ip>"):
        assert fragment in rule.description, fragment


# ------------------------------------------------------------------------------------------
# API de gestion exposée (configuration réelle capturée avec les trois API actives)
# ------------------------------------------------------------------------------------------

def test_exposed_management_apis_are_all_reported_on_the_real_config():
    config = real_config("degraded_api_exposed")
    found = violations_of("eos-api-gestion-exposee", config)
    assert sorted(found) == sorted([
        "API de gestion eAPI (management api http-commands) active (no shutdown)",
        "API de gestion gNMI (management api gnmi) active (transport configuré)",
        "API de gestion NETCONF (management api netconf) active (transport configuré)",
    ])


def test_each_api_is_reported_independently():
    base = real_config()
    only_gnmi = base.replace("interface Ethernet1\n", "management api gnmi\n   transport grpc default\n!\n"
                             "interface Ethernet1\n", 1)
    assert violations_of("eos-api-gestion-exposee", only_gnmi) == [
        "API de gestion gNMI (management api gnmi) active (transport configuré)"]
    only_eapi = base.replace("interface Ethernet1\n", "management api http-commands\n   no shutdown\n!\n"
                             "interface Ethernet1\n", 1)
    assert violations_of("eos-api-gestion-exposee", only_eapi) == [
        "API de gestion eAPI (management api http-commands) active (no shutdown)"]


def test_an_eapi_section_that_is_not_enabled_is_not_reported():
    config = real_config().replace("interface Ethernet1\n", "management api http-commands\n   shutdown\n!\n"
                                   "interface Ethernet1\n", 1)
    assert violations_of("eos-api-gestion-exposee", config) == []


def test_the_hardened_lab_config_exposes_no_api():
    assert "management api" not in real_config()
    startup = (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
    code_lines = [line for line in startup.splitlines() if not line.lstrip().startswith("!")]
    assert not [line for line in code_lines if "management api" in line]


def test_a_device_dataclass_copy_keeps_the_eos_driver():
    assert replace(device("x")).driver == "eos"
