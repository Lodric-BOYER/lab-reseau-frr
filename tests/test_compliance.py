"""Tests du moteur de conformité (§5.4 et §6) :
  - chargement sûr des règles (yaml.safe_load, jamais yaml.load) et validation du schéma ;
  - un cas conforme et un cas non conforme par type de règle implémenté (5 des 6 kind ;
    interface_description_required est un exercice, voir test_compliance_interface_
    description_required.py -- ces tests-là échouent volontairement pour l'instant).
"""
from pathlib import Path

import pytest
import yaml

from netcheck import compliance
from netcheck.compliance import Rule, load_rules, verdict
from netcheck.model import DeviceState, Interface

FIXTURES = Path(__file__).resolve().parent / "fixtures"
R3_CONFIG = (FIXTURES / "r3" / "running_config.txt").read_text(encoding="utf-8")


def device(running_config: str = R3_CONFIG, interfaces=None, name="r3") -> DeviceState:
    return DeviceState(name=name, host="172.20.20.13", timestamp="2026-01-01T00:00:00+00:00",
                        reachable=True, running_config=running_config, interfaces=interfaces or [])


def rule(kind: str, **params) -> Rule:
    return Rule(id="test", description="test", severity="haute", applies_to="all", kind=kind, params=params)


# ------------------------------------------------------------------------------------------
# Chargement sûr (C1 étendu aux règles : aucun code arbitraire au chargement) et schéma
# ------------------------------------------------------------------------------------------

def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "rules.yml"
    p.write_text(text, encoding="utf-8")
    return p


def test_malicious_python_tag_is_refused(tmp_path):
    # yaml.load (non sûr) exécuterait ce tag ; yaml.safe_load doit le refuser.
    malicious = tmp_path / "rules.yml"
    malicious.write_text(
        "rules:\n"
        "  - id: evil\n"
        "    description: x\n"
        "    severity: haute\n"
        "    applies_to: all\n"
        "    kind: !!python/object/apply:os.system [\"echo pwned\"]\n",
        encoding="utf-8",
    )
    with pytest.raises((ValueError, yaml.YAMLError)):
        load_rules(malicious)


def test_default_rules_file_loads_and_is_non_empty():
    default_path = Path(__file__).resolve().parent.parent / "netcheck" / "rules" / "default.yml"
    rules = load_rules(default_path)
    assert len(rules) >= 5
    assert {r.kind for r in rules} == {
        "line_present", "line_absent", "bgp_neighbor_inbound_policy",
        "bgp_neighbor_outbound_policy", "ospf_passive_on_interfaces",
    }


def test_missing_required_field_is_rejected(tmp_path):
    path = _write(
        tmp_path, "rules:\n  - id: x\n    description: y\n    severity: haute\n    kind: line_present\n",
    )
    with pytest.raises(ValueError, match="applies_to"):
        load_rules(path)


def test_unknown_severity_is_rejected(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: catastrophique\n"
        "    applies_to: all\n    kind: line_present\n    pattern: x\n")
    with pytest.raises(ValueError, match="severity"):
        load_rules(path)


def test_unknown_kind_is_rejected(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    kind: reboot_router\n")
    with pytest.raises(ValueError, match="kind"):
        load_rules(path)


def test_duplicate_id_is_rejected(tmp_path):
    text = (
        "rules:\n"
        "  - id: dup\n    description: a\n    severity: haute\n    applies_to: all\n"
        "    kind: line_present\n    pattern: a\n"
        "  - id: dup\n    description: b\n    severity: basse\n    applies_to: all\n"
        "    kind: line_present\n    pattern: b\n"
    )
    with pytest.raises(ValueError, match="dup"):
        load_rules(_write(tmp_path, text))


def test_error_message_names_the_offending_rule(tmp_path):
    path = _write(tmp_path, "rules:\n  - id: ma-regle-fautive\n    description: y\n    severity: haute\n")
    with pytest.raises(ValueError, match="ma-regle-fautive"):
        load_rules(path)


# ------------------------------------------------------------------------------------------
# line_present / line_absent
# ------------------------------------------------------------------------------------------

def test_line_present_conforme():
    r = rule("line_present", pattern="^log syslog informational$")
    assert compliance._check_line_present(r, device()) == []


def test_line_present_violation():
    r = rule("line_present", pattern="^ip prefix-list PL-INEXISTANTE")
    violations = compliance._check_line_present(r, device())
    assert len(violations) == 1 and violations[0].device == "r3"


def test_line_absent_conforme():
    r = rule("line_absent", pattern=r"^\s*(enable )?password\s")
    assert compliance._check_line_absent(r, device()) == []


def test_line_absent_violation():
    config_with_password = R3_CONFIG + "password secret123\n"
    r = rule("line_absent", pattern=r"^\s*(enable )?password\s")
    violations = compliance._check_line_absent(r, device(running_config=config_with_password))
    assert len(violations) == 1
    assert "password secret123" in violations[0].detail


# ------------------------------------------------------------------------------------------
# bgp_neighbor_inbound_policy / outbound_policy (r3 est réellement filtré dans les 2 sens)
# ------------------------------------------------------------------------------------------

def test_bgp_inbound_policy_conforme():
    r = rule("bgp_neighbor_inbound_policy")
    assert compliance._check_bgp_neighbor_inbound_policy(r, device()) == []


def test_bgp_outbound_policy_conforme():
    r = rule("bgp_neighbor_outbound_policy")
    assert compliance._check_bgp_neighbor_outbound_policy(r, device()) == []


def test_bgp_inbound_policy_violation_when_route_map_removed():
    broken = R3_CONFIG.replace("  neighbor 172.16.34.2 route-map RM-EBGP-IN in\n", "")
    r = rule("bgp_neighbor_inbound_policy")
    violations = compliance._check_bgp_neighbor_inbound_policy(r, device(running_config=broken))
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_outbound_policy_violation_when_route_map_removed():
    broken = R3_CONFIG.replace("  neighbor 172.16.34.2 route-map RM-EBGP-OUT out\n", "")
    r = rule("bgp_neighbor_outbound_policy")
    violations = compliance._check_bgp_neighbor_outbound_policy(r, device(running_config=broken))
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_policy_router_without_bgp_is_not_a_violation():
    # r1 n'a pas de "router bgp" : la règle ne s'applique tout simplement pas.
    r1_config = (FIXTURES / "r1" / "running_config.txt").read_text(encoding="utf-8")
    r = rule("bgp_neighbor_inbound_policy")
    assert compliance._check_bgp_neighbor_inbound_policy(r, device(running_config=r1_config, name="r1")) == []


# ------------------------------------------------------------------------------------------
# ospf_passive_on_interfaces
# ------------------------------------------------------------------------------------------

def test_ospf_passive_conforme():
    r1_config = (FIXTURES / "r1" / "running_config.txt").read_text(encoding="utf-8")
    r1_interfaces = [
        Interface("eth3", "LAN-pc1", True, True, ["192.168.1.1/24"]),
        Interface("eth1", "vers-r2", True, True, ["10.1.12.1/30"]),
    ]
    r = rule("ospf_passive_on_interfaces", pattern="LAN")
    assert compliance._check_ospf_passive_on_interfaces(
        r, device(running_config=r1_config, interfaces=r1_interfaces, name="r1")) == []


def test_ospf_passive_violation_when_removed():
    r1_config = (FIXTURES / "r1" / "running_config.txt").read_text(encoding="utf-8")
    # Retire le "ip ospf passive" du bloc LAN-pc1 (eth3) précisément.
    broken = r1_config.replace(
        "interface eth3\n description LAN-pc1\n ip address 192.168.1.1/24\n ip ospf area 0\n"
        " ip ospf passive\nexit",
        "interface eth3\n description LAN-pc1\n ip address 192.168.1.1/24\n ip ospf area 0\nexit",
    )
    assert broken != r1_config  # la substitution a bien eu lieu, sinon le test ne teste rien
    r1_interfaces = [Interface("eth3", "LAN-pc1", True, True, ["192.168.1.1/24"])]
    r = rule("ospf_passive_on_interfaces", pattern="LAN")
    violations = compliance._check_ospf_passive_on_interfaces(
        r, device(running_config=broken, interfaces=r1_interfaces, name="r1"))
    assert len(violations) == 1 and "eth3" in violations[0].detail


def test_ospf_passive_ignores_interfaces_not_matching_pattern():
    r = rule("ospf_passive_on_interfaces", pattern="LAN")
    interfaces = [Interface("eth1", "vers-r2", True, True, ["10.1.12.1/30"])]  # pas passive, mais pas "LAN"
    assert compliance._check_ospf_passive_on_interfaces(r, device(interfaces=interfaces)) == []


# ------------------------------------------------------------------------------------------
# Verdict / code retour (§5.4)
# ------------------------------------------------------------------------------------------

def _violation(severity: str) -> compliance.Violation:
    return compliance.Violation(
        rule=Rule(id="x", description="x", severity=severity, applies_to="all", kind="line_present"),
        device="r1", detail="x",
    )


@pytest.mark.parametrize("severities,expected", [
    ([], (True, 0)),
    (["basse"], (False, 1)),
    (["moyenne", "basse"], (False, 1)),
    (["haute"], (False, 2)),
    (["critique"], (False, 2)),
    (["basse", "critique"], (False, 2)),
])
def test_verdict(severities, expected):
    violations = [_violation(s) for s in severities]
    assert verdict(violations) == expected
