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
        "srlinux_interface_mtu_margin", "srlinux_ospf_interface_type_point_to_point",
    }


def test_default_rules_file_all_text_based_rules_are_scoped_to_frr():
    # Phase D2 : toute règle qui lit le TEXTE de la running-config (donc écrite pour la
    # syntaxe d'UN seul constructeur) doit porter drivers: [frr], sinon un lab multi-
    # constructeurs produirait de fausses non-conformités sur les autres drivers.
    default_path = Path(__file__).resolve().parent.parent / "netcheck" / "rules" / "default.yml"
    rules = load_rules(default_path)
    text_based_kinds = {
        "line_present", "line_absent", "bgp_neighbor_inbound_policy",
        "bgp_neighbor_outbound_policy", "ospf_passive_on_interfaces",
    }
    for r in rules:
        if r.kind in text_based_kinds:
            assert r.drivers == ["frr"], f"{r.id} (kind={r.kind}) devrait porter drivers: [frr]"


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
# Champ "drivers" (Phase D2) : validation du schéma
# ------------------------------------------------------------------------------------------

def test_unknown_driver_in_drivers_field_is_rejected(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    drivers: [cisco_ios]\n    kind: line_present\n    pattern: x\n")
    with pytest.raises(ValueError, match="cisco_ios"):
        load_rules(path)


def test_known_driver_in_drivers_field_is_accepted(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    drivers: [srlinux]\n    kind: line_present\n    pattern: x\n")
    rules = load_rules(path)
    assert rules[0].drivers == ["srlinux"]


def test_drivers_field_absent_means_none_ie_all_drivers(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    kind: line_present\n    pattern: x\n")
    rules = load_rules(path)
    assert rules[0].drivers is None


def test_drivers_field_must_be_a_non_empty_list(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    drivers: []\n    kind: line_present\n    pattern: x\n")
    with pytest.raises(ValueError, match="drivers"):
        load_rules(path)


def test_drivers_field_rejects_a_bare_string(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    drivers: frr\n    kind: line_present\n    pattern: x\n")
    with pytest.raises(ValueError, match="drivers"):
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
# Règles SR Linux (Phase D2) : fixtures réelles (tests/fixtures/r5/), running_config construit
# EXACTEMENT comme le fait SrlinuxDriver.parse() (mêmes marqueurs de section), pour que les
# tests exercent le vrai format produit, pas une supposition sur ce format.
# ------------------------------------------------------------------------------------------

R5_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "r5"
R5_INTERFACE_CONFIG = (R5_FIXTURES / "running_config.txt").read_text(encoding="utf-8")
R5_OSPF_CONFIG = (R5_FIXTURES / "ospf_running_config.txt").read_text(encoding="utf-8")


def srlinux_device(interface_config=None, ospf_config=None, name="r5") -> DeviceState:
    interface_config = R5_INTERFACE_CONFIG if interface_config is None else interface_config
    ospf_config = R5_OSPF_CONFIG if ospf_config is None else ospf_config
    running_config = (
        "# --- interface ---\n" + interface_config + "\n"
        "# --- network-instance default protocols ospf ---\n" + ospf_config
    )
    return DeviceState(name=name, host="172.20.21.15", timestamp="2026-01-01T00:00:00+00:00",
                        reachable=True, running_config=running_config, driver="srlinux")


def test_srlinux_mtu_margin_conforme_sur_le_vrai_lab():
    # ethernet-1/1 : mtu 1514, ip-mtu 1500 -> marge de 14, exactement la marge minimale (Phase
    # C). C'est la config réelle actuellement déployée : doit être conforme.
    r = rule("srlinux_interface_mtu_margin")
    assert compliance._check_srlinux_interface_mtu_margin(r, srlinux_device()) == []


def test_srlinux_mtu_margin_violation_quand_la_marge_est_insuffisante():
    broken = R5_INTERFACE_CONFIG.replace("ip-mtu 1500", "ip-mtu 1505")  # marge de 9 < 14
    r = rule("srlinux_interface_mtu_margin")
    violations = compliance._check_srlinux_interface_mtu_margin(
        r, srlinux_device(interface_config=broken))
    assert len(violations) == 1
    assert "ethernet-1/1" in violations[0].detail and "1505" in violations[0].detail


def test_srlinux_mtu_margin_ignores_interfaces_without_explicit_mtu():
    # ethernet-1/2 n'a pas de "mtu" L2 explicite dans la fixture : rien à vérifier, pas une
    # violation (on ne devine pas la valeur par défaut de la plateforme).
    r = rule("srlinux_interface_mtu_margin")
    violations = compliance._check_srlinux_interface_mtu_margin(r, srlinux_device())
    assert not any("ethernet-1/2" in v.detail for v in violations)


def test_srlinux_ospf_point_to_point_conforme_sur_le_vrai_lab():
    # ethernet-1/1.0 (seule interface OSPF active, non passive) porte bien interface-type
    # point-to-point dans la config réelle actuellement déployée.
    r = rule("srlinux_ospf_interface_type_point_to_point")
    assert compliance._check_srlinux_ospf_interface_type_point_to_point(r, srlinux_device()) == []


def test_srlinux_ospf_point_to_point_violation_quand_absent():
    broken = R5_OSPF_CONFIG.replace(
        "interface ethernet-1/1.0 {\n                interface-type point-to-point\n            }",
        "interface ethernet-1/1.0 {\n            }",
    )
    assert broken != R5_OSPF_CONFIG  # la substitution a bien eu lieu
    r = rule("srlinux_ospf_interface_type_point_to_point")
    violations = compliance._check_srlinux_ospf_interface_type_point_to_point(
        r, srlinux_device(ospf_config=broken))
    assert len(violations) == 1 and "ethernet-1/1.0" in violations[0].detail


def test_srlinux_ospf_point_to_point_ignores_passive_interfaces():
    # ethernet-1/2.0 et lo0.0 sont passives, sans interface-type point-to-point : normal, pas
    # une violation (aucune adjacence ne s'y forme, DR/BDR ne s'applique pas).
    r = rule("srlinux_ospf_interface_type_point_to_point")
    violations = compliance._check_srlinux_ospf_interface_type_point_to_point(r, srlinux_device())
    assert not any("ethernet-1/2.0" in v.detail or "lo0.0" in v.detail for v in violations)


# ------------------------------------------------------------------------------------------
# evaluate() : filtrage par driver (Phase D2) -- "non applicable", jamais "conforme", jamais
# comptée dans verdict()
# ------------------------------------------------------------------------------------------

def test_evaluate_marks_driver_mismatch_as_not_applicable_not_a_violation():
    frr_rule = Rule(id="frr-only", description="d", severity="haute", applies_to="all",
                     drivers=["frr"], kind="line_present", params={"pattern": "^log syslog informational$"})
    devices = {"r5": srlinux_device()}
    violations, not_applicable = compliance.evaluate([frr_rule], devices)
    assert violations == []
    assert len(not_applicable) == 1
    assert not_applicable[0].device == "r5" and not_applicable[0].rule.id == "frr-only"


def test_evaluate_runs_rule_normally_when_driver_matches():
    srl_rule = Rule(id="srl-only", description="d", severity="haute", applies_to="all",
                     drivers=["srlinux"], kind="srlinux_interface_mtu_margin", params={})
    devices = {"r5": srlinux_device()}
    violations, not_applicable = compliance.evaluate([srl_rule], devices)
    assert violations == []  # config reelle conforme
    assert not_applicable == []


def test_evaluate_universal_rule_applies_to_every_driver():
    universal_rule = Rule(id="universal", description="d", severity="basse", applies_to="all",
                           drivers=None, kind="interface_description_required", params={})
    devices = {"r5": srlinux_device()}  # sans interfaces : rien a signaler, mais bien evaluee
    violations, not_applicable = compliance.evaluate([universal_rule], devices)
    assert not_applicable == []  # jamais "non applicable" pour une regle universelle


def test_not_applicable_never_affects_verdict():
    devices = {"r5": srlinux_device()}
    frr_rule = Rule(id="frr-only", description="d", severity="critique", applies_to="all",
                     drivers=["frr"], kind="line_present", params={"pattern": "inexistant"})
    violations, not_applicable = compliance.evaluate([frr_rule], devices)
    assert len(not_applicable) == 1
    assert verdict(violations) == (True, 0)  # CONFORME : seule "violations" compte


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
