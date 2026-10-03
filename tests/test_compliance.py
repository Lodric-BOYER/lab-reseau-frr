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
        "interface_description_required",
        "srlinux_interface_mtu_margin", "srlinux_ospf_interface_type_point_to_point",
    }
    universal = next(r for r in rules if r.kind == "interface_description_required")
    assert universal.drivers is None  # O3 : lit le modèle, jamais du texte -> tous les drivers


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
# Champs "references" et "category" (Phase A, sécurité, C14) : validation du schéma
# ------------------------------------------------------------------------------------------

def test_references_field_absent_means_none(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    kind: line_present\n    pattern: x\n")
    assert load_rules(path)[0].references is None


def test_references_field_accepted_with_title_and_url(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n    applies_to: all\n"
        "    kind: line_present\n    pattern: x\n"
        "    references:\n      - title: RFC 2328\n        url: https://www.rfc-editor.org/rfc/rfc2328.html\n")
    refs = load_rules(path)[0].references
    assert refs == [{"title": "RFC 2328", "url": "https://www.rfc-editor.org/rfc/rfc2328.html"}]


def test_references_field_must_be_a_non_empty_list(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    kind: line_present\n    pattern: x\n    references: []\n")
    with pytest.raises(ValueError, match="references"):
        load_rules(path)


def test_references_entry_must_have_exactly_title_and_url(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n    applies_to: all\n"
        "    kind: line_present\n    pattern: x\n"
        "    references:\n      - title: RFC 2328\n")
    with pytest.raises(ValueError, match="title"):
        load_rules(path)


def test_references_entry_rejects_empty_title_or_url(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n    applies_to: all\n"
        "    kind: line_present\n    pattern: x\n"
        "    references:\n      - title: \"\"\n        url: https://example.org\n")
    with pytest.raises(ValueError, match="vides"):
        load_rules(path)


def test_category_field_absent_means_none(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n"
        "    applies_to: all\n    kind: line_present\n    pattern: x\n")
    assert load_rules(path)[0].category is None


def test_category_field_accepted_as_string(tmp_path):
    path = _write(tmp_path,
        "rules:\n  - id: x\n    description: y\n    severity: haute\n    applies_to: all\n"
        "    kind: line_present\n    pattern: x\n    category: bgp\n")
    assert load_rules(path)[0].category == "bgp"


def test_security_rules_file_loads_and_covers_new_kinds():
    security_path = Path(__file__).resolve().parent.parent / "netcheck" / "rules" / "security.yml"
    rules = load_rules(security_path)
    assert len(rules) >= 9
    kinds = {r.kind for r in rules}
    assert {
        "ospf_authentication_required", "bgp_neighbor_password_required",
        "bgp_neighbor_maximum_prefix_required", "bgp_neighbor_ttl_security_required",
        "bgp_neighbor_no_default_route_policy", "bgp_neighbor_no_own_prefixes_policy",
        "srlinux_ospf_authentication_required",
    } <= kinds
    # Chaque règle qui porte "references" doit avoir title+url non vides (déjà garanti par le
    # chargement, mais reconfirmé ici pour repérer un fichier qui l'aurait contourné).
    for r in rules:
        if r.references:
            for ref in r.references:
                assert ref["title"] and ref["url"]


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
    assert compliance.check_one(r, device()) == []


def test_bgp_outbound_policy_conforme():
    r = rule("bgp_neighbor_outbound_policy")
    assert compliance.check_one(r, device()) == []


def test_bgp_inbound_policy_violation_when_route_map_removed():
    broken = R3_CONFIG.replace("  neighbor 172.16.34.2 route-map RM-EBGP-IN in\n", "")
    r = rule("bgp_neighbor_inbound_policy")
    violations = compliance.check_one(r, device(running_config=broken))
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_outbound_policy_violation_when_route_map_removed():
    broken = R3_CONFIG.replace("  neighbor 172.16.34.2 route-map RM-EBGP-OUT out\n", "")
    r = rule("bgp_neighbor_outbound_policy")
    violations = compliance.check_one(r, device(running_config=broken))
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_policy_router_without_bgp_is_not_a_violation():
    # r1 n'a pas de "router bgp" : la règle ne s'applique tout simplement pas.
    r1_config = (FIXTURES / "r1" / "running_config.txt").read_text(encoding="utf-8")
    r = rule("bgp_neighbor_inbound_policy")
    assert compliance.check_one(r, device(running_config=r1_config, name="r1")) == []


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
    assert compliance.check_one(
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
    violations = compliance.check_one(
        r, device(running_config=broken, interfaces=r1_interfaces, name="r1"))
    assert len(violations) == 1 and "eth3" in violations[0].detail


def test_ospf_passive_ignores_interfaces_not_matching_pattern():
    r = rule("ospf_passive_on_interfaces", pattern="LAN")
    interfaces = [Interface("eth1", "vers-r2", True, True, ["10.1.12.1/30"])]  # pas passive, mais pas "LAN"
    assert compliance.check_one(r, device(interfaces=interfaces)) == []


# ------------------------------------------------------------------------------------------
# ospf_authentication_required (Phase A, sécurité, O1) : vérifié en direct sur r1<->r2 (FRR
# 10.2.1), adjacence reste Full une fois appliqué symétriquement.
# ------------------------------------------------------------------------------------------

R1_CONFIG = (FIXTURES / "r1" / "running_config.txt").read_text(encoding="utf-8")


def test_ospf_authentication_violation_on_unhardened_lab():
    # Configuration réelle actuelle (avant Phase B) : aucune interface OSPF n'est authentifiée.
    r = rule("ospf_authentication_required")
    dev = device(running_config=R1_CONFIG, name="r1")
    violations = compliance.check_one(r, dev)
    assert {v.detail.split()[1] for v in violations} == {"eth1", "eth2"}  # actives, non passives


def test_ospf_authentication_conforme_once_configured():
    hardened = R1_CONFIG.replace(
        " ip ospf network point-to-point\nexit",
        " ip ospf authentication message-digest\n"
        " ip ospf message-digest-key 1 md5 CleDeLabUniquement\n"
        " ip ospf network point-to-point\nexit",
    )
    r = rule("ospf_authentication_required")
    assert compliance.check_one(r, device(running_config=hardened, name="r1")) == []


def test_ospf_authentication_ignores_passive_interfaces():
    # eth3 (LAN) et lo sont passives : pas d'adjacence, rien à authentifier.
    r = rule("ospf_authentication_required")
    dev = device(running_config=R1_CONFIG, name="r1")
    violations = compliance.check_one(r, dev)
    assert not any("eth3" in v.detail or " lo " in v.detail for v in violations)


# ------------------------------------------------------------------------------------------
# bgp_neighbor_password_required / maximum_prefix / ttl_security (Phase A, sécurité, O1) :
# les trois vérifiées en direct sur la session eBGP réelle r3<->r4 (FRR 10.2.1).
# ------------------------------------------------------------------------------------------

def test_bgp_password_violation_on_unhardened_lab():
    r = rule("bgp_neighbor_password_required")
    violations = compliance.check_one(r, device())  # R3_CONFIG
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_password_conforme_once_configured():
    hardened = R3_CONFIG.replace(
        " neighbor 172.16.34.2 description r4-AS65002\n",
        " neighbor 172.16.34.2 description r4-AS65002\n"
        " neighbor 172.16.34.2 password CleDeLabUniquement\n",
    )
    r = rule("bgp_neighbor_password_required")
    assert compliance.check_one(r, device(running_config=hardened)) == []


def test_bgp_password_no_bgp_is_not_a_violation():
    r = rule("bgp_neighbor_password_required")
    dev = device(running_config=R1_CONFIG, name="r1")
    assert compliance.check_one(r, dev) == []


def test_bgp_maximum_prefix_violation_on_unhardened_lab():
    r = rule("bgp_neighbor_maximum_prefix_required")
    violations = compliance.check_one(r, device())
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_maximum_prefix_conforme_once_configured():
    # Positionné dans l'address-family, comme vérifié en direct (contrairement à
    # ttl-security, qui est une commande de niveau voisin, hors address-family).
    hardened = R3_CONFIG.replace(
        "  network 192.168.1.0/24\n",
        "  network 192.168.1.0/24\n  neighbor 172.16.34.2 maximum-prefix 100\n",
    )
    r = rule("bgp_neighbor_maximum_prefix_required")
    assert compliance.check_one(r, device(running_config=hardened)) == []


def test_bgp_ttl_security_violation_on_unhardened_lab():
    r = rule("bgp_neighbor_ttl_security_required")
    violations = compliance.check_one(r, device())
    assert len(violations) == 1 and "172.16.34.2" in violations[0].detail


def test_bgp_ttl_security_conforme_once_configured():
    hardened = R3_CONFIG.replace(
        " neighbor 172.16.34.2 description r4-AS65002\n",
        " neighbor 172.16.34.2 description r4-AS65002\n"
        " neighbor 172.16.34.2 ttl-security hops 1\n",
    )
    r = rule("bgp_neighbor_ttl_security_required")
    assert compliance.check_one(r, device(running_config=hardened)) == []


# ------------------------------------------------------------------------------------------
# bgp_neighbor_no_default_route_policy / no_own_prefixes_policy (Phase A, sécurité, O1) :
# politique déclarée (prefix-list en entrée), jamais la table de routage -- voir la docstring
# des évaluateurs. r3 est déjà conforme aux deux sur sa config réelle.
# ------------------------------------------------------------------------------------------

def test_no_default_route_conforme_on_real_config():
    r = rule("bgp_neighbor_no_default_route_policy")
    assert compliance.check_one(r, device()) == []  # R3_CONFIG


def test_no_default_route_violation_when_prefix_list_permits_it():
    broken = R3_CONFIG.replace(
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n",
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n"
        "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n",
    )
    r = rule("bgp_neighbor_no_default_route_policy")
    violations = compliance.check_one(r, device(running_config=broken))
    assert len(violations) == 1 and "0.0.0.0/0" in violations[0].detail


def test_no_default_route_violation_even_with_le_clause():
    # "0.0.0.0/0 le 32" autorise tout : détecté via le réseau de base, pas la clause le/ge.
    broken = R3_CONFIG.replace(
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n",
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n"
        "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0 le 32\n",
    )
    r = rule("bgp_neighbor_no_default_route_policy")
    violations = compliance.check_one(r, device(running_config=broken))
    assert len(violations) == 1


def test_no_own_prefixes_conforme_on_real_config():
    r = rule("bgp_neighbor_no_own_prefixes_policy")
    assert compliance.check_one(r, device()) == []  # R3_CONFIG


def test_no_own_prefixes_violation_when_reinjected():
    # r3 annonce 10.1.0.0/16 ; si sa PL-EBGP-IN l'autorisait aussi en entrée, un voisin pourrait
    # le lui réannoncer.
    broken = R3_CONFIG.replace(
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n",
        "ip prefix-list PL-EBGP-IN seq 10 permit 10.2.0.0/16\n"
        "ip prefix-list PL-EBGP-IN seq 30 permit 10.1.0.0/16\n",
    )
    r = rule("bgp_neighbor_no_own_prefixes_policy")
    violations = compliance.check_one(r, device(running_config=broken))
    assert len(violations) == 1 and "10.1.0.0/16" in violations[0].detail


def test_no_own_prefixes_no_bgp_is_not_a_violation():
    r = rule("bgp_neighbor_no_own_prefixes_policy")
    dev = device(running_config=R1_CONFIG, name="r1")
    assert compliance.check_one(r, dev) == []


# ------------------------------------------------------------------------------------------
# Règles SR Linux (Phase D2) : fixtures réelles (tests/fixtures/r5/), running_config construit
# EXACTEMENT comme le fait SrlinuxDriver.parse() (mêmes marqueurs de section), pour que les
# tests exercent le vrai format produit, pas une supposition sur ce format.
# ------------------------------------------------------------------------------------------

R5_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "r5"
R5_INTERFACE_CONFIG = (R5_FIXTURES / "running_config.txt").read_text(encoding="utf-8")
R5_OSPF_CONFIG = (R5_FIXTURES / "ospf_running_config.txt").read_text(encoding="utf-8")


def srlinux_device(interface_config=None, ospf_config=None, auth_config=None, banner_config=None,
                    name="r5") -> DeviceState:
    interface_config = R5_INTERFACE_CONFIG if interface_config is None else interface_config
    ospf_config = R5_OSPF_CONFIG if ospf_config is None else ospf_config
    auth_config = "" if auth_config is None else auth_config
    banner_config = "" if banner_config is None else banner_config
    running_config = (
        "# --- interface ---\n" + interface_config + "\n"
        "# --- network-instance default protocols ospf ---\n" + ospf_config + "\n"
        "# --- system authentication ---\n" + auth_config + "\n"
        "# --- system banner ---\n" + banner_config
    )
    return DeviceState(name=name, host="172.20.21.15", timestamp="2026-01-01T00:00:00+00:00",
                        reachable=True, running_config=running_config, driver="srlinux")


# Phase A (sécurité, O1) : textes réellement capturés en direct sur r5 (keychain + référence
# depuis l'interface OSPF), pendant le test d'interopérabilité MD5 FRR<->SR Linux -- retirés du
# lab après capture (Phase B les remettra en place pour de bon), mais ce sont de vraies sorties
# de l'équipement, pas un format inventé.
R5_OSPF_CONFIG_WITH_AUTH = R5_OSPF_CONFIG.replace(
    "interface ethernet-1/1.0 {\n                interface-type point-to-point\n            }",
    "interface ethernet-1/1.0 {\n                interface-type point-to-point\n"
    "                authentication {\n                    keychain frr-ospf\n"
    "                }\n            }",
)
R5_AUTH_CONFIG_OSPF_KEYCHAIN = (
    "    keychain frr-ospf {\n"
    "        admin-state enable\n"
    "        type ospf\n"
    "        key 1 {\n"
    "            algorithm md5\n"
    "            authentication-key $aes1$ATLlcEqv7bqoT28=$quwaA3HqquakFj2MYIQ7VQ==\n"
    "        }\n"
    "    }\n"
)


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


def test_srlinux_ospf_authentication_violation_on_unhardened_lab():
    # Configuration réelle actuelle (avant Phase B) : aucune keychain n'existe encore.
    r = rule("srlinux_ospf_authentication_required")
    violations = compliance._check_srlinux_ospf_authentication_required(r, srlinux_device())
    assert len(violations) == 1
    assert "ethernet-1/1.0" in violations[0].detail and "aucune keychain" in violations[0].detail


def test_srlinux_ospf_authentication_conforme_once_configured():
    # Textes réellement capturés en direct (voir R5_OSPF_CONFIG_WITH_AUTH / R5_AUTH_CONFIG_*),
    # pendant le test d'interopérabilité MD5 avec FRR (adjacence confirmée Full des deux côtés).
    r = rule("srlinux_ospf_authentication_required")
    violations = compliance._check_srlinux_ospf_authentication_required(
        r, srlinux_device(ospf_config=R5_OSPF_CONFIG_WITH_AUTH, auth_config=R5_AUTH_CONFIG_OSPF_KEYCHAIN))
    assert violations == []


def test_srlinux_ospf_authentication_violation_when_keychain_missing():
    # L'interface référence une keychain, mais /system authentication est vide (dangling ref).
    r = rule("srlinux_ospf_authentication_required")
    violations = compliance._check_srlinux_ospf_authentication_required(
        r, srlinux_device(ospf_config=R5_OSPF_CONFIG_WITH_AUTH))  # auth_config par défaut : vide
    assert len(violations) == 1 and "introuvable" in violations[0].detail


def test_srlinux_ospf_authentication_violation_when_keychain_wrong_type():
    wrong_type = R5_AUTH_CONFIG_OSPF_KEYCHAIN.replace("type ospf", "type isis")
    r = rule("srlinux_ospf_authentication_required")
    violations = compliance._check_srlinux_ospf_authentication_required(
        r, srlinux_device(ospf_config=R5_OSPF_CONFIG_WITH_AUTH, auth_config=wrong_type))
    assert len(violations) == 1 and "n'est pas de type ospf" in violations[0].detail


def test_srlinux_ospf_authentication_ignores_passive_interfaces():
    # ethernet-1/2.0 et lo0.0 sont passives : aucune violation attendue à leur sujet, même sans
    # aucune keychain configurée nulle part.
    r = rule("srlinux_ospf_authentication_required")
    violations = compliance._check_srlinux_ospf_authentication_required(r, srlinux_device())
    assert not any("ethernet-1/2.0" in v.detail or "lo0.0" in v.detail for v in violations)


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


def test_old_snapshot_without_driver_field_is_evaluated_as_frr():
    # Compatibilité ascendante (Phase D2) : un snapshot écrit avant l'ajout du champ "driver"
    # (donc chargé via DeviceState.from_dict sans cette clé -> défaut "frr", voir
    # test_model.py) doit continuer à fonctionner hors ligne avec `check --snapshot` : les
    # règles FRR s'appliquent normalement, les règles SR Linux deviennent "non applicable"
    # (jamais une erreur de chargement, jamais une fausse conformité).
    from netcheck.model import DeviceState
    old_snapshot_data = {
        "name": "r1", "host": "172.20.20.11", "timestamp": "2026-01-01T00:00:00+00:00",
        "reachable": True, "running_config": R3_CONFIG,
        # pas de clé "driver" : simule un snapshot pré-D2.
    }
    state = DeviceState.from_dict(old_snapshot_data)
    assert state.driver == "frr"

    frr_rule = Rule(id="frr-rule", description="d", severity="basse", applies_to="all",
                     drivers=["frr"], kind="line_present", params={"pattern": "^log syslog informational$"})
    srl_rule = Rule(id="srl-rule", description="d", severity="basse", applies_to="all",
                     drivers=["srlinux"], kind="srlinux_interface_mtu_margin", params={})

    violations, not_applicable = compliance.evaluate([frr_rule, srl_rule], {"r1": state})
    assert violations == []  # la regle FRR trouve bien la ligne dans R3_CONFIG
    assert len(not_applicable) == 1
    assert not_applicable[0].rule.id == "srl-rule"


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
