"""Moteur de conformité de la v4 (SPEC_v4, Phase A3) : résolution des évaluateurs chez les drivers,
deux causes de « non applicable » comptées à part, refus au chargement d'une règle aveugle,
avertissements d'analyse de la configuration (verdict, trois sorties, monitor).

Les écarts voulus avec la v0.3.0 sont encodés en fin de fichier : ce sont les comportements validés
après présentation de la liste des écarts du gel (voir tests/golden/README.md).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest
from rich.console import Console

from netcheck import cli, collector, compliance, confparse, monitor, report
from netcheck.confparse import ParseWarning
from netcheck.drivers import registry
from netcheck.drivers.base import Driver
from netcheck.model import DeviceState, Interface
from netcheck.ruletypes import CAUSE_DRIVER, CAUSE_NOT_IMPLEMENTED, Check, ConfigWarning, NotApplicable, Rule

REPO = Path(__file__).resolve().parent.parent
R3 = (REPO / "tests" / "golden" / "inputs" / "frr_r3.conf").read_text(encoding="utf-8")


def rule(kind, rule_id="r", severity="haute", drivers=None, applies_to="all", **params) -> Rule:
    return Rule(id=rule_id, description=f"règle {rule_id}", severity=severity, applies_to=applies_to,
                kind=kind, drivers=drivers, params=params)


def device(name="r3", driver="frr", config=R3, reachable=True, interfaces=None) -> DeviceState:
    return DeviceState(name=name, host="-", timestamp="", reachable=reachable, running_config=config,
                       driver=driver, interfaces=interfaces or [])


class _BraceDriver(Driver):
    """Driver factice : sa configuration est lue en accolades ; un « } » orphelin est une ligne NON lue."""
    REQUIRED_COMMANDS: list[str] = []
    CONFIG_CHECKS = {"fake_kind": Check(lambda rule, device, config: [])}

    def parse(self, raw, name, host):
        raise NotImplementedError

    def parse_config(self, running_config):
        return confparse.parse_braces(running_config)


class _IndentDriver(_BraceDriver):
    """Même chose en indentation : une dédentation partielle est une ligne lue mais ambiguë."""

    def parse_config(self, running_config):
        return confparse.parse_indented(running_config)


@pytest.fixture
def fake_drivers(monkeypatch):
    monkeypatch.setitem(registry.DRIVER_REGISTRY, "fake-brace", _BraceDriver)
    monkeypatch.setitem(registry.DRIVER_REGISTRY, "fake-indent", _IndentDriver)


UNREAD = "a {\n  b 1\n}\n}\n"                 # « } » orphelin : ligne 4 NON lue
AMBIGUOUS = "a\n   b\n      c\n    d\n"      # dédentation partielle : ligne 4 lue mais ambiguë


# ------------------------------------------------------------------------------------------
# Résolution des évaluateurs et registre
# ------------------------------------------------------------------------------------------

def test_registry_is_shared_with_the_collector():
    assert collector.DRIVER_REGISTRY is registry.DRIVER_REGISTRY
    assert set(registry.DRIVER_REGISTRY) == {"frr", "srlinux", "eos"}


def test_the_engine_does_not_import_the_collector_nor_netmiko():
    """Le moteur résout les évaluateurs par le registre des drivers, pas par le collecteur (qui,
    lui, importe Netmiko). `report` et la CLI importent `diff`, donc `labtools` : hors de ce test."""
    code = ("import sys; import netcheck.compliance; "
            "sys.exit(any(m in sys.modules for m in ('netmiko', 'netcheck.collector')))")
    assert subprocess.run([sys.executable, "-c", code], cwd=REPO, check=False).returncode == 0


def test_neutral_kinds_are_resolved_for_every_driver_and_vendor_kinds_only_for_theirs():
    for name in registry.DRIVER_REGISTRY:
        assert compliance.resolve_check("line_present", name) is not None
        assert compliance.resolve_check("interface_description_required", name) is not None
    assert compliance.resolve_check("ospf_authentication_required", "frr") is not None
    assert compliance.resolve_check("ospf_authentication_required", "eos") is None
    assert compliance.implementers("ospf_authentication_required") == ["frr"]
    assert "ospf_authentication_required" in compliance.KNOWN_KINDS


def test_a_check_declares_what_it_reads():
    frr = registry.DRIVER_REGISTRY["frr"].CONFIG_CHECKS
    assert frr["ospf_passive_on_interfaces"].needs == {"config", "interfaces"}   # lit le modèle aussi
    assert frr["bgp_neighbor_password_required"].needs == {"config"}


def test_evaluate_keeps_its_historical_two_value_shape():
    rules = [rule("bgp_neighbor_password_required")]
    config = "router bgp 1\n neighbor 1.1.1.1 remote-as 2\n"
    result = compliance.evaluate_config(rules, {"r3": device(config=config)})
    violations, not_applicable = compliance.evaluate(rules, {"r3": device(config=config)})
    assert (violations, not_applicable) == (result.violations, result.not_applicable)
    assert len(violations) == 1


def test_check_one_refuses_a_kind_the_driver_does_not_implement():
    with pytest.raises(ValueError, match="non implémenté par le driver 'srlinux'"):
        compliance.check_one(rule("ospf_authentication_required"), device(driver="srlinux"))


# ------------------------------------------------------------------------------------------
# « Non applicable » : deux causes, jamais confondues
# ------------------------------------------------------------------------------------------

def test_not_implemented_and_out_of_scope_are_two_distinct_causes():
    rules = [
        rule("ospf_authentication_required", "sans-drivers"),                 # concerne tout driver...
        rule("ospf_authentication_required", "frr-seulement", drivers=["frr"]),
    ]
    devices = {"r1": device("r1"), "r5": device("r5", driver="srlinux", config="")}
    result = compliance.evaluate_config(rules, devices)
    by_rule = {n.rule.id: n for n in result.not_applicable}
    # ... mais SR Linux ne sait pas l'évaluer : trou de couverture, dit explicitement.
    assert by_rule["sans-drivers"].cause == CAUSE_NOT_IMPLEMENTED
    assert by_rule["sans-drivers"].reason == "non implémenté par le driver srlinux"
    # La règle qui ne liste pas le driver est « hors sujet » : un choix, pas un trou.
    assert by_rule["frr-seulement"].cause == CAUSE_DRIVER
    assert "non couvert par cette règle" in by_rule["frr-seulement"].reason
    assert len(result.not_applicable) == 2 and result.violations == [] or result.violations is not None


def test_a_rule_naming_a_blind_driver_is_refused_at_load_time(tmp_path):
    """v0.4.0 : `drivers: [eos]` + un kind que seul FRR implémente ne vérifierait rien : refusé."""
    path = tmp_path / "rules.yml"
    path.write_text("rules:\n  - {id: x, description: d, severity: haute, applies_to: all,\n"
                    "     drivers: [eos], kind: ospf_authentication_required}\n", encoding="utf-8")
    with pytest.raises(ValueError) as e:
        compliance.load_rules(path)
    message = str(e.value)
    assert "n'est pas implémenté" in message and "['eos']" in message and "['frr']" in message
    path.write_text(path.read_text(encoding="utf-8").replace("[eos]", "[frr]"), encoding="utf-8")
    assert compliance.load_rules(path)[0].drivers == ["frr"]


def test_the_v3_rule_files_still_load_unchanged():
    for name in ("default", "security"):
        assert compliance.load_rules(REPO / "netcheck" / "rules" / f"{name}.yml")


# ------------------------------------------------------------------------------------------
# Avertissements d'analyse : verdict
# ------------------------------------------------------------------------------------------

def test_an_unread_line_prevents_a_conforme_verdict_even_when_every_rule_passes(fake_drivers):
    result = compliance.evaluate_config([rule("fake_kind")], {"x": device("x", "fake-brace", UNREAD)})
    assert result.violations == []                      # toutes les règles sont satisfaites...
    assert [w.warning.line for w in result.unread_lines] == [4] and result.notes == []
    # ... mais le verdict n'est pas « conforme ».
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 1)


def test_an_ambiguous_line_is_information_and_never_changes_the_verdict(fake_drivers):
    result = compliance.evaluate_config([rule("fake_kind")], {"x": device("x", "fake-indent", AMBIGUOUS)})
    assert result.unread_lines == [] and [w.warning.line for w in result.notes] == [4]
    assert compliance.verdict(result.violations, result.config_warnings) == (True, 0)


def test_a_rule_violation_keeps_its_own_code_and_an_unread_line_adds_at_most_one():
    critical = [compliance.Violation(rule("x", severity="critique"), "r1", "d")]
    medium = [compliance.Violation(rule("x", severity="moyenne"), "r1", "d")]
    unread = [ConfigWarning("r1", ParseWarning(1, "t", "raison", False))]
    assert compliance.verdict(critical, unread) == (False, 2)
    assert compliance.verdict(medium, unread) == (False, 1)
    assert compliance.verdict([], []) == (True, 0)
    assert compliance.verdict([]) == (True, 0)           # l'ancienne forme, sans avertissements


def test_only_audited_reachable_devices_are_parsed_for_warnings(fake_drivers):
    devices = {
        "a": device("a", "fake-brace", UNREAD),
        "b": device("b", "fake-brace", UNREAD, reachable=False),
        "c": device("c", "fake-brace", UNREAD),
    }
    result = compliance.evaluate_config([rule("fake_kind", applies_to=["a", "b"])], devices)
    assert {w.device for w in result.config_warnings} == {"a"}      # b injoignable, c hors de toute règle


def test_real_configurations_produce_no_warning():
    """Le gel de référence ne bouge pas à cause de l'analyse : les configurations réelles sont lues
    entièrement (voir aussi tests/test_confparse.py)."""
    rules = compliance.load_rules(REPO / "netcheck" / "rules" / "security.yml")
    result = compliance.evaluate_config(rules, {"r3": device("r3")})
    assert result.config_warnings == []


# ------------------------------------------------------------------------------------------
# Les trois sorties : terminal, JSON, HTML, avec chaque famille comptée à part
# ------------------------------------------------------------------------------------------

def _scenario():
    r = rule("ospf_authentication_required", "gap")
    na = [NotApplicable(r, "r5", "non implémenté par le driver srlinux", CAUSE_NOT_IMPLEMENTED),
          NotApplicable(r, "r6", "driver 'srlinux' non couvert par cette règle", CAUSE_DRIVER)]
    warnings = [
        ConfigWarning("r1", ParseWarning(12, "neighbor 10.0.0.1 password lab-bgp-r3r4 }",
                                         "accolade fermante sans bloc ouvert", False)),
        ConfigWarning("r1", ParseWarning(7, "x", "dédentation partielle", True)),
    ]
    return na, warnings


def test_json_counts_every_family_apart_and_labels_the_cause():
    na, warnings = _scenario()
    d = report.compliance_to_dict([], compliant=False, not_applicable=na, config_warnings=warnings)
    assert d["summary"] == {
        "violations": 0, "config_lines_unread": 1, "config_notes": 1, "not_applicable": 2,
        "not_applicable_not_implemented": 1, "not_applicable_out_of_scope": 1}
    assert [(n["device"], n["cause"]) for n in d["not_applicable"]] == [
        ("r5", "not_implemented"), ("r6", "driver")]
    assert [(w["line"], w["kept"]) for w in d["config_analysis"]] == [(12, False), (7, True)]
    assert "lab-bgp-r3r4" not in json.dumps(d) and "password ****" in d["config_analysis"][0]["text"]


def test_terminal_shows_unread_lines_notes_and_the_gap_apart():
    na, warnings = _scenario()
    console = Console(record=True, width=200)
    report.print_compliance_terminal([], False, na, console=console, config_warnings=warnings)
    text = console.export_text()
    assert "Analyse de la configuration" in text and "NON LUE" in text
    assert "information (lue, ambiguë)" in text
    assert "NON IMPLÉMENTÉ" in text and "hors sujet (driver)" in text
    assert "non implémenté par le driver srlinux" in text
    assert "1 ligne(s) de configuration non lue(s)" in text and "1 information(s) d'analyse" in text
    assert "2 non applicable(s) dont 1 non implémentée(s) par leur driver" in " ".join(text.split())
    # Aucune violation prouvée : « ANALYSE INCOMPLÈTE », jamais « NON CONFORME ».
    assert "ANALYSE INCOMPLÈTE" in text and "NON CONFORME" not in text and "lab-bgp-r3r4" not in text


def test_html_shows_the_same_families_and_masks_the_secret():
    na, warnings = _scenario()
    html = report.render_compliance_html([], False, "rules/security.yml", na, warnings)
    assert "Analyse de la configuration" in html and "NON LUE" in html and "NON IMPLÉMENTÉ" in html
    assert "1 ligne(s) de configuration non lue(s)" in html
    assert "1 règle(s) non implémentée(s) par leur driver" in html
    assert "password ****" in html and "lab-bgp-r3r4" not in html
    # Le titre et le verdict disent « ANALYSE INCOMPLÈTE » : aucune violation n'est prouvée.
    assert "netcheck — ANALYSE INCOMPLÈTE</title>" in html and "NON CONFORME" not in html
    assert "verdict-analyse-incomplete" in html


def test_html_escapes_the_warning_text():
    payload = "<script>alert(1)</script>"
    html = report.render_compliance_html(
        [], False, "r.yml", None, [ConfigWarning("r1", ParseWarning(1, payload, payload, False))])
    assert payload not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_a_clean_report_mentions_none_of_the_new_sections():
    html = report.render_compliance_html([], True, "rules/default.yml")
    assert "Analyse de la configuration" not in html and "non implémentée" not in html
    d = report.compliance_to_dict([], compliant=True)
    assert d["config_analysis"] == [] and d["summary"]["config_lines_unread"] == 0


# ------------------------------------------------------------------------------------------
# monitor et CLI
# ------------------------------------------------------------------------------------------

def test_monitor_turns_unread_lines_into_one_attention_per_device_without_any_line_text():
    warnings = [ConfigWarning("r1", ParseWarning(1, "password lab-bgp-r3r4", "x", False)),
                ConfigWarning("r1", ParseWarning(2, "secret-text", "y", False)),
                ConfigWarning("r2", ParseWarning(3, "z", "ambiguë", True))]
    status, contributions = monitor.check_outcome([], warnings)
    assert status == monitor.ATTENTION and len(contributions) == 1
    c = contributions[0]
    assert (c.device, c.component) == ("r1", "check")
    assert "2 ligne(s) de configuration non lue(s)" in c.message
    assert "lab-bgp" not in repr(c) and "secret-text" not in repr(c)
    assert monitor.check_outcome([], [warnings[2]]) == (monitor.OK, [])      # ambiguë : aucun effet


def test_cli_check_exits_1_on_an_unread_line_even_when_all_rules_pass(
        fake_drivers, monkeypatch, tmp_path, capsys):
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text("rules:\n  - {id: fk, description: d, severity: haute, applies_to: all,\n"
                          "     drivers: [fake-brace], kind: fake_kind}\n", encoding="utf-8")
    monkeypatch.setattr(cli.snapshot, "load", lambda name: {"x": device("x", "fake-brace", UNREAD)})
    out_json = tmp_path / "out.json"
    args = argparse.Namespace(rules=str(rules_file), inventory=None, snapshot="s",
                              json=str(out_json), html=None)
    assert cli.cmd_check(args) == 1
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["compliant"] is False and data["violations"] == []
    assert data["status"] == "ANALYSE INCOMPLÈTE" and data["summary"]["config_lines_unread"] == 1
    out = capsys.readouterr().out
    assert "NON LUE" in out and "ANALYSE INCOMPLÈTE" in out and "NON CONFORME" not in out


# ------------------------------------------------------------------------------------------
# Écarts VOULUS avec la v0.3.0 (validés ; la liste est dans tests/golden/README.md)
# ------------------------------------------------------------------------------------------

def _frr(config, kind, **kw):
    return compliance.check_one(rule(kind, **kw), device(config=config))


def test_a_deleted_exit_no_longer_loses_the_previous_block():
    """v0.3.0 ne retrouvait un bloc d'interface que s'il se terminait par `exit` : supprimer un `exit`
    faisait disparaître l'interface (faux négatif) ou fusionnait deux route-maps (faux positif)."""
    without_exit = "\n".join(line for line in R3.splitlines() if line.strip() != "exit")
    assert _frr(without_exit, "ospf_authentication_required") == []
    assert _frr(without_exit, "bgp_neighbor_no_own_prefixes_policy") == []     # v0.3.0 : 2 violations à tort
    unhardened = without_exit.replace(" ip ospf authentication message-digest\n", "")
    assert len(_frr(unhardened, "ospf_authentication_required")) == 2          # eth1, eth2 : vues sans `exit`


def test_a_negated_command_is_not_read_as_the_command():
    """v0.3.0 testait une sous-chaîne : `no ip ospf passive` comptait comme « ip ospf passive »."""
    config = ("interface eth9\n description LAN\n ip address 10.0.0.1/24\n ip ospf area 0\n"
              " no ip ospf passive\nexit\n")
    assert len(_frr(config, "ospf_authentication_required")) == 1
    eth9 = Interface("eth9", "LAN-x", True, True, ["10.0.0.1/24"])
    violations = compliance.check_one(rule("ospf_passive_on_interfaces", pattern="LAN"),
                                      device(config=config, interfaces=[eth9]))
    assert len(violations) == 1


def test_text_inside_a_description_is_not_configuration():
    config = "interface eth9\n description ip ospf passive\n ip ospf area 0\nexit\n"
    # v0.3.0 lisait « passive » dans la description et ne signalait rien.
    assert len(_frr(config, "ospf_authentication_required")) == 1


def test_extra_spaces_are_not_a_missing_password():
    config = ("router bgp 65001\n neighbor  172.16.34.2  remote-as  65002\n"
              " neighbor  172.16.34.2  password  x\nexit\n")
    assert _frr(config, "bgp_neighbor_password_required") == []        # v0.3.0 : « sans mot de passe » à tort


# ------------------------------------------------------------------------------------------
# Libellé : NON CONFORME est réservé aux violations réelles
# ------------------------------------------------------------------------------------------

def test_status_label_reserves_non_conforme_for_real_violations():
    violation = [compliance.Violation(rule("x"), "r1", "d")]
    unread = [ConfigWarning("r1", ParseWarning(1, "t", "raison", False))]
    ambiguous = [ConfigWarning("r1", ParseWarning(1, "t", "raison", True))]
    assert compliance.status_label([], []) == "CONFORME"
    assert compliance.status_label([], ambiguous) == "CONFORME"                 # information seulement
    assert compliance.status_label([], unread) == "ANALYSE INCOMPLÈTE"          # rien de prouvé
    assert compliance.status_label(violation, []) == "NON CONFORME"
    assert compliance.status_label(violation, unread) == "NON CONFORME"         # la violation prouvée prime
    # Le code retour reste celui de la plus grave des deux situations.
    assert compliance.verdict([], unread) == (False, 1)
    critical = [compliance.Violation(rule("x", severity="critique"), "r1", "d")]
    assert compliance.verdict(critical, unread) == (False, 2)


def test_report_status_in_the_three_outputs_when_a_violation_and_an_unread_line_coexist():
    unread = [ConfigWarning("r1", ParseWarning(1, "t", "raison", False))]
    violation = [compliance.Violation(rule("x"), "r1", "d")]
    assert report.compliance_to_dict(violation, False, None, unread)["status"] == "NON CONFORME"
    console = Console(record=True, width=200)
    report.print_compliance_terminal(violation, False, None, console=console, config_warnings=unread)
    text = console.export_text()
    assert "NON CONFORME" in text and "1 ligne(s) de configuration non lue(s)" in text
    assert "NON CONFORME" in report.render_compliance_html(violation, False, "r.yml", None, unread)


# ------------------------------------------------------------------------------------------
# FRR ne lit pas l'indentation : une sous-commande au premier niveau est une ligne NON conservée
# ------------------------------------------------------------------------------------------

HAND_WRITTEN_INTERFACE = (
    "hostname r1\n"
    "interface eth1\n"
    "ip address 10.1.13.1/30\n"
    "ip ospf area 0\n"
    "ip ospf authentication message-digest\n"
    "ip ospf message-digest-key 1 md5 lab-ospf-r1r3\n"
    "exit\n"
)
HAND_WRITTEN_BGP = (
    "router bgp 65001\n"
    "neighbor 10.0.0.1 remote-as 65002\n"
    "neighbor 10.0.0.1 password lab-bgp-r3r4\n"
    "exit\n"
)


def _frr_audit(config, *rules_):
    return compliance.evaluate_config(list(rules_), {"r1": device("r1", config=config)})


def test_unindented_interface_subcommands_are_flagged_not_silently_ignored():
    """FRR (vérifié avec `vtysh -C`) applique ces lignes à l'interface ouverte. L'arbre, lui, les
    verrait au premier niveau : l'interface paraîtrait sans authentification, sans alerte."""
    result = _frr_audit(HAND_WRITTEN_INTERFACE, rule("ospf_authentication_required"))
    assert result.violations == []                                  # aucune violation PROUVÉE...
    assert [(w.warning.line, w.kept) for w in result.config_warnings] == [
        (3, False), (4, False), (5, False), (6, False)]
    assert all("sous-commande de « interface » au premier niveau" in w.warning.reason
               for w in result.config_warnings)
    assert compliance.status_label(result.violations, result.config_warnings) == "ANALYSE INCOMPLÈTE"
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 1)


def test_unindented_router_bgp_subcommands_are_flagged():
    result = _frr_audit(HAND_WRITTEN_BGP, rule("bgp_neighbor_password_required"))
    assert result.violations == []
    assert [w.warning.line for w in result.unread_lines] == [2, 3]
    assert "router bgp" in result.unread_lines[0].warning.reason
    # Le mot de passe ne figure ni dans l'avertissement ni dans les trois sorties.
    assert "lab-bgp-r3r4" not in " ".join(str(w.warning) for w in result.config_warnings)


def test_flagged_lines_leave_the_tree_and_every_line_stays_counted():
    cfg = registry.DRIVER_REGISTRY["frr"]().parse_config(HAND_WRITTEN_INTERFACE)
    assert sum(cfg.counts.values()) == cfg.lines_total == 7
    assert cfg.counts["skipped"] == 4 == len(cfg.unclassified())
    # Rien de la sous-commande au premier niveau ; le `exit` final, lui, est une ligne légitime.
    assert [f.path for f in cfg.flat] == [("hostname", "r1"), ("interface", "eth1"), ("exit",)]


def test_correctly_indented_blocks_and_real_root_commands_give_no_warning():
    config = ("hostname r1\nlog syslog informational\nip route 10.0.0.0/8 Null0\n"
              "ip prefix-list PL seq 10 permit 10.0.0.0/8\n"
              "route-map RM permit 10\n match ip address prefix-list PL\nexit\n"
              "interface eth1\n ip ospf area 0\nexit\n"
              "router bgp 65001\n neighbor 1.1.1.1 remote-as 2\nexit\n"
              "bgp community-list standard C permit 65001:1\nend\n")
    cfg = registry.DRIVER_REGISTRY["frr"]().parse_config(config)
    assert cfg.warnings == []          # « bgp community-list » est valide à la racine : jamais signalé


@pytest.mark.parametrize("path", [
    *(REPO / "tests" / "fixtures" / r / "running_config.txt" for r in ("r1", "r3", "r4")),
    *sorted((REPO / "tests" / "golden" / "inputs").glob("frr_*.conf")),
], ids=lambda p: p.name if "golden" in str(p) else p.parent.name)
def test_real_frr_configurations_give_no_warning_with_the_frr_driver(path):
    """Les sorties relevées en direct sont toujours indentées (vérifié aussi sur les 13 équipements FRR
    des trois labs lors de la Phase A3) : aucune ligne n'est signalée."""
    assert registry.DRIVER_REGISTRY["frr"]().parse_config(path.read_text(encoding="utf-8")).warnings == []


# ------------------------------------------------------------------------------------------
# « Structure incertaine » : ligne lue (ses violations sont rapportées) mais verdict jamais « conforme »
# ------------------------------------------------------------------------------------------

UNCLOSED = "a {\n  b 1\n"        # il manque le « } » : la place de tout ce qui suit est incertaine


def test_an_unclosed_block_keeps_its_lines_but_blocks_a_conforme_verdict(fake_drivers):
    result = compliance.evaluate_config([rule("fake_kind")], {"x": device("x", "fake-brace", UNCLOSED)})
    (w,) = result.config_warnings
    assert w.kept and w.blocks_verdict and "jamais fermé" in w.warning.reason
    assert result.unread_lines == [w] and result.notes == []
    assert compliance.status_label(result.violations, result.config_warnings) == "ANALYSE INCOMPLÈTE"
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 1)


def test_structure_uncertain_lines_have_their_own_label_in_the_three_outputs():
    w = [ConfigWarning("r1", ParseWarning(4, "a {", "bloc ouvert jamais fermé", True, blocking=True))]
    d = report.compliance_to_dict([], False, None, w)
    assert d["status"] == "ANALYSE INCOMPLÈTE" and d["summary"]["config_lines_unread"] == 1
    assert d["config_analysis"][0]["kept"] is True and d["config_analysis"][0]["blocks_verdict"] is True
    console = Console(record=True, width=240)
    report.print_compliance_terminal([], False, None, console=console, config_warnings=w)
    assert "STRUCTURE INCERTAINE" in console.export_text() and "NON LUE" not in console.export_text()
    html = report.render_compliance_html([], False, "r.yml", None, w)
    assert "STRUCTURE INCERTAINE" in html and "ANALYSE INCOMPLÈTE" in html and "NON CONFORME" not in html


def test_monitor_counts_structure_uncertain_lines_like_unread_ones():
    w = [ConfigWarning("r1", ParseWarning(4, "a {", "bloc ouvert jamais fermé", True, blocking=True))]
    status, contributions = monitor.check_outcome([], w)
    assert status == monitor.ATTENTION
    assert "1 ligne(s) de configuration non lue(s) ou incertaine(s)" in contributions[0].message
