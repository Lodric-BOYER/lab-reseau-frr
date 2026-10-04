"""Phase B4 : un audit ne se tait pas sur l'IPv6.

Si l'état relevé (ou la configuration auditée) contient de l'IPv6 et qu'aucune règle propre à l'IPv6 n'est
chargée pour l'équipement, `check` le dit en INFORMATION dans les trois sorties : « IPv6 configuré, aucune
règle IPv6 chargée ». Jamais un constat, jamais d'effet sur le code retour. Configurations réelles : celles
relevées en direct sur les labs (tests/fixtures/live_dualstack/) et les fichiers de démarrage du dépôt.
"""
import io
import json
from pathlib import Path

import dualstack_support as ds
import pytest
from rich.console import Console

from netcheck import cli, compliance, monitor, report
from netcheck.drivers import base
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import BgpPeer, DeviceState, Interface, OspfNeighbor, Route
from netcheck.ruletypes import Check

REPO = Path(__file__).resolve().parent.parent
FX = Path(__file__).resolve().parent / "fixtures" / "live_dualstack"
DEFAULT = REPO / "netcheck/rules/default.yml"
SECURITY = REPO / "netcheck/rules/security.yml"
SECURITY6 = REPO / "netcheck/rules/security-ipv6.yml"
NOTE = compliance.NOTE_IPV6_UNCOVERED
MGMT = {"eth0", "mgmt0", "Management0"}

LAB = {"r1": ("frr", "frr_r1.txt"), "r2": ("frr", "frr_r2.txt"), "r3": ("frr", "frr_r3.txt"),
       "r4": ("frr", "frr_r4.txt"), "r5": ("frr", "frr_r5.txt")}
MIXED = {**LAB, "r5": ("srlinux", "srl_r5.txt")}
CEOS = {**LAB, "r4": ("eos", "eos_r4.txt")}


def devices(spec=LAB) -> dict[str, DeviceState]:
    return {n: DeviceState(name=n, host="-", timestamp="", reachable=True, driver=d,
                           running_config=(FX / f).read_text(encoding="utf-8")) for n, (d, f) in spec.items()}


def audit(*files, spec=LAB, devs=None, mgmt=MGMT):
    return compliance.evaluate_config(compliance.load_rule_files(list(files)), devs or devices(spec), mgmt)


def noted(result) -> list[str]:
    return [d for n in result.coverage_notes for d in n.devices]


# ------------------------------------------------------------------------------------------
# Reconnaître l'IPv6 dans une configuration : l'adresse, jamais un faux ami
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    " ipv6 address 2001:db8:1:12::2/127", "ipv6 prefix-list P permit ::/0", "fe80::1", "neighbor 2001:db8::1",
    "address 2001:db8:2:45::3/127 {", "ipv6 route 2001:db8:2::/48 Null0",
])
def test_an_ipv6_literal_is_recognized(text):
    assert base.has_ipv6_literal(text)


@pytest.mark.parametrize("text", [
    "no ipv6 forwarding",                            # le mot seul ne dit pas qu'il y a de l'IPv6
    "mac-address aa:bb:cc:dd:ee:ff", "set community 65001:100", "clock 12:30:00", "ip address 10.0.0.1/24",
    "router-id 10.1.255.1", "neighbor 172.16.34.1 password x", "",
])
def test_things_that_look_like_ipv6_are_not(text):
    assert not base.has_ipv6_literal(text)


@pytest.mark.parametrize("name,spec", [("frr", "frr_r4.txt"), ("eos", "eos_r4.txt"),
                                       ("srlinux", "srl_r5.txt")])
def test_each_driver_sees_ipv6_in_its_real_configuration(name, spec):
    config = (FX / spec).read_text(encoding="utf-8")
    assert DRIVER_REGISTRY[name]().config_uses_ipv6(config)


def test_the_keyword_lines_say_ipv6_even_without_an_address():
    frr, eos = DRIVER_REGISTRY["frr"](), DRIVER_REGISTRY["eos"]()
    assert frr.config_uses_ipv6("router ospf6\n ospf6 router-id 10.0.0.1\n")
    assert frr.config_uses_ipv6("router bgp 65001\n address-family ipv6 unicast\n")
    assert eos.config_uses_ipv6("ipv6 unicast-routing\n") and eos.config_uses_ipv6("router ospfv3\n")
    assert not frr.config_uses_ipv6("no ipv6 forwarding\nrouter ospf\n ospf router-id 10.0.0.1\n")
    assert not eos.config_uses_ipv6("hostname r4\nip routing\n")


def test_the_ipv4_only_configurations_of_v030_do_not_say_ipv6():
    for router in ("r1", "r3", "r4"):
        text = (REPO / "tests/fixtures" / router / "running_config.txt").read_text(encoding="utf-8")
        assert not DRIVER_REGISTRY["frr"]().config_uses_ipv6(text), router


# ------------------------------------------------------------------------------------------
# Le moteur : quand la note apparaît, et quand elle ne doit pas
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("files", [(DEFAULT,), (SECURITY,), (DEFAULT, SECURITY)])
@pytest.mark.parametrize("spec", [LAB, MIXED, CEOS], ids=["frr", "mixed", "ceos"])
def test_without_an_ipv6_rule_every_ipv6_device_is_named(files, spec):
    result = audit(*files, spec=spec)
    assert [n.kind for n in result.coverage_notes] == [NOTE]
    assert noted(result) == ["r1", "r2", "r3", "r4", "r5"]
    text = result.coverage_notes[0].text
    assert text.startswith("IPv6 configuré (r1, r2, r3, r4, r5), aucune règle IPv6 chargée")
    assert "security-ipv6.yml" in text and "--rules" in text


@pytest.mark.parametrize("files", [(SECURITY, SECURITY6), (SECURITY6,), (DEFAULT, SECURITY, SECURITY6)])
@pytest.mark.parametrize("spec", [LAB, MIXED, CEOS], ids=["frr", "mixed", "ceos"])
def test_with_the_ipv6_rule_file_there_is_no_note(files, spec):
    assert audit(*files, spec=spec).coverage_notes == []


def test_the_note_is_information_only_the_verdict_does_not_move():
    # security.yml seul : l'authentification OSPFv3 n'a aucune règle, l'audit est donc « conforme » : c'est
    # le silence que la note dénonce. Avec les deux fichiers, le défaut du lien r4-r5 apparaît.
    alone = audit(SECURITY)
    assert alone.violations == [] and compliance.verdict(alone.violations, alone.config_warnings) == (True, 0)
    assert alone.coverage_notes
    both = audit(SECURITY, SECURITY6)
    assert sorted(v.device for v in both.violations) == ["r4", "r5"] and both.coverage_notes == []


def test_a_device_that_only_a_foreign_driver_rule_covers_is_still_named():
    # Une règle IPv6 limitée à FRR ne couvre pas r5 (SR Linux) : la note nomme r5 seul.
    only_frr = [r for r in compliance.load_rules(SECURITY6) if r.drivers == ["frr"]]
    assert len(only_frr) == 1
    result = compliance.evaluate_config(only_frr, devices(MIXED), MGMT)
    assert noted(result) == ["r5"]
    result = compliance.evaluate_config(only_frr, devices(CEOS), MGMT)
    assert noted(result) == ["r4"]


def test_a_rule_that_does_not_apply_to_the_device_does_not_cover_it():
    rule = [r for r in compliance.load_rules(SECURITY6) if r.drivers == ["frr"]][0]
    rule.applies_to = ["r1"]
    result = compliance.evaluate_config([rule], devices(LAB), MGMT)
    # Aucune règle ne s'applique à r2..r5 : ils ne sont pas audités du tout, donc pas nommés.
    assert noted(result) == []
    other = compliance.load_rules(DEFAULT)[0]
    other.applies_to = ["r2"]
    result = compliance.evaluate_config([rule, other], devices(LAB), MGMT)
    assert noted(result) == ["r2"]               # r2 est audité, et l'IPv6 y est sans règle IPv6


def test_an_unreachable_device_is_not_named():
    devs = devices()
    devs["r2"].reachable = False
    assert "r2" not in noted(audit(SECURITY, devs=devs))


def test_an_ipv4_only_network_gets_no_note():
    devs = {"r1": DeviceState(name="r1", host="-", timestamp="", reachable=True, driver="frr",
                              running_config="hostname r1\nno ipv6 forwarding\nrouter ospf\n",
                              interfaces=[Interface("eth1", None, True, True, ["10.0.0.1/30"])])}
    assert audit(DEFAULT, devs=devs).coverage_notes == []


def state_with(**over) -> DeviceState:
    base_state = dict(name="r1", host="-", timestamp="", reachable=True, driver="frr", running_config="")
    return DeviceState(**{**base_state, **over})


@pytest.mark.parametrize("over", [
    {"interfaces": [Interface("eth1", None, True, True, addresses6=["2001:db8::1/64"])]},
    {"interfaces": [Interface("eth1", None, True, True, link_local6="fe80::1")]},
    {"ospf6_neighbors": [OspfNeighbor("10.0.0.2", "Full/-", "eth1")]},
    {"bgp_peers": [BgpPeer("2001:db8::2", 65002, "Established", 1, 1, address_family="ipv6")]},
    {"routes": [Route("2001:db8:2::/48", "static", 0, 1, True)]},
], ids=["address", "link-local", "ospfv3", "bgp6", "route"])
def test_each_ipv6_signal_of_the_collected_state_is_enough(over):
    assert noted(audit(DEFAULT, devs={"r1": state_with(**over)})) == ["r1"]


def test_an_ipv6_link_local_route_alone_is_not_a_signal():
    devs = {"r1": state_with(routes=[Route("fe80::/64", "connected", 0, 0, True)])}
    assert audit(DEFAULT, devs=devs).coverage_notes == []


def test_ipv6_on_a_management_interface_is_not_counted_but_elsewhere_it_is():
    mgmt_only = [Interface("eth0", None, True, True, addresses6=["2001:db8:ffff::2/64"])]
    assert audit(DEFAULT, devs={"r1": state_with(interfaces=mgmt_only)}).coverage_notes == []
    elsewhere = [Interface("eth1", None, True, True, addresses6=["2001:db8:ffff::2/64"])]
    assert noted(audit(DEFAULT, devs={"r1": state_with(interfaces=elsewhere)})) == ["r1"]


def test_the_real_ipv4_only_configurations_of_v030_get_no_note():
    def config(router: str) -> str:
        return (REPO / "tests/fixtures" / router / "running_config.txt").read_text(encoding="utf-8")

    devs = {r: DeviceState(name=r, host="-", timestamp="", reachable=True, driver="frr",
                           running_config=config(r)) for r in ("r1", "r3", "r4")}
    assert audit(DEFAULT, SECURITY, devs=devs).coverage_notes == []


def test_a_legacy_snapshot_is_judged_on_its_configuration_too():
    # snapshot_v030/frr : relevé d'AVANT l'IPv6 (aucune section IPv6), mais la configuration qu'il porte
    # est en double pile : la note tient à la configuration, pas seulement aux sections collectées.
    from netcheck import snapshot
    devs = snapshot.load(str(REPO / "tests/fixtures/snapshot_v030/frr"))
    assert all(s.collected is None for s in devs.values())
    assert noted(audit(DEFAULT, SECURITY, devs=devs)) == ["r1", "r2", "r3", "r4", "r5"]


# ------------------------------------------------------------------------------------------
# Les trois sorties
# ------------------------------------------------------------------------------------------

def outputs(result):
    coverage = report.coverage_data(result)
    compliant, _ = compliance.verdict(result.violations, result.config_warnings)
    console = Console(file=io.StringIO(), width=2000, force_terminal=False)
    report.print_compliance_terminal(result.violations, compliant, result.not_applicable, console,
                                     result.config_warnings, coverage=coverage)
    data = report.compliance_to_dict(result.violations, compliant, result.not_applicable,
                                     result.config_warnings, coverage=coverage)
    html = report.render_compliance_html(result.violations, compliant, "rules", result.not_applicable,
                                         result.config_warnings, coverage=coverage)
    return console.file.getvalue(), data, html


def test_the_three_outputs_carry_the_note():
    result = audit(SECURITY)
    out, data, html = outputs(result)
    sentence = "IPv6 configuré (r1, r2, r3, r4, r5), aucune règle IPv6 chargée"
    assert "information (couverture)" in out and sentence in out
    assert "1 information(s) de couverture" in out and "CONFORME" in out
    assert data["coverage_notes"] == [{"kind": NOTE, "devices": ["r1", "r2", "r3", "r4", "r5"],
                                       "text": result.coverage_notes[0].text}]
    assert data["summary"]["coverage_notes"] == 1
    assert data["compliant"] is True and data["status"] == "CONFORME"
    assert sentence in html and "1 information(s) de couverture" in html and "security-ipv6.yml" in html
    json.dumps(data)                                                      # sérialisable


def test_without_a_note_the_outputs_are_those_of_before():
    result = audit(SECURITY, SECURITY6)
    out, data, html = outputs(result)
    assert "couverture" not in out
    assert "coverage_notes" not in data and "coverage_notes" not in data["summary"]
    assert "information (couverture)" not in html and "information(s) de couverture" not in html


def test_the_text_of_the_note_goes_through_the_masking_and_the_html_escaping():
    result = audit(SECURITY)
    result.coverage_notes[0] = compliance.CoverageNote(NOTE, ("r1",), "x <b>gras</b> password hunter2")
    out, data, html = outputs(result)
    assert "hunter2" not in out and "hunter2" not in json.dumps(data) and "hunter2" not in html
    assert "<b>gras</b>" not in html and "&lt;b&gt;gras&lt;/b&gt;" in html


def test_the_note_text_cannot_be_read_as_rich_markup():
    result = audit(SECURITY)
    result.coverage_notes[0] = compliance.CoverageNote(NOTE, ("r1",), "texte [bold red]piégé[/] visible")
    out, _, _ = outputs(result)
    assert "[bold red]piégé[/]" in out


# ------------------------------------------------------------------------------------------
# CLI (hors ligne : les fichiers de démarrage du dépôt) et monitor
# ------------------------------------------------------------------------------------------

def cli_check(*rules, extra=()):
    argv = ["check", "--config-dir", str(REPO / "configs"), "-i", str(REPO / "automation/inventory.yml")]
    for r in rules:
        argv += ["--rules", str(r)]
    return cli.main(argv + list(extra))


def test_cli_offline_security_yml_alone_says_it_and_the_code_is_unchanged(capsys, tmp_path):
    out_json = tmp_path / "c.json"
    assert cli_check(SECURITY, extra=["--json", str(out_json), "--html", str(tmp_path / "c.html")]) == 0
    assert "aucune règle IPv6 chargée" in " ".join(capsys.readouterr().out.split())
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["coverage_notes"][0]["kind"] == NOTE and data["summary"]["violations"] == 0
    assert "aucune règle IPv6 chargée" in (tmp_path / "c.html").read_text(encoding="utf-8")


def test_cli_with_both_rule_files_there_is_no_note(capsys):
    assert cli_check(SECURITY, SECURITY6) == 2                                # le défaut réel du lien r4-r5
    assert "couverture" not in capsys.readouterr().out


def test_monitor_reports_carry_the_note(tmp_path):
    lab = ds.load_lab("frr")
    results = {n: (True, s) for n, s in lab.items()}
    rules = compliance.load_rule_files([SECURITY])
    ev = monitor.evaluate(results, lab, set(), None, rules)
    assert ev.coverage and ev.coverage[0]["kind"] == NOTE
    assert ev.status == monitor.OK                                            # information : aucune alerte
    monitor.write_reports(tmp_path, ev, "base", None, str(SECURITY), "2026-10-05T00:00:00")
    data = json.loads((tmp_path / "check.json").read_text(encoding="utf-8"))
    assert data["coverage_notes"][0]["devices"] == ["r1", "r2", "r3", "r4", "r5"]
    assert "aucune règle IPv6 chargée" in (tmp_path / "check.html").read_text(encoding="utf-8")
    both = monitor.evaluate(results, lab, set(), None, compliance.load_rule_files([SECURITY, SECURITY6]))
    assert both.coverage == []


# ------------------------------------------------------------------------------------------
# Garde-fou : un kind propre à l'IPv6 ajouté plus tard doit être déclaré
# ------------------------------------------------------------------------------------------

def test_every_kind_about_ipv6_objects_is_declared_ipv6_by_its_driver():
    for name, driver in DRIVER_REGISTRY.items():
        for kind, check in driver.CONFIG_CHECKS.items():
            about_ipv6 = "ospf6" in kind or "ipv6" in kind or "ospfv3" in kind
            assert check.ipv6 == about_ipv6, (name, kind)
        # Chaque driver qui sait lire l'OSPFv3 fournit un évaluateur déclaré IPv6.
        assert any(check.ipv6 for check in driver.CONFIG_CHECKS.values()), name
    # Un évaluateur neutre du moteur n'est jamais « IPv6 » : il ne dit rien d'un objet précis.
    assert not any(check.ipv6 for check in compliance._UNIVERSAL.values())


@pytest.mark.parametrize("name", ["frr", "eos", "srlinux"])
def test_every_declared_keyword_line_counts_for_its_driver(name):
    driver = DRIVER_REGISTRY[name]()
    for prefix in driver.IPV6_CONFIG_PREFIXES:
        assert driver.config_uses_ipv6(f"hostname x\n  {prefix.strip()} suite\n"), prefix
    assert not driver.config_uses_ipv6("hostname x\n  interface eth1\n")


def test_a_rule_whose_kind_the_driver_cannot_evaluate_covers_nothing_on_that_driver():
    # Une règle EOS sans `drivers:` est « non implémentée » par FRR : elle ne couvre pas r1..r3 (FRR).
    rule = [r for r in compliance.load_rules(SECURITY6) if r.drivers == ["eos"]][0]
    rule.drivers = None
    assert compliance.resolve_check(rule.kind, "frr") is None
    result = compliance.evaluate_config([rule], devices(CEOS), MGMT)
    assert noted(result) == ["r1", "r2", "r3", "r5"]            # r4 (EOS) est couvert


def test_the_drivers_list_of_a_rule_limits_what_it_covers(monkeypatch):
    # Un kind NEUTRE (que tous les drivers savent évaluer) déclaré « IPv6 » : sa liste `drivers:` décide seule
    # de ce qu'il couvre, la résolution du kind ne pouvant pas les départager.
    neutral = compliance._UNIVERSAL["line_present"]
    monkeypatch.setitem(compliance._UNIVERSAL, "line_present", Check(neutral.fn, neutral.needs, ipv6=True))
    rule = compliance.Rule("p", "d", "basse", "all", "line_present", drivers=["frr"], params={"pattern": "x"})
    result = compliance.evaluate_config([rule], devices(CEOS), MGMT)
    assert noted(result) == ["r4"]
    rule.drivers = None
    assert compliance.evaluate_config([rule], devices(CEOS), MGMT).coverage_notes == []
