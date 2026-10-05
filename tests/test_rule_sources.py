"""Périmètre d'une règle par SOURCE (`sources:`), libellés HORS PÉRIMÈTRE et garde-fou « rien n'a été audité »
(phase C6).

Ce que ces tests tiennent : `sources: [live, snapshot]` est validé au chargement (valeur inconnue = erreur) ;
une règle déclarée hors de la source de l'exécution est exclue du verdict mais LISTÉE (règle, libellé,
équipements regroupés) dans le terminal, le JSON et le HTML ; une règle qui lit l'état collecté SANS
déclaration reste un trou (ANALYSE INCOMPLÈTE, code 1) ; si toutes les règles sont hors périmètre, rien n'a
été audité : code 3, jamais 0.
"""

import json
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from netcheck import cli, collector, compliance, hostkeys, monitor, report, snapshot
from netcheck.model import DeviceState
from netcheck.ruletypes import (
    CAUSE_DRIVER,
    CAUSE_NO_MODEL,
    CAUSE_NOT_IMPLEMENTED,
    CAUSE_SOURCE,
    CAUSE_UNREACHABLE,
    KNOWN_SOURCES,
    NotApplicable,
    Rule,
    coverage_gaps,
)

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "netcheck" / "rules"
FRR_CONF = "hostname r1\ninterface eth0\n description LAN\n"


def _rule_file(tmp_path, *rules, name="rules.yml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump({"rules": list(rules)}, allow_unicode=True), encoding="utf-8")
    return path


def _raw(rule_id="r", kind="line_present", **extra):
    base = {"id": rule_id, "description": "d", "severity": "moyenne", "applies_to": "all", "kind": kind}
    if kind == "line_present":
        base["pattern"] = "hostname"
    return {**base, **extra}


def _state(name="r1", driver="frr", config=FRR_CONF, reachable=True):
    return DeviceState(
        name=name, host="-", timestamp="t", reachable=reachable, running_config=config, driver=driver
    )


# ------------------------------------------------------------------------------------------
# Validation au chargement
# ------------------------------------------------------------------------------------------


def test_the_known_sources_are_the_three_ways_to_run_a_check():
    assert set(KNOWN_SOURCES) == {"live", "snapshot", "config-dir"}


@pytest.mark.parametrize(
    "sources",
    [["live"], ["snapshot"], ["config-dir"], ["live", "snapshot"], ["live", "snapshot", "config-dir"]],
)
def test_valid_sources_are_kept_on_the_rule(tmp_path, sources):
    (rule,) = compliance.load_rules(_rule_file(tmp_path, _raw(sources=sources)))
    assert rule.sources == sources


def test_a_rule_without_sources_applies_to_every_source(tmp_path):
    (rule,) = compliance.load_rules(_rule_file(tmp_path, _raw()))
    assert rule.sources is None
    for source in KNOWN_SOURCES:
        result = compliance.evaluate_config([rule], {"r1": _state()}, source=source)
        assert result.evaluated == 1 and not result.not_applicable


@pytest.mark.parametrize(
    ("sources", "message"),
    [
        (["offline"], "source\\(s\\) inconnue\\(s\\)"),
        (["live", "hors-ligne"], "hors-ligne"),
        (["LIVE"], "source\\(s\\) inconnue\\(s\\)"),
        ([], "liste non vide"),
        ("live", "liste non vide"),
        ({"live": True}, "liste non vide"),
        (["live", "live"], "en double"),
    ],
)
def test_an_invalid_sources_field_is_an_error_at_load_time(tmp_path, sources, message):
    with pytest.raises(ValueError, match=message):
        compliance.load_rules(_rule_file(tmp_path, _raw("regle-x", sources=sources)))


def test_the_error_names_the_rule_and_the_accepted_values(tmp_path):
    with pytest.raises(ValueError) as error:
        compliance.load_rules(_rule_file(tmp_path, _raw("regle-x", sources=["offline"])))
    assert "regle-x" in str(error.value) and "config-dir" in str(error.value)


def test_sources_is_not_taken_for_a_rule_parameter(tmp_path):
    (rule,) = compliance.load_rules(_rule_file(tmp_path, _raw(sources=["live"])))
    assert "sources" not in rule.params


# ------------------------------------------------------------------------------------------
# Le moteur
# ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "scoped"),
    [("live", False), ("snapshot", False), ("config-dir", True)],
)
def test_a_rule_declared_for_live_and_snapshot_is_out_of_scope_offline_only(source, scoped):
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"},
                sources=["live", "snapshot"])
    result = compliance.evaluate_config([rule], {"r1": _state()}, source=source)
    assert result.evaluated == (0 if scoped else 1)
    assert [n.cause for n in result.not_applicable] == ([CAUSE_SOURCE] if scoped else [])


def test_the_offline_flag_alone_means_the_config_dir_source():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"}, sources=["live"])
    assert compliance.evaluate_config([rule], {"r1": _state()}, offline=True).evaluated == 0
    assert compliance.evaluate_config([rule], {"r1": _state()}).evaluated == 1


def test_an_unknown_run_source_is_a_defect_not_a_silent_default():
    with pytest.raises(ValueError, match="source d'exécution inconnue"):
        compliance.evaluate_config([], {}, source="hors-ligne")


def test_the_driver_scope_is_decided_before_the_source_scope():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"},
                drivers=["frr"], sources=["live"])
    result = compliance.evaluate_config([rule], {"r1": _state(driver="eos")}, source="config-dir")
    (na,) = result.not_applicable
    assert na.cause == CAUSE_DRIVER and na.scope == "eos"
    assert na.scope_label == "HORS PÉRIMÈTRE (driver : eos)"


def test_the_source_exclusion_carries_the_source_and_its_label():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"}, sources=["live"])
    for source, label in (("config-dir", "hors ligne"), ("snapshot", "snapshot")):
        (na,) = compliance.evaluate_config([rule], {"r1": _state()}, source=source).not_applicable
        assert na.cause == CAUSE_SOURCE and na.scope == source and na.out_of_scope
        assert na.scope_label == f"HORS PÉRIMÈTRE (source : {label})"
        assert "sources:" in na.reason and "déclarée hors périmètre" in na.reason
    assert NotApplicable(rule, "r1", "x", CAUSE_SOURCE, "live").scope_label == (
        "HORS PÉRIMÈTRE (source : en direct)"
    )


def test_a_gap_is_not_out_of_scope_and_has_no_scope_label():
    rule = Rule("r", "d", "moyenne", "all", "line_present")
    for cause in (CAUSE_NOT_IMPLEMENTED, CAUSE_NO_MODEL):
        na = NotApplicable(rule, "r1", "x", cause)
        assert not na.out_of_scope and na.scope_label is None
    assert coverage_gaps([NotApplicable(rule, "r1", "x", CAUSE_SOURCE, "config-dir")]) == []


def test_a_model_rule_without_sources_is_a_gap_offline_and_incomplete(tmp_path):
    (rule,) = compliance.load_rules(_rule_file(tmp_path, _raw(kind="interface_description_required")))
    result = compliance.evaluate_config([rule], {"r1": _state()}, offline=True)
    (na,) = result.not_applicable
    assert na.cause == CAUSE_NO_MODEL and na.scope_label is None
    assert compliance.verdict([], (), result.not_applicable) == (False, 1)
    assert compliance.status_label([], (), result.not_applicable) == compliance.STATUS_INCOMPLETE


def test_the_same_model_rule_with_sources_is_out_of_scope_offline_and_conform(tmp_path):
    (rule,) = compliance.load_rules(
        _rule_file(tmp_path, _raw(kind="interface_description_required", sources=["live", "snapshot"]))
    )
    quiet = compliance.evaluate_config([rule], {"r1": _state()}, offline=True)
    (na,) = quiet.not_applicable
    assert na.cause == CAUSE_SOURCE
    assert compliance.verdict([], (), quiet.not_applicable) == (True, 0)
    assert compliance.status_label([], (), quiet.not_applicable) == compliance.STATUS_COMPLIANT
    # Déclarer `sources:` ne dispense pas de la règle en direct : elle y est évaluée.
    assert compliance.evaluate_config([rule], {"r1": _state()}).evaluated == 1


# ------------------------------------------------------------------------------------------
# Les trois sorties LISTENT les exclusions, regroupées
# ------------------------------------------------------------------------------------------


def _scoped():
    r_model = Rule("lit-le-modele", "lit l'état", "basse", "all", "interface_description_required",
                   sources=["live", "snapshot"])
    r_srl = Rule("srl-seulement", "SR Linux", "haute", "all", "line_present", drivers=["srlinux"])
    return [
        NotApplicable(r_model, "r2", "x", CAUSE_SOURCE, "config-dir"),
        NotApplicable(r_model, "r1", "x", CAUSE_SOURCE, "config-dir"),
        NotApplicable(r_model, "r1", "x", CAUSE_SOURCE, "config-dir"),
        NotApplicable(r_srl, "r1", "x", CAUSE_DRIVER, "frr"),
        NotApplicable(r_srl, "r2", "x", CAUSE_DRIVER, "frr"),
        NotApplicable(r_srl, "r5", "x", CAUSE_DRIVER, "eos"),
    ]


def test_the_groups_are_one_line_per_rule_and_label_with_sorted_unique_devices():
    assert report.out_of_scope_groups(_scoped()) == [
        {"rule_id": "lit-le-modele", "scope": "HORS PÉRIMÈTRE (source : hors ligne)",
         "description": "lit l'état", "devices": ["r1", "r2"]},
        {"rule_id": "srl-seulement", "scope": "HORS PÉRIMÈTRE (driver : eos)", "description": "SR Linux",
         "devices": ["r5"]},
        {"rule_id": "srl-seulement", "scope": "HORS PÉRIMÈTRE (driver : frr)", "description": "SR Linux",
         "devices": ["r1", "r2"]},
    ]


def test_a_gap_never_appears_among_the_out_of_scope_groups():
    rule = Rule("r", "d", "basse", "all", "line_present")
    assert report.out_of_scope_groups([NotApplicable(rule, "r1", "x", CAUSE_NO_MODEL)]) == []
    assert report.out_of_scope_groups([]) == []


def test_the_terminal_lists_the_rule_the_label_and_all_its_devices_not_only_a_count():
    console = Console(record=True, width=200)
    report.print_compliance_terminal([], True, _scoped(), console=console)
    text = console.export_text()
    assert "HORS PÉRIMÈTRE : exclusion déclarée, sans effet sur le verdict" in text
    flat = " ".join(text.split())
    assert "lit-le-modele │ HORS PÉRIMÈTRE (source : hors ligne) │ r1, r2" in flat
    assert "srl-seulement │ HORS PÉRIMÈTRE (driver : frr) │ r1, r2" in flat
    assert "srl-seulement │ HORS PÉRIMÈTRE (driver : eos) │ r5" in flat
    assert "Conformité : CONFORME" in text and "6 non applicable(s) dont 6 hors périmètre" in flat
    assert "NON ÉVALUABLE" not in text and "NON AUDITÉ" not in text


def test_the_terminal_keeps_the_gap_table_apart_from_the_out_of_scope_one():
    rule = Rule("trou", "d", "basse", "all", "line_present")
    na = [*_scoped(), NotApplicable(rule, "r3", "pas de modèle", CAUSE_NO_MODEL)]
    console = Console(record=True, width=200)
    report.print_compliance_terminal([], False, na, console=console)
    text = console.export_text()
    assert "NON ÉVALUABLE : l'audit est incomplet" in text and "ÉTAT REQUIS (hors ligne)" in text
    assert "HORS PÉRIMÈTRE : exclusion déclarée" in text
    assert "ANALYSE INCOMPLÈTE" in text


def test_the_json_has_the_label_per_entry_and_the_compact_groups():
    data = report.compliance_to_dict([], True, not_applicable=_scoped())
    assert {e["scope"] for e in data["not_applicable"]} == {
        "HORS PÉRIMÈTRE (source : hors ligne)", "HORS PÉRIMÈTRE (driver : frr)",
        "HORS PÉRIMÈTRE (driver : eos)"}
    assert data["out_of_scope"][0]["devices"] == ["r1", "r2"]
    assert data["summary"]["not_applicable_out_of_scope"] == 6
    assert data["status"] == "CONFORME"


def test_a_gap_entry_has_a_null_scope_in_the_json():
    rule = Rule("trou", "d", "basse", "all", "line_present")
    gap = NotApplicable(rule, "r3", "x", CAUSE_NO_MODEL)
    data = report.compliance_to_dict([], False, not_applicable=[gap])
    assert data["not_applicable"][0]["scope"] is None and data["out_of_scope"] == []
    assert data["status"] == "ANALYSE INCOMPLÈTE"


def test_the_html_lists_the_groups_and_keeps_the_gaps_in_their_own_section():
    html = report.render_compliance_html([], True, "rules.yml", not_applicable=_scoped())
    assert 'id="out-of-scope"' in html and 'id="not-evaluable"' not in html
    assert "HORS PÉRIMÈTRE (source : hors ligne)" in html and "r1, r2" in html
    rule = Rule("trou", "d", "basse", "all", "line_present")
    html = report.render_compliance_html(
        [], False, "rules.yml", not_applicable=[*_scoped(), NotApplicable(rule, "r3", "x", CAUSE_NO_MODEL)]
    )
    assert 'id="not-evaluable"' in html and 'id="out-of-scope"' in html


def test_the_html_escapes_the_scope_texts():
    payload = "<script>alert(1)</script>"
    rule = Rule("<b>r</b>", payload, "basse", "all", "line_present")
    html = report.render_compliance_html(
        [], True, "rules.yml", not_applicable=[NotApplicable(rule, payload, "x", CAUSE_DRIVER, payload)]
    )
    assert payload not in html and "&lt;script&gt;" in html


# ------------------------------------------------------------------------------------------
# « Rien n'a été audité » : jamais un faux OK
# ------------------------------------------------------------------------------------------


def _audit(rules, devices, **kwargs):
    return compliance.evaluate_config(rules, devices, **kwargs)


def test_nothing_is_audited_when_every_rule_is_out_of_scope_by_driver():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "x"}, drivers=["srlinux"])
    assert compliance.nothing_audited(_audit([rule], {"r1": _state()}))


def test_nothing_is_audited_when_every_rule_is_out_of_scope_by_source():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "x"}, sources=["live"])
    assert compliance.nothing_audited(_audit([rule], {"r1": _state()}, source="config-dir"))
    assert not compliance.nothing_audited(_audit([rule], {"r1": _state()}, source="live"))


def test_nothing_is_audited_when_no_rule_concerns_any_device():
    rule = Rule("r", "d", "moyenne", ["r9"], "line_present", params={"pattern": "x"})
    assert compliance.nothing_audited(_audit([rule], {"r1": _state()}))


def test_nothing_is_audited_when_no_device_is_reachable_or_there_is_none():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "x"})
    assert compliance.nothing_audited(_audit([rule], {"r1": _state(reachable=False)}))
    assert compliance.nothing_audited(_audit([rule], {}))


def test_one_evaluated_pair_is_an_audit_even_if_the_rest_is_out_of_scope():
    in_scope = Rule("a", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"})
    out = Rule("b", "d", "moyenne", "all", "line_present", params={"pattern": "x"}, drivers=["srlinux"])
    result = _audit([in_scope, out], {"r1": _state()})
    assert result.evaluated == 1 and not compliance.nothing_audited(result)


def test_a_gap_with_nothing_evaluated_is_nothing_audited_too():
    """Une seule règle : zéro couple évalué, quelle qu'en soit la cause (ici un trou), est « rien audité »."""
    rule = Rule("r", "d", "moyenne", "all", "interface_description_required")
    result = _audit([rule], {"r1": _state()}, offline=True)
    assert result.evaluated == 0 and compliance.nothing_audited(result)
    # Le verdict seul, lui, reste « incomplet » (le code 3 est celui de la commande).
    assert compliance.verdict([], (), result.not_applicable) == (False, 1)


def _inventory(tmp_path):
    path = tmp_path / "inv.yml"
    path.write_text(
        yaml.safe_dump({"lab": True,
                        "defaults": {"device_type": "linux", "username": "u", "password": "mot-de-passe-1"},
                        "routers": {"r1": {"host": "127.0.0.1", "ospf_neighbors": 1}}}),
        encoding="utf-8")
    return str(path)


def test_check_config_dir_with_only_out_of_scope_rules_exits_3_and_writes_nothing(tmp_path, capsys):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "r1.conf").write_text(FRR_CONF, encoding="utf-8")
    rules = _rule_file(tmp_path, _raw("seulement-en-direct", sources=["live", "snapshot"]))
    out_json = tmp_path / "o.json"
    code = cli.main(["check", "--rules", str(rules), "--config-dir", str(tmp_path / "cfg"), "-i",
                     _inventory(tmp_path), "--json", str(out_json)])
    err = capsys.readouterr().err
    assert code == 3 and "rien n'a été audité" in err
    assert "seulement-en-direct HORS PÉRIMÈTRE (source : hors ligne) : r1" in err
    assert not out_json.exists()
    assert err.count("Erreur") == 1 and "Traceback" not in err


def test_check_with_only_driver_scoped_rules_exits_3(tmp_path, capsys):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "r1.conf").write_text(FRR_CONF, encoding="utf-8")
    rules = _rule_file(tmp_path, _raw("srl", drivers=["srlinux"], pattern="x"))
    code = cli.main(["check", "--rules", str(rules), "--config-dir", str(tmp_path / "cfg"), "-i",
                     _inventory(tmp_path)])
    err = capsys.readouterr().err
    assert code == 3 and "rien n'a été audité" in err and "HORS PÉRIMÈTRE (driver : frr)" in err


def test_check_snapshot_with_an_empty_snapshot_exits_3(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(snapshot, "load", lambda name: {})
    code = cli.main(["check", "--snapshot", "vide", "--rules", str(RULES / "security.yml"), "-i",
                     _inventory(tmp_path)])
    assert code == 3 and "rien n'a été audité" in capsys.readouterr().err


def test_check_snapshot_runs_with_the_snapshot_source(tmp_path, capsys, monkeypatch):
    """Une règle déclarée `sources: [live]` n'est PAS évaluée sur un snapshot : hors périmètre (snapshot)."""
    monkeypatch.setattr(snapshot, "load", lambda name: {"r1": _state()})
    rules = _rule_file(tmp_path, _raw("a"), _raw("b", sources=["live"]), _raw("c", sources=["snapshot"]))
    out_json = tmp_path / "o.json"
    code = cli.main(["check", "--snapshot", "s", "--rules", str(rules), "-i", _inventory(tmp_path),
                     "--json", str(out_json)])
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert code == 0 and data["status"] == "CONFORME"
    assert data["out_of_scope"] == [{"rule_id": "b", "scope": "HORS PÉRIMÈTRE (source : snapshot)",
                                     "description": "d", "devices": ["r1"]}]
    capsys.readouterr()


def test_check_with_one_evaluated_rule_is_not_refused(tmp_path, capsys):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "r1.conf").write_text(FRR_CONF, encoding="utf-8")
    rules = _rule_file(tmp_path, _raw("a"), _raw("b", sources=["live"]))
    out_json = tmp_path / "o.json"
    code = cli.main(["check", "--rules", str(rules), "--config-dir", str(tmp_path / "cfg"), "-i",
                     _inventory(tmp_path), "--json", str(out_json)])
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert code == 0 and data["status"] == "CONFORME"
    assert [g["rule_id"] for g in data["out_of_scope"]] == ["b"]
    capsys.readouterr()


def test_monitor_never_counts_an_audit_that_evaluated_nothing_as_ok():
    rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "x"}, drivers=["srlinux"])
    state = _state()
    ev = monitor.evaluate({"r1": (True, state)}, {"r1": state}, set(), None, [rule])
    assert ev.components["check"] == monitor.ATTENTION and ev.status == monitor.ATTENTION
    assert any(c.category == "rien-audite" and c.device == "*" for c in ev.contributions)
    ok_rule = Rule("r", "d", "moyenne", "all", "line_present", params={"pattern": "hostname"})
    clean = monitor.evaluate({"r1": (True, state)}, {"r1": state}, set(), None, [ok_rule])
    assert clean.components["check"] == monitor.OK


# ------------------------------------------------------------------------------------------
# Les fichiers de règles du dépôt
# ------------------------------------------------------------------------------------------


def test_only_the_two_rules_that_read_the_collected_state_declare_sources():
    declared = {}
    for name in ("default", "security", "security-ipv6"):
        for rule in compliance.load_rules(RULES / f"{name}.yml"):
            if rule.sources is not None:
                declared[rule.id] = rule.sources
    assert declared == {
        "interface-avec-description": ["live", "snapshot"],
        "lan-en-ospf-passif": ["live", "snapshot"],
    }


def test_every_rule_that_reads_the_model_declares_sources_in_the_shipped_rule_files():
    """Sans déclaration, une règle qui lit l'état collecté ferait de `--config-dir` une alarme permanente."""
    for name in ("default", "security", "security-ipv6"):
        for rule in compliance.load_rules(RULES / f"{name}.yml"):
            for driver in compliance.KNOWN_DRIVERS if rule.drivers is None else rule.drivers:
                check = compliance.resolve_check(rule.kind, driver)
                if check is not None and "interfaces" in check.needs:
                    assert rule.sources is not None and "config-dir" not in rule.sources, (name, rule.id)


# ------------------------------------------------------------------------------------------
# Une seule règle : 0 couple évalué = 3 (avec TOUTES les causes) ; ≥ 1 évalué avec des trous = 1 ; tout = 0
# ------------------------------------------------------------------------------------------


def _live(tmp_path, monkeypatch, collected, routers=("r1", "r2")):
    """Un `check` en direct dont la collecte est simulée : {nom: (True, état) | (False, erreur)}."""
    inv = tmp_path / "live.yml"
    inv.write_text(
        yaml.safe_dump({"lab": True,
                        "defaults": {"device_type": "linux", "username": "u", "password": "mot-de-passe-1"},
                        "routers": {name: {"host": f"127.0.0.{i + 1}", "ospf_neighbors": 1}
                                    for i, name in enumerate(routers)}}),
        encoding="utf-8")
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "kh"))
    monkeypatch.setattr(hostkeys, "_policy", None)
    monkeypatch.setattr(collector, "collect_all", lambda inventory_routers, driver=None: collected)
    return str(inv)


def _run(argv, tmp_path, capsys):
    out_json = tmp_path / "o.json"
    code = cli.main([*argv, "--json", str(out_json)])
    data = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else None
    return code, data, capsys.readouterr().err


def test_live_check_where_no_device_is_reachable_is_code_3_and_names_them(tmp_path, monkeypatch, capsys):
    """Le faux OK préexistant : tous les équipements injoignables sortaient CONFORME (0)."""
    inv = _live(tmp_path, monkeypatch, {"r1": (False, "délai dépassé"), "r2": (False, "refusé")})
    rules = _rule_file(tmp_path, _raw("a"))
    code, data, err = _run(["check", "-i", inv, "--rules", str(rules)], tmp_path, capsys)
    assert code == 3 and data is None
    assert "rien n'a été audité" in err and "équipement(s) injoignable(s) : r1, r2" in err
    assert "non évaluable" not in err and "ÉQUIPEMENT INJOIGNABLE" not in err   # dite une seule fois
    assert err.count("Erreur") == 1 and "Traceback" not in err


def test_live_check_where_one_device_is_unreachable_is_code_1_not_0(tmp_path, monkeypatch, capsys):
    inv = _live(tmp_path, monkeypatch, {"r1": (True, _state("r1")), "r2": (False, "délai dépassé")})
    rules = _rule_file(tmp_path, _raw("a"))
    code, data, _ = _run(["check", "-i", inv, "--rules", str(rules)], tmp_path, capsys)
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE" and data["violations"] == []
    gaps = [n for n in data["not_applicable"] if n["cause"] == "unreachable"]
    assert [(n["device"], n["rule_id"], n["scope"]) for n in gaps] == [("r2", "a", None)]
    assert data["summary"]["not_applicable_unreachable"] == 1


def test_live_check_where_everything_is_evaluated_and_conform_is_code_0(tmp_path, monkeypatch, capsys):
    inv = _live(tmp_path, monkeypatch, {"r1": (True, _state("r1")), "r2": (True, _state("r2"))})
    rules = _rule_file(tmp_path, _raw("a"))
    code, data, _ = _run(["check", "-i", inv, "--rules", str(rules)], tmp_path, capsys)
    assert code == 0 and data["status"] == "CONFORME" and data["not_applicable"] == []


def test_a_real_violation_keeps_code_2_even_with_an_unreachable_device(tmp_path, monkeypatch, capsys):
    inv = _live(tmp_path, monkeypatch, {"r1": (True, _state("r1")), "r2": (False, "refusé")})
    rules = _rule_file(tmp_path, _raw("a", severity="haute", pattern="^jamais-present$"))
    code, data, _ = _run(["check", "-i", inv, "--rules", str(rules)], tmp_path, capsys)
    assert code == 2 and [v["device"] for v in data["violations"]] == ["r1"]


def test_a_snapshot_whose_only_device_was_unreachable_is_code_3(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(snapshot, "load", lambda name: {"r1": _state("r1", reachable=False)})
    rules = _rule_file(tmp_path, _raw("a"))
    code, data, err = _run(["check", "--snapshot", "s", "-i", _inventory(tmp_path), "--rules", str(rules)],
                           tmp_path, capsys)
    assert code == 3 and data is None and "équipement(s) injoignable(s) : r1" in err


def test_an_empty_snapshot_is_code_3_and_says_the_source_is_empty(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(snapshot, "load", lambda name: {})
    rules = _rule_file(tmp_path, _raw("a"))
    code, _, err = _run(["check", "--snapshot", "s", "-i", _inventory(tmp_path), "--rules", str(rules)],
                        tmp_path, capsys)
    assert code == 3 and "la source ne contient aucun équipement" in err


def test_rules_that_concern_no_device_are_code_3_and_are_named(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(snapshot, "load", lambda name: {"r1": _state("r1")})
    rules = _rule_file(tmp_path, _raw("pour-r9", applies_to=["r9"]), _raw("pour-r8", applies_to=["r8"]))
    code, _, err = _run(["check", "--snapshot", "s", "-i", _inventory(tmp_path), "--rules", str(rules)],
                        tmp_path, capsys)
    assert code == 3 and "règle(s) qui ne concernent aucun équipement : pour-r9, pour-r8" in err


def test_a_model_rule_alone_offline_is_code_3_and_names_the_gap(tmp_path, capsys):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "r1.conf").write_text(FRR_CONF, encoding="utf-8")
    rules = _rule_file(tmp_path, _raw("lit-le-modele", kind="interface_description_required"))
    code, _, err = _run(["check", "--config-dir", str(tmp_path / "cfg"), "-i", _inventory(tmp_path),
                         "--rules", str(rules)], tmp_path, capsys)
    assert code == 3 and "non évaluable : lit-le-modele ÉTAT REQUIS (hors ligne) : r1" in err


def test_a_rule_the_driver_cannot_evaluate_alone_is_code_3_and_names_the_gap(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(snapshot, "load", lambda name: {"r1": _state("r1")})
    monkeypatch.setattr(compliance, "resolve_check", lambda kind, driver: None)
    rules = _rule_file(tmp_path, _raw("sans-driver"))
    code, _, err = _run(["check", "--snapshot", "s", "-i", _inventory(tmp_path), "--rules", str(rules)],
                        tmp_path, capsys)
    assert code == 3 and "non évaluable : sans-driver NON IMPLÉMENTÉ : r1" in err


def test_the_message_lists_every_cause_at_once(tmp_path, monkeypatch, capsys):
    states = {"r1": _state("r1"), "r2": _state("r2", reachable=False)}
    monkeypatch.setattr(snapshot, "load", lambda name: states)
    rules = _rule_file(tmp_path, _raw("pour-srl", drivers=["srlinux"]), _raw("live", sources=["live"]),
                       _raw("pour-r9", applies_to=["r9"]))
    code, _, err = _run(["check", "--snapshot", "s", "-i", _inventory(tmp_path), "--rules", str(rules)],
                        tmp_path, capsys)
    assert code == 3
    causes = (
        "équipement(s) injoignable(s) : r2",
        "hors périmètre : ",
        "pour-srl HORS PÉRIMÈTRE (driver : frr)",
        "live HORS PÉRIMÈTRE (source : snapshot) : r1",
        "règle(s) qui ne concernent aucun équipement",
    )
    for cause in causes:
        assert cause in err, cause


def test_the_decision_is_one_rule_zero_evaluated_is_3_some_evaluated_with_gaps_is_1_all_conform_is_0():
    unreachable_only = _audit([Rule("a", "d", "basse", "all", "line_present", params={"pattern": "x"})],
                              {"r1": _state("r1", reachable=False)})
    assert (unreachable_only.evaluated, compliance.nothing_audited(unreachable_only)) == (0, True)
    rule = Rule("a", "d", "basse", "all", "line_present", params={"pattern": "hostname"})
    some = _audit([rule], {"r1": _state("r1"), "r2": _state("r2", reachable=False)})
    assert some.evaluated == 1 and not compliance.nothing_audited(some)
    assert compliance.verdict(some.violations, (), some.not_applicable) == (False, 1)
    full = _audit([rule], {"r1": _state("r1"), "r2": _state("r2")})
    assert full.evaluated == 2 and compliance.verdict(full.violations, (), full.not_applicable) == (True, 0)


def _unreachable_scenario():
    rule = Rule("a", "d", "basse", "all", "line_present")
    scoped = Rule("b", "d", "basse", "all", "line_present", sources=["live"])
    return [
        NotApplicable(rule, "r2", "équipement injoignable (délai dépassé)", CAUSE_UNREACHABLE),
        NotApplicable(scoped, "r1", "x", CAUSE_SOURCE, "config-dir"),
        NotApplicable(scoped, "r3", "x", CAUSE_DRIVER, "eos"),
    ]


def test_an_unreachable_device_is_counted_apart_in_the_summary():
    summary = report.compliance_to_dict([], False, not_applicable=_unreachable_scenario())["summary"]
    assert summary["not_applicable"] == 3
    assert summary["not_applicable_unreachable"] == 1 and summary["not_applicable_out_of_scope"] == 2
    assert summary["not_applicable_not_implemented"] == 0 and summary["not_applicable_no_model"] == 0


def test_an_unreachable_device_is_labelled_in_the_terminal_and_the_html_and_makes_the_audit_incomplete():
    na = _unreachable_scenario()
    console = Console(record=True, width=200)
    report.print_compliance_terminal([], False, na, console=console)
    text = console.export_text()
    flat = " ".join(text.split())
    assert "ÉQUIPEMENT INJOIGNABLE" in text and "ANALYSE INCOMPLÈTE" in text
    assert "dont 1 sur équipement(s) injoignable(s)" in flat and "dont 2 hors périmètre" in flat
    html = report.render_compliance_html([], False, "rules.yml", not_applicable=na)
    assert "ÉQUIPEMENT INJOIGNABLE" in html and 'id="not-evaluable"' in html and "ANALYSE INCOMPLÈTE" in html
