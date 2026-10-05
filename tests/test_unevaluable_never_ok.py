"""Phase C6 (décision de la revue) : un résultat avec des parties NON ÉVALUABLES ne sort JAMAIS en code 0.

État des lieux AVANT ce changement, commande par commande (mesuré, voir le CHANGELOG) :
- `assert` : NON ÉVALUABLE n'y changeait rien (code 0) ;
- `check` : une règle non évaluable (trou de couverture, état absent hors ligne) donnait CONFORME / 0 ;
- `diff` : une section relevée d'un seul côté était une simple information (code 0) ;
- `monitor` : le composant assert comptait déjà NON ÉVALUABLE en ATTENTION, pas le composant check ;
- `guard` : un équipement sans attendus locaux était ignoré en silence par le calcul de convergence.

Ce fichier prouve le comportement corrigé. Le gel des verdicts (tests/golden/) ne bouge pas : il enregistre la
réponse du MOTEUR (`compliance.verdict(violations)` sans règle non applicable).
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import yaml

from netcheck import cli, collector, compliance, guard, hostkeys, inventory, monitor, snapshot
from netcheck.assertions import AssertionResult, Status
from netcheck.diff import Finding, Severity
from netcheck.guard import DiffResult, GuardIO, Journal, ScriptResult, SnapshotNames
from netcheck.model import DeviceState, Interface
from netcheck.ruletypes import (
    CAUSE_DRIVER,
    CAUSE_NO_MODEL,
    CAUSE_NOT_IMPLEMENTED,
    CAUSE_SOURCE,
    CAUSE_UNREACHABLE,
    GAP_CAUSES,
    NotApplicable,
    Rule,
    coverage_gaps,
)

ROOT = Path(__file__).resolve().parent.parent


def _rule(severity):
    return Rule(
        id="r",
        description="d",
        severity=severity,
        applies_to="all",
        kind="line_present",
        params={"pattern": "x"},
    )


def na(cause, device="r1"):
    return NotApplicable(_rule("moyenne"), device, "raison", cause)


# === 1. règles de conformité : verdict, libellé, JSON =============================================


def test_only_the_missing_data_causes_are_gaps():
    assert set(GAP_CAUSES) == {CAUSE_NOT_IMPLEMENTED, CAUSE_NO_MODEL, CAUSE_UNREACHABLE}
    assert coverage_gaps([na(CAUSE_DRIVER), na(CAUSE_SOURCE)]) == []
    causes = [na(CAUSE_NOT_IMPLEMENTED), na(CAUSE_NO_MODEL), na(CAUSE_UNREACHABLE), na(CAUSE_DRIVER)]
    assert len(coverage_gaps(causes)) == 3


@pytest.mark.parametrize(
    ("not_applicable", "expected"),
    [
        ([], (True, 0)),
        ([na(CAUSE_DRIVER)], (True, 0)),  # hors périmètre de la règle : un choix, pas un manque
        ([na(CAUSE_NOT_IMPLEMENTED)], (False, 1)),
        ([na(CAUSE_NO_MODEL)], (False, 1)),
        ([na(CAUSE_UNREACHABLE)], (False, 1)),
        ([na(CAUSE_SOURCE)], (True, 0)),  # hors périmètre déclaré : un choix, comme « driver »
        ([na(CAUSE_DRIVER), na(CAUSE_NO_MODEL)], (False, 1)),
    ],
)
def test_a_rule_that_could_not_be_evaluated_is_never_code_0(not_applicable, expected):
    assert compliance.verdict([], (), not_applicable) == expected


def test_the_verdict_without_the_new_argument_is_unchanged_for_the_freeze():
    assert compliance.verdict([]) == (True, 0)  # tests/tools/golden.py appelle ainsi : le gel ne bouge pas


def test_a_real_violation_keeps_its_own_code_whatever_the_gaps():
    high, low = _rule("haute"), _rule("basse")
    from netcheck.ruletypes import Violation

    assert compliance.verdict([Violation(high, "r1", "x")], (), [na(CAUSE_NO_MODEL)]) == (False, 2)
    assert compliance.verdict([Violation(low, "r1", "x")], (), [na(CAUSE_NO_MODEL)]) == (False, 1)


def test_the_label_says_incomplete_analysis_not_compliant_and_not_non_compliant():
    assert compliance.status_label([], (), [na(CAUSE_NO_MODEL)]) == compliance.STATUS_INCOMPLETE
    assert compliance.status_label([], (), [na(CAUSE_NOT_IMPLEMENTED)]) == compliance.STATUS_INCOMPLETE
    assert compliance.status_label([], (), [na(CAUSE_DRIVER)]) == compliance.STATUS_COMPLIANT
    assert compliance.status_label([], (), []) == compliance.STATUS_COMPLIANT


def _check(args, tmp_path, capsys, rules="default"):
    out_json, out_html = tmp_path / "r.json", tmp_path / "r.html"
    rules_path = rules if rules.endswith(".yml") else str(ROOT / "netcheck" / "rules" / f"{rules}.yml")
    code = cli.main(["check", *args, "--rules", rules_path, "--json", str(out_json), "--html", str(out_html)])
    return (
        code,
        json.loads(out_json.read_text(encoding="utf-8")),
        out_html.read_text(encoding="utf-8"),
        capsys.readouterr(),
    )


def _offline(directory, inventory_file):
    return ["--config-dir", str(ROOT / directory), "-i", str(ROOT / "automation" / inventory_file)]


def _default_without_sources(tmp_path) -> str:
    """default.yml sans `sources:` : ses règles qui lisent l'état collecté y sont des trous hors ligne."""
    data = yaml.safe_load((ROOT / "netcheck" / "rules" / "default.yml").read_text(encoding="utf-8"))
    for rule in data["rules"]:
        rule.pop("sources", None)
    path = tmp_path / "default-sans-sources.yml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return str(path)


def test_the_offline_audit_of_the_repository_configurations_is_incomplete_and_says_why(tmp_path, capsys):
    code, data, html, out = _check(_offline("configs", "inventory.yml"), tmp_path, capsys,
                                   rules=_default_without_sources(tmp_path))
    text = " ".join(out.out.split())
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE" and data["compliant"] is False
    assert data["violations"] == []
    assert {n["cause"] for n in data["not_applicable"]} >= {"no_model"}
    assert "Conformité : ANALYSE INCOMPLÈTE" in text and "non évaluable(s) hors ligne" in text
    assert "ANALYSE INCOMPLÈTE" in html


def test_the_security_rules_have_nothing_non_evaluable_offline_and_stay_code_0(tmp_path, capsys):
    code, data, _, _ = _check(_offline("configs", "inventory.yml"), tmp_path, capsys, rules="security")
    assert code == 0 and data["status"] == "CONFORME" and data["compliant"] is True
    assert not [n for n in data["not_applicable"] if n["cause"] in GAP_CAUSES]


def test_a_live_audit_with_a_rule_the_driver_cannot_evaluate_is_never_code_0(tmp_path, capsys, monkeypatch):
    path = tmp_path / "inv.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "lab": True,
                "defaults": {"device_type": "linux", "username": "u", "password": "mot-de-passe-1"},
                "routers": {"r1": {"host": "127.0.0.1", "ospf_neighbors": 1}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "kh"))
    monkeypatch.setattr(hostkeys, "_policy", None)
    state = DeviceState(
        name="r1", host="127.0.0.1", timestamp="t", reachable=True, running_config="hostname r1\n"
    )
    monkeypatch.setattr(collector, "collect_all", lambda routers, driver=None: {"r1": (True, state)})
    rules = tmp_path / "rules.yml"
    rules.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "nom",
                        "description": "d",
                        "severity": "basse",
                        "applies_to": "all",
                        "kind": "line_present",
                        "pattern": "^hostname r1$",
                    },
                    {
                        "id": "absente",
                        "description": "d",
                        "severity": "basse",
                        "applies_to": "all",
                        "kind": "line_absent",
                        "pattern": "^zzz$",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    code, data, _, _ = _check(["-i", str(path)], tmp_path, capsys, rules=str(rules))
    assert code == 0 and data["status"] == "CONFORME"  # contrôle : sans trou, tout va bien
    real = compliance.resolve_check
    monkeypatch.setattr(compliance, "resolve_check",
                        lambda kind, driver: None if kind == "line_absent" else real(kind, driver))
    code, data, _, _ = _check(["-i", str(path)], tmp_path, capsys, rules=str(rules))
    # Un couple évalué, un trou : 1 (jamais 0).
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE"
    assert {n["cause"] for n in data["not_applicable"]} == {"not_implemented"}


# === 2. assert ====================================================================================


def _result(status):
    from netcheck.assertions import Assertion

    return AssertionResult(Assertion("a", "d", "r1", "interface_up", {"interface": "eth1"}), status)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], ("OK", 0)),
        ([Status.OK, Status.OK], ("OK", 0)),
        ([Status.NON_EVALUABLE], ("ATTENTION", 1)),
        ([Status.OK, Status.NON_EVALUABLE], ("ATTENTION", 1)),
        ([Status.ECHEC, Status.NON_EVALUABLE], ("ÉCHEC", 2)),
        ([Status.ECHEC], ("ÉCHEC", 2)),
    ],
)
def test_assert_verdict_never_says_ok_with_a_non_evaluable_part(statuses, expected):
    from netcheck.assertions import verdict

    assert verdict([_result(s) for s in statuses]) == expected


def _snapshot_with_one_unreachable(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    up = Interface(name="eth1", description=None, admin_up=True, oper_up=True)
    r1 = DeviceState(name="r1", host="10.0.0.1", timestamp="t", reachable=True, interfaces=[up])
    snapshot.save("base", {"r1": (True, r1), "r2": (False, "injoignable")})


INTENT = """assertions:
  - {id: eth1-r1, description: "r1 eth1 up", device: r1, type: interface_up, interface: eth1}
%s
"""


def test_assert_cli_is_code_1_attention_when_a_device_is_unreachable_and_nothing_else_fails(
    tmp_path, monkeypatch, capsys
):
    _snapshot_with_one_unreachable(tmp_path, monkeypatch)
    intent = tmp_path / "i.yml"
    intent.write_text(
        INTENT % "  - {id: eth1-r2, description: x, device: r2, type: interface_up, interface: eth1}",
        encoding="utf-8",
    )
    out_json = tmp_path / "a.json"
    code = cli.main(
        [
            "assert",
            "--intent",
            str(intent),
            "--snapshot",
            "base",
            "--json",
            str(out_json),
            "--html",
            str(tmp_path / "a.html"),
        ]
    )
    text = " ".join(capsys.readouterr().out.split())
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert code == 1 and data["verdict"] == "ATTENTION"
    assert {r["status"] for r in data["results"]} == {"OK", "NON ÉVALUABLE"}
    assert "Verdict : ATTENTION" in text and "ATTENTION" in (tmp_path / "a.html").read_text(encoding="utf-8")


def test_assert_cli_is_still_code_0_when_everything_is_evaluable_and_ok(tmp_path, monkeypatch, capsys):
    _snapshot_with_one_unreachable(tmp_path, monkeypatch)
    intent = tmp_path / "i.yml"
    intent.write_text(INTENT % "", encoding="utf-8")
    assert cli.main(["assert", "--intent", str(intent), "--snapshot", "base"]) == 0


# === 3. diff ======================================================================================


def test_a_section_collected_on_one_side_only_is_attention_not_information():
    from netcheck import diff

    findings = [Finding(Severity.ATTENTION, "section", "r1", "sections non comparées")]
    assert diff.verdict(findings) == ("ATTENTION", 1)
    source = (ROOT / "netcheck" / "diff.py").read_text(encoding="utf-8")
    assert (
        'Severity.INFO, "section"' not in source
    )  # l'information « relevées seulement après » n'existe plus


# === 4. monitor ===================================================================================


def test_monitor_check_component_counts_a_non_evaluable_rule_as_attention():
    status, contributions = monitor.check_outcome(
        [], (), [na(CAUSE_NOT_IMPLEMENTED), na(CAUSE_NO_MODEL, "r2")]
    )
    assert status == monitor.ATTENTION
    assert [(c.device, c.category) for c in contributions] == [
        ("r1", "regles-non-evaluables"),
        ("r2", "regles-non-evaluables"),
    ]
    assert all("règle(s) non évaluable(s)" in c.message for c in contributions)


def test_monitor_ignores_rules_that_are_out_of_scope_by_choice():
    assert monitor.check_outcome([], (), [na(CAUSE_DRIVER)]) == (monitor.OK, [])
    assert monitor.check_outcome([], (), []) == (monitor.OK, [])


def _state(name="r1"):
    return DeviceState(
        name=name, host="10.0.0.1", timestamp="t", reachable=True, running_config="hostname r1\n"
    )


def test_a_monitor_evaluation_with_a_rule_the_driver_cannot_evaluate_is_attention_end_to_end(monkeypatch):
    """Toute la chaîne : monitor.evaluate -> audit -> check_outcome -> statut global (jamais OK)."""
    rule = Rule(
        id="nom",
        description="d",
        severity="basse",
        applies_to="all",
        kind="line_present",
        params={"pattern": "^hostname r1$"},
    )
    absent = Rule(id="absente", description="d", severity="basse", applies_to="all", kind="line_absent",
                  params={"pattern": "^zzz$"})
    results = {"r1": (True, _state())}
    clean = monitor.evaluate(results, {"r1": _state()}, set(), None, [rule, absent])
    assert clean.status == monitor.OK and clean.compliant is True
    real = compliance.resolve_check
    monkeypatch.setattr(compliance, "resolve_check",
                        lambda kind, driver: None if kind == "line_absent" else real(kind, driver))
    gap = monitor.evaluate(results, {"r1": _state()}, set(), None, [rule, absent])
    assert gap.status == monitor.ATTENTION and gap.compliant is False
    assert gap.components["check"] == monitor.ATTENTION
    assert [c.category for c in gap.contributions] == ["regles-non-evaluables"]


def test_monitor_assert_component_already_gave_attention_and_still_does():
    status, _ = monitor.assert_outcome([_result(Status.NON_EVALUABLE)])
    assert status == monitor.ATTENTION


# === 5. guard : option C ==========================================================================


def test_without_expectations_lists_every_router_with_none_of_the_four_keys():
    routers = {
        "r1": {"ospf_neighbors": 2},
        "r2": {"bgp_peers": {}},
        "r3": {"ospf_neighbors": 0},  # une valeur à 0 est un attendu ÉCRIT
        "r6": {"host": "10.0.0.6"},
        "r7": {},
        "r5": {"bgp6_peers": {"2001:db8::1": 1}},
        "r4": {"ospf6_neighbors": 1},
    }
    assert inventory.without_expectations(routers) == ["r6", "r7"]


def test_the_keys_are_exactly_those_the_convergence_wait_reads():
    source = (ROOT / "netcheck" / "collector.py").read_text(encoding="utf-8")
    body = source.split("def _converged")[1].split("def wait_for_convergence")[0]
    assert all(f'"{key}"' in body for key in inventory.EXPECTATION_KEYS)
    assert len(inventory.EXPECTATION_KEYS) == 4


@pytest.mark.parametrize("name", ["inventory.yml", "inventory-multivendor.yml", "inventory-ceos.yml"])
def test_the_three_lab_inventories_have_expectations_for_every_router(name):
    inv = inventory.load(path=ROOT / "automation" / name, resolve_credentials=False)
    assert inventory.without_expectations(inv.routers) == []


INVENTORY = {
    "lab": True,
    "defaults": {"device_type": "linux", "username": "u", "password": "mot-de-passe-1"},
    "routers": {
        "r1": {"host": "10.0.0.1", "ospf_neighbors": 1},
        "r6": {"host": "10.0.0.6"},
        "r7": {"host": "10.0.0.7"},
    },
}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    path = tmp_path / "inv.yml"
    path.write_text(yaml.safe_dump(INVENTORY), encoding="utf-8")
    marker = tmp_path / "executed"
    script = tmp_path / "change.sh"
    script.write_text(f"touch {marker}\n", encoding="utf-8")
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(guard, "PROOF_POLL_SECONDS", 0.01)
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "kh"))
    monkeypatch.setattr(hostkeys, "_policy", None)
    seen = {"collected": [], "waited": []}

    def collect(routers, driver=None, workers=5):
        seen["collected"].append(sorted(routers))
        return {
            n: (True, DeviceState(name=n, host=r["host"], timestamp="t", reachable=True))
            for n, r in routers.items()
        }

    def wait(routers, driver=None, *, timeout, interval=2.0):
        seen["waited"].append(sorted(routers))
        return True

    monkeypatch.setattr(collector, "collect_all", collect)
    monkeypatch.setattr(collector, "wait_for_convergence", wait)
    return {"inv": str(path), "marker": marker, "script": str(script), "seen": seen, "tmp": tmp_path}


def _guard(lab, *extra):
    return cli.main(["guard", "--change", lab["script"], "--yes", "--wait", "1", "-i", lab["inv"], *extra])


def test_guard_refuses_before_running_anything_and_lists_every_device_without_expectations(lab, capsys):
    code = _guard(lab)
    err = " ".join(capsys.readouterr().err.split())
    assert code == 3
    assert "2 équipement(s) du périmètre sans attendus locaux" in err and "r6, r7" in err
    assert "--accept-unverified r6,r7" in err and "jamais OK" in err and "Aucun script n'a été exécuté" in err
    assert not lab["marker"].exists()
    assert lab["seen"]["collected"] == [] and not (lab["tmp"] / "snaps").exists()
    assert not (lab["tmp"] / "reports").exists()  # pas même un journal


def test_the_refusal_comes_before_the_confirmation_and_before_the_scripts_are_shown(lab, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("aucune confirmation avant le refus"))
    code = cli.main(["guard", "--change", lab["script"], "-i", lab["inv"]])
    captured = capsys.readouterr()
    assert code == 3 and "Scripts qui vont être exécutés" not in captured.out


@pytest.mark.parametrize(
    ("option", "fragment"),
    [
        ("*", "pas de joker"),
        ("all", "pas de joker"),
        ("ALL", "pas de joker"),
        ("tous", "pas de joker"),
        ("r6,*", "pas de joker"),
        ("r6,", "nom vide"),
        ("r6,,r7", "nom vide"),
        ("", "nom vide"),
        ("r6, r7", "refusé"),
        ("r6;r7", "refusé"),
        ("r?", "refusé"),
        ("r[67]", "refusé"),
        ("../x", "refusé"),
        ("r6,r6,r7", "en double"),
        ("r9", "inconnu(s) ou absent(s) du périmètre"),
        ("r6,r7,r9", "inconnu(s) ou absent(s) du périmètre"),
        ("r1,r6,r7", "déjà des attendus locaux"),
        ("r1", "déjà des attendus locaux"),
    ],
)
def test_the_opt_in_takes_explicit_names_only_and_refuses_everything_else(lab, capsys, option, fragment):
    code = _guard(lab, "--accept-unverified", option)
    err = " ".join(capsys.readouterr().err.split())
    assert code == 3 and fragment in err
    assert not lab["marker"].exists() and lab["seen"]["collected"] == []


def test_a_partial_opt_in_still_refuses_and_names_the_device_left_out(lab, capsys):
    code = _guard(lab, "--accept-unverified", "r6")
    err = " ".join(capsys.readouterr().err.split())
    assert code == 3 and "1 équipement(s) du périmètre sans attendus locaux" in err
    assert "attendus locaux (ospf_neighbors, ospf6_neighbors, bgp_peers, bgp6_peers) : r7." in err
    assert "--accept-unverified r7" in err and "--accept-unverified r6,r7" not in err
    assert not lab["marker"].exists()


def test_with_the_opt_in_guard_runs_excludes_them_from_convergence_and_is_never_code_0(lab, capsys):
    code = _guard(lab, "--accept-unverified", "r6,r7")
    out = " ".join(capsys.readouterr().out.split())
    assert lab["marker"].exists()  # le changement a été exécuté
    assert code == 1  # le diff est vide (verdict OK) : le verdict final n'est JAMAIS 0 pour autant
    assert "Équipements acceptés SANS vérification de convergence (--accept-unverified) : r6, r7" in out
    assert "convergence NON vérifiée (--accept-unverified) pour : r6, r7" in out
    assert "CHANGEMENT TERMINÉ AVEC ATTENTION" in out and "CHANGEMENT RÉUSSI" not in out
    seen = lab["seen"]
    assert seen["waited"] and all(
        names == ["r1"] for names in seen["waited"]
    )  # hors du calcul de convergence
    assert all(names == ["r1", "r6", "r7"] for names in seen["collected"])  # mais présents dans les snapshots
    journal = json.loads(next((lab["tmp"] / "reports").glob("guard_*.json")).read_text(encoding="utf-8"))
    assert journal["options"]["accept_unverified"] == ["r6", "r7"]
    assert journal["final_state"] == "ATTENTION" and journal["outcome_details"]["unverified"] == ["r6", "r7"]


def test_without_any_gap_nothing_changes_for_guard(lab, tmp_path, capsys):
    data = {**INVENTORY, "routers": {"r1": {"host": "10.0.0.1", "ospf_neighbors": 1}}}
    path = tmp_path / "ok.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert cli.main(["guard", "--change", lab["script"], "--yes", "--wait", "1", "-i", str(path)]) == 0
    assert "CHANGEMENT RÉUSSI" in capsys.readouterr().out


# --- run_guard : la table des issues avec des équipements non vérifiés ----------------------------

CLEAN = DiffResult([], "OK", 0)
ATTENTION = DiffResult([Finding(Severity.ATTENTION, "metric", "r1", "métrique modifiée")], "ATTENTION", 1)
BROKEN = DiffResult([Finding(Severity.CRITIQUE, "ospf_neighbor", "r1", "voisin OSPF perdu")], "ÉCHEC", 2)
NAMES = SnapshotNames("g_avant", "g_apres", "g_retour")


class _UI(guard.UI):
    def __init__(self):
        self.finals = []

    def info(self, message):
        pass

    def script_output(self, line):
        pass

    def show_diff(self, result):
        pass

    def final(self, state, code, details):
        self.finals.append((state, code, details))


def _run(tmp_path, after, change_rc=0, unverified=(), rollback=False):
    change = tmp_path / "change.sh"
    change.write_text("true\n", encoding="utf-8")
    io_ = GuardIO(
        snapshot=lambda name: None,
        wait_convergence=lambda t: True,
        diff=lambda before, after_name, use_expect: after if after_name == NAMES.after else CLEAN,
        run_script=lambda path, timeout: ScriptResult(rc=change_rc),
        sleep=lambda s: None,
        clock=lambda: 0.0,
    )
    journal = Journal(
        tmp_path / "j.json", {"change_script": guard.script_record(change), "rollback_script": None}
    )
    ui = _UI()
    result = guard.run_guard(
        change=change,
        rollback=change if rollback else None,
        rollback_on="echec",
        wait=1,
        script_timeout=1,
        io=io_,
        ui=ui,
        journal=journal,
        names=NAMES,
        unverified=unverified,
    )
    return result, ui


@pytest.mark.parametrize(
    ("after", "change_rc", "expected"),
    [
        (CLEAN, 0, ("ATTENTION", 1)),  # un OK devient ATTENTION
        (ATTENTION, 0, ("ATTENTION", 1)),
        (BROKEN, 0, ("FAILED_NO_ROLLBACK", 2)),  # un échec reste un échec
        (CLEAN, 9, ("FAILED_NO_ROLLBACK", 2)),
    ],
)
def test_run_guard_with_unverified_devices_is_never_a_success(tmp_path, after, change_rc, expected):
    result, ui = _run(tmp_path, after, change_rc, unverified=("r6",))
    assert (result.state, result.code) == expected
    assert ui.finals[0][2].get("unverified") == ["r6"]


def test_run_guard_without_unverified_devices_keeps_its_success(tmp_path):
    result, ui = _run(tmp_path, CLEAN)
    assert (result.state, result.code) == ("SUCCESS", 0) and "unverified" not in ui.finals[0][2]


def test_a_rollback_outcome_is_not_downgraded_by_the_opt_in(tmp_path):
    result, _ = _run(tmp_path, BROKEN, unverified=("r6",), rollback=True)
    assert result.code in (4, 5) and result.state in ("ROLLED_BACK", "ROLLBACK_FAILED")


# === 6. l'ordre des vérifications de guard : refus avant tout, y compris avant le délai ===========


def test_the_refusal_happens_even_with_assume_yes_and_a_rollback_script(lab, capsys):
    rollback = lab["tmp"] / "rb.sh"
    rollback.write_text("true\n", encoding="utf-8")
    code = _guard(lab, "--rollback", str(rollback))
    assert code == 3 and not lab["marker"].exists()


def test_closed_stdin_still_reaches_the_confirmation_when_every_device_has_expectations(
    lab, tmp_path, capsys, monkeypatch
):
    data = {**INVENTORY, "routers": {"r1": {"host": "10.0.0.1", "ospf_neighbors": 1}}}
    path = tmp_path / "ok.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["guard", "--change", lab["script"], "-i", str(path)]) == 3
    assert "--yes" in capsys.readouterr().err and not lab["marker"].exists()
