"""Tests de guard (Phase D2, SPEC_v3 §7) -- retour arrière, codes retour 0 à 6, journal.

Trois niveaux, tous sans lab :
  1. décision pure (rollback_reasons, outcome) ;
  2. run_guard avec des E/S injectées (GuardIO factice) : toute la table des issues ;
  3. vrais sous-processus (délai, groupe de processus, SIGTERM) et CLI de bout en bout avec de
     vrais scripts bash et un « réseau » factice dont l'état dépend d'un fichier témoin.
"""
import hashlib
import json
import os
import signal
import threading
import time
from pathlib import Path

import pytest

from netcheck import cli, collector, guard, snapshot
from netcheck.diff import Finding, Severity
from netcheck.guard import DiffResult, GuardIO, Journal, ScriptResult, SnapshotNames
from netcheck.model import DeviceState, Interface, OspfNeighbor

CLEAN = DiffResult([], "OK", 0)
BROKEN = DiffResult([Finding(Severity.CRITIQUE, "ospf_neighbor", "r1", "voisin OSPF perdu : 10.1.255.3")],
                    "ÉCHEC", 2)
ATTENTION = DiffResult([Finding(Severity.ATTENTION, "metric", "r1", "métrique modifiée")], "ATTENTION", 1)
OK_SCRIPT = ScriptResult(rc=0)


# ------------------------------------------------------------------------------------------
# 1. Décision pure
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("verdict,rollback_on,change,expected_count", [
    (0, "echec", ScriptResult(0), 0),
    (1, "echec", ScriptResult(0), 0),          # ATTENTION sous le seuil par défaut
    (2, "echec", ScriptResult(0), 1),
    (1, "attention", ScriptResult(0), 1),
    (0, "attention", ScriptResult(0), 0),
    (0, "echec", ScriptResult(7), 1),          # script en échec : déclenche même verdict OK
    (0, "echec", ScriptResult(None, timed_out=True), 1),
    (2, "echec", ScriptResult(7), 2),          # deux raisons cumulées
])
def test_rollback_reasons(verdict, rollback_on, change, expected_count):
    assert len(guard.rollback_reasons(verdict, change, rollback_on)) == expected_count


def test_rollback_reason_texts_name_the_cause():
    text = " | ".join(guard.rollback_reasons(2, ScriptResult(7), "echec"))
    assert "ÉCHEC" in text and "code 7" in text
    assert "bloqué" in " | ".join(guard.rollback_reasons(0, ScriptResult(None, timed_out=True), "echec"))


@pytest.mark.parametrize("verdict,change_failed,rolled_back,rollback_ok,expected", [
    (0, False, False, False, ("SUCCESS", 0)),
    (1, False, False, False, ("ATTENTION", 1)),
    (2, False, False, False, ("FAILED_NO_ROLLBACK", 2)),
    (0, True, False, False, ("FAILED_NO_ROLLBACK", 2)),   # script en échec sans rollback : au moins 2
    (1, True, False, False, ("FAILED_NO_ROLLBACK", 2)),
    (2, False, True, True, ("ROLLED_BACK", 4)),
    (2, False, True, False, ("ROLLBACK_FAILED", 5)),
    (0, True, True, True, ("ROLLED_BACK", 4)),
    (0, True, True, False, ("ROLLBACK_FAILED", 5)),
])
def test_outcome_table(verdict, change_failed, rolled_back, rollback_ok, expected):
    assert guard.outcome(verdict, change_failed, rolled_back, rollback_ok) == expected


def test_every_final_state_has_a_distinct_documented_exit_code():
    codes = {s: c for s, c in guard.STATE_CODES.items() if s not in ("ERROR",)}
    assert sorted(codes.values()) == [0, 1, 2, 4, 5, 6]  # 3 est réservé à l'usage
    assert guard.EXIT_USAGE == 3 and guard.STATE_CODES["ERROR"] == guard.EXIT_INTERRUPTED


# ------------------------------------------------------------------------------------------
# 2. run_guard avec des E/S injectées
# ------------------------------------------------------------------------------------------

class FakeUI(guard.UI):
    def __init__(self):
        self.infos, self.finals, self.diffs = [], [], []

    def info(self, message):
        self.infos.append(message)

    def script_output(self, line):
        pass

    def show_diff(self, result):
        self.diffs.append(result)

    def final(self, state, code, details):
        self.finals.append((state, code, details))


class FakeIO:
    """Journal des appels dans l'ordre + réponses programmées. L'horloge est simulée : sleep()
    la fait avancer, ce qui rend la boucle de preuve déterministe et instantanée."""

    def __init__(self, change=OK_SCRIPT, rollback=OK_SCRIPT, after=CLEAN, backs=(CLEAN,),
                 raise_on=None, names=None):
        self.change, self.rollback, self.after, self.backs = change, rollback, after, list(backs)
        self.raise_on = raise_on or {}      # {("script", "change.sh"): KeyboardInterrupt(), ...}
        self.names = names
        self.calls: list[tuple] = []
        self.t = 0.0

    def _maybe_raise(self, key):
        if key in self.raise_on:
            raise self.raise_on[key]

    def snapshot(self, name):
        self.calls.append(("snapshot", name))
        self._maybe_raise(("snapshot", name))

    def wait_convergence(self, timeout):
        self.calls.append(("converge",))
        return True

    def diff(self, before, after, use_expect):
        self.calls.append(("diff", after, use_expect))
        self._maybe_raise(("diff", after))
        if after == self.names.after:
            return self.after
        return self.backs.pop(0) if len(self.backs) > 1 else self.backs[0]

    def run_script(self, path, timeout):
        self.calls.append(("script", path.name))
        self._maybe_raise(("script", path.name))
        return self.change if path.name == "change.sh" else self.rollback

    def sleep(self, seconds):
        self.t += seconds

    def clock(self):
        return self.t

    def as_guard_io(self):
        return GuardIO(snapshot=self.snapshot, wait_convergence=self.wait_convergence, diff=self.diff,
                       run_script=self.run_script, sleep=self.sleep, clock=self.clock)

    def count(self, kind, arg=None):
        return sum(1 for c in self.calls if c[0] == kind and (arg is None or c[1] == arg))


NAMES = SnapshotNames("g_avant", "g_apres", "g_retour")


@pytest.fixture
def scripts(tmp_path):
    change, rollback = tmp_path / "change.sh", tmp_path / "rollback.sh"
    change.write_text("echo changement\n", encoding="utf-8")
    rollback.write_text("echo annulation\n", encoding="utf-8")
    return change, rollback


def _run(tmp_path, scripts, io, *, with_rollback=True, rollback_on="echec", wait=10):
    change, rollback = scripts
    io.names = NAMES
    journal = Journal(tmp_path / "reports" / "guard_test.json",
                      {"change_script": guard.script_record(change),
                       "rollback_script": guard.script_record(rollback) if with_rollback else None})
    ui = FakeUI()
    result = guard.run_guard(change=change, rollback=rollback if with_rollback else None,
                             rollback_on=rollback_on, wait=wait, script_timeout=5,
                             io=io.as_guard_io(), ui=ui, journal=journal, names=NAMES)
    data = json.loads((tmp_path / "reports" / "guard_test.json").read_text(encoding="utf-8"))
    return result, ui, data


def test_success_code_0_rollback_never_run(tmp_path, scripts):
    io = FakeIO()
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("SUCCESS", 0)
    assert io.count("script", "rollback.sh") == 0
    assert data["final_state"] == "SUCCESS" and data["exit_code"] == 0
    assert [s["name"] for s in data["steps"]] == [
        "snapshot_avant", "script_changement", "convergence_apres", "snapshot_apres", "diff_apres"]
    assert ui.finals[0][:2] == ("SUCCESS", 0)


def test_attention_below_default_threshold_is_code_1_without_rollback(tmp_path, scripts):
    io = FakeIO(after=ATTENTION)
    result, _, _ = _run(tmp_path, scripts, io, rollback_on="echec")
    assert (result.state, result.code) == ("ATTENTION", 1)
    assert io.count("script", "rollback.sh") == 0


def test_attention_triggers_rollback_when_threshold_is_attention(tmp_path, scripts):
    io = FakeIO(after=ATTENTION, backs=(CLEAN,))
    result, _, _ = _run(tmp_path, scripts, io, rollback_on="attention")
    assert (result.state, result.code) == ("ROLLED_BACK", 4)
    assert io.count("script", "rollback.sh") == 1


def test_failure_without_rollback_script_is_code_2(tmp_path, scripts):
    io = FakeIO(after=BROKEN)
    result, ui, _ = _run(tmp_path, scripts, io, with_rollback=False)
    assert (result.state, result.code) == ("FAILED_NO_ROLLBACK", 2)
    assert any("ÉCHEC" in r for r in ui.finals[0][2]["reasons"])


def test_change_script_failure_without_rollback_is_at_least_code_2(tmp_path, scripts):
    io = FakeIO(change=ScriptResult(rc=3), after=CLEAN)  # verdict OK, mais le script a échoué
    result, ui, _ = _run(tmp_path, scripts, io, with_rollback=False)
    assert (result.state, result.code) == ("FAILED_NO_ROLLBACK", 2)
    assert any("code 3" in r for r in ui.finals[0][2]["reasons"])


def test_change_script_timeout_triggers_rollback(tmp_path, scripts):
    io = FakeIO(change=ScriptResult(rc=None, timed_out=True), after=CLEAN, backs=(CLEAN,))
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLED_BACK", 4)
    assert any("bloqué" in r for r in data["rollback_reasons"])


def test_failure_then_valid_rollback_is_code_4_and_proven(tmp_path, scripts):
    io = FakeIO(after=BROKEN, backs=(CLEAN,))
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLED_BACK", 4)
    assert io.count("script", "rollback.sh") == 1
    # La preuve est un diff avant <-> retour SANS --expect.
    assert ("diff", "g_retour", False) in io.calls and ("diff", "g_apres", True) in io.calls
    assert data["final_state"] == "ROLLED_BACK" and data["exit_code"] == 4
    assert data["rollback_triggered"] is True
    assert data["steps"][-1]["name"] == "preuve_retour" and data["steps"][-1]["detail"]["clean"] is True
    # Ordre : le script d'annulation vient APRÈS le diff déclencheur, la preuve APRÈS l'annulation.
    order = [c for c in io.calls if c[0] in ("script", "diff")]
    assert order.index(("script", "rollback.sh")) > order.index(("diff", "g_apres", True))
    assert order.index(("diff", "g_retour", False)) > order.index(("script", "rollback.sh"))


def test_rollback_that_repairs_nothing_is_code_5_and_runs_only_once(tmp_path, scripts):
    io = FakeIO(after=BROKEN, backs=(BROKEN,))  # l'état ne revient jamais
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLBACK_FAILED", 5)
    assert io.count("script", "rollback.sh") == 1          # jamais rejoué, même si le retour n'est pas propre
    assert io.count("snapshot", "g_retour") >= 2            # ... mais l'état est relevé plusieurs fois
    assert data["final_state"] == "ROLLBACK_FAILED" and data["exit_code"] == 5
    details = ui.finals[0][2]
    assert details["proven"] is False and details["remaining_findings"] == 1
    assert details["remaining"].findings  # les écarts restants sont transmis à l'affichage


def test_proof_settles_after_a_few_polls_without_rerunning_rollback(tmp_path, scripts):
    io = FakeIO(after=BROKEN, backs=(BROKEN, BROKEN, CLEAN))
    result, _, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLED_BACK", 4)
    assert io.count("script", "rollback.sh") == 1
    assert data["steps"][-1]["detail"]["attempts"] == 3


def test_rollback_script_error_is_code_5_even_if_state_is_clean(tmp_path, scripts):
    io = FakeIO(after=BROKEN, rollback=ScriptResult(rc=1), backs=(CLEAN,))
    result, ui, _ = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLBACK_FAILED", 5)
    assert ui.finals[0][2]["rollback_script_failed"] is True


def test_rollback_script_timeout_is_code_5(tmp_path, scripts):
    io = FakeIO(after=BROKEN, rollback=ScriptResult(rc=None, timed_out=True), backs=(CLEAN,))
    result, ui, _ = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLBACK_FAILED", 5)
    assert ui.finals[0][2]["rollback_timed_out"] is True


def test_proof_requires_zero_findings_any_severity(tmp_path, scripts):
    info_only = DiffResult([Finding(Severity.INFO, "config", "r1", "+ ligne restée")], "OK", 0)
    io = FakeIO(after=BROKEN, backs=(info_only,))
    result, _, _ = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ROLLBACK_FAILED", 5)  # verdict OK, mais pas zéro constat


# -- Interruption : jamais d'annulation automatique (état inconnu) --------------------------

def test_interrupt_during_change_script_is_code_6_and_no_rollback(tmp_path, scripts):
    io = FakeIO(raise_on={("script", "change.sh"): KeyboardInterrupt()})
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("INTERRUPTED", 6)
    assert io.count("script", "rollback.sh") == 0
    assert data["final_state"] == "INTERRUPTED" and data["exit_code"] == 6
    assert data["outcome_details"]["step"] == "script_changement"
    assert data["outcome_details"]["change_started"] is True
    # L'étape interrompue est tracée dans le journal, sans date de fin.
    assert data["steps"][-1]["name"] == "script_changement" and data["steps"][-1]["ended_at"] is None


def test_interrupt_during_rollback_script_does_not_rerun_it(tmp_path, scripts):
    io = FakeIO(after=BROKEN, raise_on={("script", "rollback.sh"): KeyboardInterrupt()})
    result, _, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("INTERRUPTED", 6)
    assert io.count("script", "rollback.sh") == 1
    assert data["outcome_details"]["step"] == "script_annulation"


def test_interrupt_before_any_change_says_nothing_was_modified(tmp_path, scripts):
    io = FakeIO(raise_on={("snapshot", "g_avant"): KeyboardInterrupt()})
    result, ui, _ = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("INTERRUPTED", 6)
    assert io.count("script") == 0
    assert ui.finals[0][2]["change_started"] is False


def test_internal_error_is_code_6_never_a_rollback(tmp_path, scripts):
    io = FakeIO(after=BROKEN, raise_on={("diff", "g_apres"): RuntimeError("collecte KO")})
    result, ui, data = _run(tmp_path, scripts, io)
    assert (result.state, result.code) == ("ERROR", 6)
    assert io.count("script", "rollback.sh") == 0
    assert "RuntimeError: collecte KO" in ui.finals[0][2]["error"]
    assert data["final_state"] == "ERROR"


# -- Journal : secrets masqués, SHA-256, hors Git ------------------------------------------

def test_journal_masks_secrets_and_records_sha256(tmp_path):
    change = tmp_path / "change.sh"
    change.write_text("vtysh -c 'neighbor 172.16.34.2 password SuperSecret'\n", encoding="utf-8")
    rollback = tmp_path / "rollback.sh"
    rollback.write_text("echo rollback\n", encoding="utf-8")
    leaky = ScriptResult(rc=0, tail=["ip ospf message-digest-key 1 md5 TopSecret"])
    io = FakeIO(change=leaky)
    _, _, data = _run(tmp_path, (change, rollback), io)
    raw = (tmp_path / "reports" / "guard_test.json").read_text(encoding="utf-8")
    assert "SuperSecret" not in raw and "TopSecret" not in raw
    assert "password ****" in raw and "md5 ****" in raw
    assert data["change_script"]["sha256"] == hashlib.sha256(change.read_bytes()).hexdigest()


def test_journal_records_steps_timestamps_and_script_codes(tmp_path, scripts):
    io = FakeIO(change=ScriptResult(rc=0, duration=1.5, tail=["ok"]), after=BROKEN, backs=(CLEAN,))
    _, _, data = _run(tmp_path, scripts, io)
    change_step = next(s for s in data["steps"] if s["name"] == "script_changement")
    assert change_step["detail"]["rc"] == 0 and change_step["detail"]["output_tail"] == ["ok"]
    assert change_step["started_at"] and change_step["ended_at"]
    assert {s["name"] for s in data["steps"]} >= {"script_annulation", "convergence_retour", "preuve_retour"}
    assert data["steps"][4]["detail"]["verdict"] == "ÉCHEC"


def test_journal_write_failure_never_breaks_guard(tmp_path, scripts, monkeypatch):
    io = FakeIO()
    monkeypatch.setattr(Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("disque plein")))
    change, rollback = scripts
    io.names = NAMES
    journal = Journal(tmp_path / "reports" / "j.json", {})
    result = guard.run_guard(change=change, rollback=rollback, rollback_on="echec", wait=5,
                             script_timeout=5, io=io.as_guard_io(), ui=FakeUI(), journal=journal,
                             names=NAMES)
    assert result.code == 0


# -- Messages finaux : impossibles à rater --------------------------------------------------

def test_rollback_failed_message_is_unmissable():
    title, lines = guard_message("ROLLBACK_FAILED", 5, {"reasons": ["verdict ÉCHEC"], "proven": False,
                                                       "remaining_findings": 3, "journal": "reports/g.json"})
    text = title + "\n".join(lines)
    assert "ANNULATION ÉCHOUÉE" in text and "N'EST PAS DANS SON ÉTAT INITIAL" in text
    assert "INTERVENTION MANUELLE" in text and "code retour : 5" in text and "reports/g.json" in text


def test_interrupted_message_states_step_and_that_no_rollback_ran():
    title, lines = guard_message("INTERRUPTED", 6, {"step": "script_changement", "change_started": True})
    assert "interrompu pendant le script de changement" in title.lower()
    assert "vérifie l'état du réseau : l'annulation n'a PAS été lancée" in lines
    assert "code retour : 6" in lines


def test_alarm_key_sentences_fit_a_narrow_terminal_without_truncation(capsys, monkeypatch):
    # Régression trouvée en conditions réelles : un titre de cadre trop long était tronqué à 80
    # colonnes et la phrase « l'annulation n'a PAS été lancée » disparaissait.
    monkeypatch.setenv("COLUMNS", "80")
    from netcheck import report
    report.print_guard_final("INTERRUPTED", 6, {"step": "preuve_retour", "change_started": True,
                                                "journal": "reports/guard_x.json"})
    err = capsys.readouterr().err
    assert "l'annulation n'a PAS été lancée" in err and "vérifie l'état du réseau" in err
    report.print_guard_final("ROLLBACK_FAILED", 5, {"reasons": ["verdict ÉCHEC (seuil --rollback-on echec)"],
                                                    "proven": False, "remaining_findings": 4})
    err = capsys.readouterr().err
    assert "LE RÉSEAU N'EST PAS DANS SON ÉTAT INITIAL" in err and "INTERVENTION MANUELLE REQUISE" in err


def test_final_alarm_goes_to_stderr_in_a_panel(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    from netcheck import report
    report.print_guard_final("ROLLBACK_FAILED", 5, {"reasons": [], "proven": False, "remaining_findings": 1})
    captured = capsys.readouterr()
    assert "ANNULATION ÉCHOUÉE" in captured.err and "ANNULATION ÉCHOUÉE" not in captured.out


def guard_message(state, code, details):
    from netcheck import report
    return report.guard_final_message(state, code, details)


# ------------------------------------------------------------------------------------------
# 3a. Vrais sous-processus
# ------------------------------------------------------------------------------------------

def _script(tmp_path, body, name="s.sh"):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ")[-1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


def test_run_script_captures_output_and_exit_code(tmp_path):
    seen = []
    res = guard.run_script(_script(tmp_path, "echo un; echo deux >&2; exit 3\n"), 10, echo=seen.append)
    assert res.rc == 3 and not res.timed_out and res.failed
    assert res.tail == ["un", "deux"] and seen == ["un", "deux"]


def test_run_script_success(tmp_path):
    res = guard.run_script(_script(tmp_path, "true\n"), 10)
    assert res.rc == 0 and not res.failed


def test_run_script_timeout_kills_the_whole_process_group(tmp_path):
    # Le fils (sleep) survivrait à la mort de bash si on ne tuait pas le groupe entier.
    script = _script(tmp_path, "sleep 60 &\necho $!\nwait\n")
    start = time.monotonic()
    res = guard.run_script(script, 1)
    assert time.monotonic() - start < 15
    assert res.timed_out and res.rc is None and res.failed
    child = int(res.tail[0])
    for _ in range(30):
        if not _alive(child):
            break
        time.sleep(0.1)
    assert not _alive(child), "le processus fils du script est resté vivant après le délai"


def test_run_script_runs_in_its_own_session_without_stdin(tmp_path):
    res = guard.run_script(_script(tmp_path, "read x || echo stdin-ferme\n"), 10)
    assert res.tail == ["stdin-ferme"]


def test_sigterm_is_turned_into_interrupt_and_kills_the_child(tmp_path):
    script = _script(tmp_path, "sleep 60 &\necho $!\nwait\n")
    timer = threading.Timer(1.0, lambda: os.kill(os.getpid(), signal.SIGTERM))
    child_pid = {}

    def echo(line):
        child_pid.setdefault("pid", int(line))

    previous = signal.getsignal(signal.SIGTERM)
    timer.start()
    try:
        with guard.sigterm_as_interrupt(), pytest.raises(KeyboardInterrupt):
            guard.run_script(script, 60, echo=echo)
    finally:
        timer.cancel()
    assert signal.getsignal(signal.SIGTERM) == previous   # gestionnaire restauré
    for _ in range(30):
        if not _alive(child_pid["pid"]):
            break
        time.sleep(0.1)
    assert not _alive(child_pid["pid"]), "guard interrompu ne doit pas laisser tourner le script"


# ------------------------------------------------------------------------------------------
# 3b. CLI de bout en bout : vrais scripts bash, réseau factice piloté par un fichier témoin
# ------------------------------------------------------------------------------------------

def _network_state(broken: bool) -> DeviceState:
    neighbors = [] if broken else [OspfNeighbor("10.1.255.3", "Full/-", "eth2")]
    return DeviceState(name="r1", host="h", timestamp="t", reachable=True,
                       interfaces=[Interface("eth2", "vers-r3", True, True, ["10.1.13.1/30"])],
                       ospf_neighbors=neighbors)


@pytest.fixture
def fake_lab(tmp_path, monkeypatch):
    """Le « réseau » est cassé tant que le fichier témoin existe : un script de changement le
    crée, un script d'annulation le supprime -- de vrais scripts, sans conteneur."""
    marker = tmp_path / "casse"
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(guard, "PROOF_POLL_SECONDS", 0.05)
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(collector, "collect_all",
                        lambda routers, driver=None: {"r1": (True, _network_state(marker.exists()))})
    monkeypatch.setattr(collector, "wait_for_convergence", lambda *a, **k: True)
    return marker


def _guard(tmp_path, *extra, change_body="touch {marker}\n", rollback_body=None, marker=None):
    change = _script(tmp_path, change_body.format(marker=marker), "change.sh")
    args = ["guard", "--change", str(change), "--yes", "--wait", "1", *extra]
    if rollback_body is not None:
        rollback = _script(tmp_path, rollback_body.format(marker=marker), "rollback.sh")
        args += ["--rollback", str(rollback)]
    return cli.main(args)


def _journal(tmp_path):
    files = sorted((tmp_path / "reports").glob("guard_*.json"))
    assert len(files) == 1
    return json.loads(files[0].read_text(encoding="utf-8"))


def test_cli_breaking_change_with_valid_rollback_is_code_4(tmp_path, fake_lab, capsys):
    code = _guard(tmp_path, marker=fake_lab, rollback_body="rm -f {marker}\n")
    assert code == 4
    out = capsys.readouterr().out
    assert "ANNULÉ AVEC SUCCÈS" in out
    journal = _journal(tmp_path)
    assert journal["final_state"] == "ROLLED_BACK" and journal["rollback_triggered"] is True
    assert list((tmp_path / "snaps").glob("guard_*_retour"))  # le troisième snapshot existe


def test_cli_rollback_that_repairs_nothing_is_code_5(tmp_path, fake_lab, capsys):
    code = _guard(tmp_path, marker=fake_lab, rollback_body="true\n")
    assert code == 5
    err = capsys.readouterr().err
    assert "ANNULATION ÉCHOUÉE" in err and "N'EST PAS DANS SON ÉTAT INITIAL" in err
    assert _journal(tmp_path)["final_state"] == "ROLLBACK_FAILED"
    assert fake_lab.exists()  # le « réseau » est resté cassé, et guard l'a dit


def test_cli_breaking_change_without_rollback_is_code_2(tmp_path, fake_lab, capsys):
    code = _guard(tmp_path, marker=fake_lab)
    assert code == 2 and fake_lab.exists()
    assert _journal(tmp_path)["final_state"] == "FAILED_NO_ROLLBACK"


def test_cli_harmless_change_is_code_0_and_rollback_never_runs(tmp_path, fake_lab, capsys):
    code = _guard(tmp_path, marker=fake_lab, change_body="true\n", rollback_body="touch {marker}\n")
    assert code == 0
    assert not fake_lab.exists()  # le script d'annulation n'a jamais tourné
    assert _journal(tmp_path)["final_state"] == "SUCCESS"


def test_cli_failing_change_script_without_rollback_is_code_2(tmp_path, fake_lab, capsys):
    # Changement de comportement v0.3 : avant, un simple avertissement.
    code = _guard(tmp_path, marker=fake_lab, change_body="exit 9\n")
    assert code == 2
    assert any("code 9" in r for r in _journal(tmp_path)["outcome_details"]["reasons"])


def test_cli_blocked_change_script_is_stopped_after_the_timeout_and_rolled_back(tmp_path, fake_lab):
    code = _guard(tmp_path, "--script-timeout", "1", marker=fake_lab,
                  change_body="sleep 60\n", rollback_body="rm -f {marker}\n")
    assert code == 4  # bloqué = échec -> annulation ; l'état n'a jamais changé donc retour prouvé
    journal = _journal(tmp_path)
    assert next(s for s in journal["steps"] if s["name"] == "script_changement")["detail"]["timed_out"]


def test_cli_both_scripts_are_shown_together_before_any_action_and_decline_runs_nothing(
        tmp_path, fake_lab, capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("aucune collecte avant la confirmation")

    monkeypatch.setattr(collector, "collect_all", forbidden)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    change = _script(tmp_path, "echo SCRIPT-CHANGEMENT\n", "change.sh")
    rollback = _script(tmp_path, "echo SCRIPT-ANNULATION\n", "rollback.sh")
    code = cli.main(["guard", "--change", str(change), "--rollback", str(rollback)])
    out = capsys.readouterr().out
    assert code == 3 and "rien n'a été exécuté" in out
    # Les deux scripts, puis le rappel des conditions, AVANT l'invite de confirmation.
    assert out.index("SCRIPT-CHANGEMENT") < out.index("SCRIPT-ANNULATION") < out.index("Retour arrière si")
    assert not (tmp_path / "reports").exists()  # ni journal, ni snapshot


def test_cli_usage_errors_are_code_3_before_any_action(tmp_path, fake_lab, monkeypatch, capsys):
    monkeypatch.setattr(collector, "collect_all", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    change = _script(tmp_path, "true\n", "change.sh")
    rollback = _script(tmp_path, "true\n", "rollback.sh")
    bad_expect = _script(tmp_path, "findings:\n  - id: x\n    description: d\n    device: r1\n"
                                   "    category: next_hop\n    pattern: '.*'\n", "expect.yml")
    cases = [
        ["guard", "--change", str(tmp_path / "absent.sh"), "--yes"],
        ["guard", "--change", str(change), "--rollback", str(tmp_path / "absent.sh"), "--yes"],
        ["guard", "--change", str(change), "--rollback-on", "attention", "--yes"],   # sans --rollback
        ["guard", "--change", str(change), "--script-timeout", "0", "--yes"],
        ["guard", "--change", str(change), "--rollback", str(rollback), "--expect", str(bad_expect), "--yes"],
    ]
    for args in cases:
        assert cli.main(args) == 3, args
    assert not (tmp_path / "reports").exists()
