"""Tests de `netcheck monitor` (Phase E) : statut, anti-bruit, verrou, état corrompu, alerte.

Aucun appel réseau externe : l'envoi est soit une fonction factice qui enregistre ce qu'on lui
donne, soit un serveur HTTP local (tests/tools/webhook_recorder.py) pour les tests de bout en
bout. La collecte est injectée (MonitorIO) : aucun lab n'est nécessaire.
"""
import ast
import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from webhook_recorder import SECRET_PATH, Recorder

from netcheck import assertions, cli, collector, compliance, monitor, snapshot, webhook
from netcheck.assertions import Assertion, AssertionResult, Status
from netcheck.compliance import Rule, Violation
from netcheck.diff import Finding, Severity
from netcheck.inventory import Inventory
from netcheck.model import DeviceState, Interface, NextHop, OspfNeighbor, Route

REPO_ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
URL = "https://hooks.example.org/services/SENTINEL-SECRET-9d1c"


# ------------------------------------------------------------------------------------------
# Réseau factice : deux routeurs, un voisin OSPF chacun, une route
# ------------------------------------------------------------------------------------------

def device(name, *, ospf=("10.255.0.9",), nexthop="10.1.12.2", config="hostname lab"):
    return DeviceState(
        name=name, host="192.0.2.1", timestamp=T0.isoformat(), reachable=True,
        interfaces=[Interface("eth1", None, True, True, ["10.1.12.1/30"], False)],
        routes=[Route("192.168.2.0/24", "ospf", 20, 110, True, [NextHop(nexthop, "eth1")])],
        ospf_neighbors=[OspfNeighbor(rid, "Full/-", "eth1:10.1.12.1") for rid in ospf],
        running_config=config,
    )


def healthy():
    return {"r1": (True, device("r1")), "r2": (True, device("r2"))}


def ospf_lost():       # CRITIQUE -> ÉCHEC
    return {"r1": (True, device("r1", ospf=())), "r2": (True, device("r2"))}


def nexthop_changed():  # ATTENTION
    return {"r1": (True, device("r1", nexthop="10.1.13.2")), "r2": (True, device("r2"))}


def r2_unreachable():
    return {"r1": (True, device("r1")), "r2": (False, "timeout vers 10.0.0.2 (mot de passe: x)")}


class Harness:
    """Une « machine » qui rejoue des exécutions de monitor, une toutes les 5 minutes."""

    def __init__(self, tmp_path, *, confirm=1, url=URL, fmt="generic"):
        self.tmp = tmp_path
        self.state_file = tmp_path / "var" / "monitor_state.json"
        self.reports = tmp_path / "reports"
        self.results = healthy()
        self.baseline = {name: ok_state for name, (_, ok_state) in healthy().items()}
        self.sent: list[tuple[str, dict]] = []
        self.send_ok, self.send_error = True, "délai dépassé"
        self.url, self.confirm, self.fmt = url, confirm, fmt
        self.intent = self.rules = None
        self.dry_run = False
        self._runs = 0

    def now(self):
        t = T0 + timedelta(minutes=5 * self._runs)
        self._runs += 1
        return t

    def send(self, url, payload):
        self.sent.append((url, payload))
        return webhook.SendResult(True, 1) if self.send_ok else webhook.SendResult(False, 2, self.send_error)

    def run(self):
        cfg = monitor.MonitorConfig(
            baseline_name="nominal", baseline=self.baseline,
            inventory=Inventory(routers={"r1": {}, "r2": {}}, management_interfaces=[]),
            state_file=self.state_file, reports_dir=self.reports, intent=self.intent,
            intent_path="intents/x.yml" if self.intent else None, rules=self.rules,
            rules_path="rules/x.yml" if self.rules else None, webhook_url=self.url,
            webhook_format=self.fmt, confirm=self.confirm, dry_run=self.dry_run, repo_root=self.tmp,
        )
        io = monitor.MonitorIO(collect=lambda: self.results, send=self.send, now=self.now)
        return monitor.run_monitor(cfg, io)

    @property
    def state(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def payloads(self):
        return [p for _, p in self.sent]


def all_text(root: Path) -> str:
    """Tout le texte de tous les fichiers sous root (pour prouver qu'un secret n'y est nulle part)."""
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in root.rglob("*") if p.is_file())


# ------------------------------------------------------------------------------------------
# Correspondance des statuts (décisions validées)
# ------------------------------------------------------------------------------------------

def _finding(sev, device="r1", cat="route", planned=None):
    return Finding(sev, cat, device, "msg", expected_by=planned)


def test_diff_status_mapping():
    assert monitor.diff_outcome([])[0] == monitor.OK
    assert monitor.diff_outcome([_finding(Severity.INFO)])[0] == monitor.OK
    assert monitor.diff_outcome([_finding(Severity.ATTENTION)])[0] == monitor.ATTENTION
    both = [_finding(Severity.ATTENTION), _finding(Severity.CRITIQUE)]
    assert monitor.diff_outcome(both)[0] == monitor.ECHEC


def test_diff_info_and_planned_findings_never_reach_the_alert():
    status, contributions = monitor.diff_outcome([
        _finding(Severity.INFO), _finding(Severity.CRITIQUE, planned="critere-1"),
        _finding(Severity.ATTENTION, device="r2"),
    ])
    assert status == monitor.ATTENTION
    assert [(c.device, c.status) for c in contributions] == [("r2", monitor.ATTENTION)]


def _ar(status):
    return AssertionResult(Assertion("a1", "desc", "r1", "ospf_neighbors", {"count": 1}), status, "détail")


def test_assert_status_mapping_non_evaluable_is_attention_never_silent_ok():
    assert monitor.assert_outcome([_ar(Status.OK)])[0] == monitor.OK
    assert monitor.assert_outcome([_ar(Status.NON_EVALUABLE)])[0] == monitor.ATTENTION
    assert monitor.assert_outcome([_ar(Status.ECHEC)])[0] == monitor.ECHEC
    assert monitor.assert_outcome([_ar(Status.NON_EVALUABLE), _ar(Status.ECHEC)])[0] == monitor.ECHEC


@pytest.mark.parametrize(("severity", "expected"), [
    ("basse", monitor.ATTENTION), ("moyenne", monitor.ATTENTION),
    ("haute", monitor.ECHEC), ("critique", monitor.ECHEC),
])
def test_check_status_mapping(severity, expected):
    rule = Rule("r", "description statique", severity, "all", "line_absent")
    status, contributions = monitor.check_outcome([Violation(rule, "r1", "password hunter2")])
    assert status == expected
    assert contributions[0].message == "description statique", "jamais Violation.detail"


def test_worst_status_wins_and_unreachable_is_failure(tmp_path):
    h = Harness(tmp_path)
    h.results = r2_unreachable()
    assert h.run() == 2
    assert h.state["components"]["collect"] == "ECHEC"


def test_nexthop_change_is_attention_code_1(tmp_path):
    h = Harness(tmp_path)
    h.results = nexthop_changed()
    assert h.run() == 1
    assert h.state["observed"]["status"] == "ATTENTION"


def test_components_without_input_are_reported_not_run(tmp_path, capsys):
    h = Harness(tmp_path)
    h.run()
    out = capsys.readouterr().out
    assert "assert non exécuté" in out and "check non exécuté" in out
    assert h.state["components"] == {"collect": "OK", "diff": "OK", "assert": None, "check": None}


def test_assert_and_check_components_feed_the_global_status(tmp_path):
    h = Harness(tmp_path)
    h.intent = assertions.validate_assertions(
        [{"id": "ospf-r1", "description": "r1 a 1 voisin", "device": "r1", "type": "ospf_neighbors",
          "count": 2}], Path("x"))      # faux : r1 n'en a qu'un -> assert ÉCHEC
    h.rules = [Rule("pw", "mot de passe en clair interdit", "moyenne", "all", "line_absent",
                    params={"pattern": "^password "})]
    h.results = {"r1": (True, device("r1", config="password hunter2")), "r2": (True, device("r2"))}
    assert h.run() == 2
    assert h.state["components"]["assert"] == "ECHEC"
    assert h.state["components"]["check"] == "ATTENTION"
    assert h.state["components"]["diff"] == "OK"          # un changement de config seul est INFO


# ------------------------------------------------------------------------------------------
# Anti-bruit : OK -> ÉCHEC -> ÉCHEC -> OK = une alerte, aucune, un retour à la normale
# ------------------------------------------------------------------------------------------

def test_transition_one_alert_then_none_then_recovery(tmp_path):
    h = Harness(tmp_path)
    assert h.run() == 0 and h.sent == []                     # premier relevé OK : rien à annoncer
    h.results = ospf_lost()
    assert h.run() == 2 and len(h.sent) == 1                 # panne : UNE alerte
    first = h.payloads()[0]
    assert (first["status"], first["previous_status"], first["kind"]) == ("ECHEC", "OK", "degradation")
    assert first["event"] == "status_change"
    assert h.run() == 2 and len(h.sent) == 1                 # même panne : aucune alerte
    h.results = healthy()
    assert h.run() == 0 and len(h.sent) == 2                 # réparation : retour à la normale
    back = h.payloads()[1]
    assert (back["status"], back["previous_status"], back["event"]) == ("OK", "ECHEC", "recovery")
    assert back["incident_duration_s"] == 600                # 10 min entre l'alerte et le retour
    assert back["findings"] == []
    assert h.run() == 0 and len(h.sent) == 2                 # et plus rien ensuite
    assert h.state["incident_since"] is None


def test_first_run_non_ok_alerts_and_first_run_ok_does_not(tmp_path):
    ok = Harness(tmp_path / "a")
    assert ok.run() == 0 and ok.sent == []
    assert ok.state["notified"]["status"] == "OK"

    bad = Harness(tmp_path / "b")
    bad.results = ospf_lost()
    assert bad.run() == 2 and len(bad.sent) == 1
    assert bad.payloads()[0]["kind"] == "first_report"
    assert bad.payloads()[0]["previous_status"] is None


@pytest.mark.parametrize(("announced", "now", "kind"), [
    (monitor.OK, monitor.ATTENTION, "degradation"),
    (monitor.OK, monitor.ECHEC, "degradation"),
    (monitor.ATTENTION, monitor.ECHEC, "degradation"),
    (monitor.ECHEC, monitor.ATTENTION, "improvement"),
    (monitor.ECHEC, monitor.OK, "recovery"),
    (monitor.ATTENTION, monitor.OK, "recovery"),
])
def test_every_status_transition_alerts_with_its_kind(announced, now, kind):
    state = monitor.State(notified={"status": announced, "at": "t"})
    decision = monitor.decide(state, now, "t1", confirm=1)
    assert decision.transition == (announced, now) and decision.kind == kind


def test_unchanged_status_never_alerts_even_with_new_findings(tmp_path):
    # Limite documentée : de NOUVEAUX constats pendant un ÉCHEC déjà annoncé n'envoient rien.
    h = Harness(tmp_path)
    h.run()
    h.results = ospf_lost()
    h.run()
    assert len(h.sent) == 1
    h.results = {"r1": (True, device("r1", ospf=())), "r2": (True, device("r2", ospf=()))}  # pire
    assert h.run() == 2 and len(h.sent) == 1


# ------------------------------------------------------------------------------------------
# --confirm N : dans les deux sens, compteur dans le fichier d'état
# ------------------------------------------------------------------------------------------

def test_confirm_isolated_failure_sends_nothing(tmp_path):
    h = Harness(tmp_path, confirm=2)
    h.run()
    h.results = ospf_lost()
    assert h.run() == 2 and h.sent == []                    # le code retour reste le vrai statut
    assert h.state["candidate"]["status"] == "ECHEC" and h.state["candidate"]["count"] == 1
    h.results = healthy()
    h.run()
    assert h.sent == [] and h.state["candidate"] is None    # la panne isolée est oubliée


def test_confirm_persistent_failure_alerts_on_the_second_run(tmp_path):
    h = Harness(tmp_path, confirm=2)
    h.run()
    h.results = ospf_lost()
    h.run()
    assert h.sent == []
    h.run()
    assert len(h.sent) == 1 and h.payloads()[0]["status"] == "ECHEC"
    assert h.state["notified"]["status"] == "ECHEC" and h.state["candidate"] is None
    h.run()
    assert len(h.sent) == 1


def test_confirm_applies_to_the_recovery_too(tmp_path):
    h = Harness(tmp_path, confirm=2)
    h.run()
    h.results = ospf_lost()
    h.run()
    h.run()
    assert len(h.sent) == 1                                  # panne annoncée
    h.results = healthy()
    h.run()
    assert len(h.sent) == 1                                  # un seul OK : pas encore de retour
    assert h.state["candidate"]["status"] == "OK" and h.state["candidate"]["count"] == 1
    h.results = ospf_lost()
    h.run()
    assert len(h.sent) == 1 and h.state["candidate"] is None  # rechute : retour annulé, rien à dire
    h.results = healthy()
    h.run()
    h.run()
    assert len(h.sent) == 2 and h.payloads()[1]["event"] == "recovery"


def test_confirm_counter_restarts_when_the_candidate_status_changes(tmp_path):
    h = Harness(tmp_path, confirm=2)
    h.run()
    h.results = nexthop_changed()
    h.run()
    h.results = ospf_lost()
    h.run()                                                  # ATTENTION puis ÉCHEC : pas 2 fois le même
    assert h.sent == [] and h.state["candidate"]["status"] == "ECHEC"
    assert h.state["candidate"]["count"] == 1


def test_confirm_counter_survives_between_executions_in_the_state_file(tmp_path):
    h = Harness(tmp_path, confirm=3)
    h.run()
    h.results = ospf_lost()
    h.run()
    h.run()
    assert h.state["candidate"]["count"] == 2
    assert h.sent == []
    h.run()
    assert len(h.sent) == 1


# ------------------------------------------------------------------------------------------
# Fichier d'état illisible ou corrompu : jamais un plantage
# ------------------------------------------------------------------------------------------

_CORRUPT = [
    b"pas du json {{{",
    b'{"version": 1, "observed":',
    b'{"version": 2}',
    b"[]",
    b'{"version": 1, "notified": {"status": "BOUM", "at": "x"}}',
    b'{"version": 1, "candidate": {"status": "ECHEC", "count": true, "since": "x"}}',
    b'{"version": 1, "candidate": {"status": "ECHEC", "count": 0, "since": "x"}}',
    b'{"version": 1, "observed": {"status": "OK"}}',
    b"\xff\xfe\x00binaire",
    b"",
]


@pytest.mark.parametrize("body", _CORRUPT)
def test_corrupt_state_is_treated_as_a_first_run_and_reported(tmp_path, capsys, body):
    h = Harness(tmp_path)
    h.state_file.parent.mkdir(parents=True)
    h.state_file.write_bytes(body)
    assert h.run() == 0                                       # ne plante pas
    assert "fichier d'état illisible" in capsys.readouterr().out
    assert h.state_file.with_name(h.state_file.name + ".corrupt").read_bytes() == body
    assert monitor.load_state(h.state_file)[1] is None        # l'état réécrit est valide
    assert h.sent == []                                        # première exécution OK : silence


def test_corrupt_state_then_failure_alerts_like_a_first_run(tmp_path):
    h = Harness(tmp_path)
    h.state_file.parent.mkdir(parents=True)
    h.state_file.write_text("garbage")
    h.results = ospf_lost()
    assert h.run() == 2 and len(h.sent) == 1
    assert h.payloads()[0]["kind"] == "first_report"


def test_state_path_that_is_a_directory_does_not_crash(tmp_path, capsys):
    h = Harness(tmp_path)
    h.state_file.mkdir(parents=True)
    assert h.run() == 0
    assert "fichier d'état illisible" in capsys.readouterr().out


def test_state_is_written_atomically_with_owner_only_permissions(tmp_path):
    h = Harness(tmp_path)
    h.run()
    assert (h.state_file.stat().st_mode & 0o777) == 0o600
    assert not [p for p in h.state_file.parent.iterdir() if p.name.endswith(".tmp")]
    assert monitor.load_state(h.state_file)[1] is None


def test_failed_state_write_leaves_no_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "s.json"

    def boom(*_):
        raise OSError("disque plein")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        monitor.save_state(path, monitor.State())
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------------------------------------
# Verrou
# ------------------------------------------------------------------------------------------

def test_held_lock_stops_the_run_cleanly_with_code_4(tmp_path, capsys):
    h = Harness(tmp_path)
    h.results = ospf_lost()
    with monitor.RunLock(monitor.lock_path_for(h.state_file)):
        assert h.run() == monitor.EXIT_LOCKED
    err = capsys.readouterr().err
    assert "encore en cours" in err and f"pid {os.getpid()}" in err and "état inchangé" in err
    assert h.sent == [] and not h.state_file.exists(), "aucune collecte, aucune alerte, aucun état"
    assert h.run() == 2                                        # verrou libéré : l'exécution suivante passe


_HOLDER = """
import sys, time
sys.path.insert(0, {root!r})
from pathlib import Path
from netcheck import monitor
lock = monitor.RunLock(Path(sys.argv[1])).__enter__()
print("locked", flush=True)
time.sleep(60)
"""


def test_orphan_lock_after_a_crash_never_blocks_the_next_run(tmp_path):
    h = Harness(tmp_path)
    lock_file = monitor.lock_path_for(h.state_file)
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER.format(root=str(REPO_ROOT)), str(lock_file)],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        with pytest.raises(monitor.LockHeld) as held:        # vivant : le verrou est bien tenu
            monitor.RunLock(lock_file).__enter__()
        assert held.value.pid == holder.pid
        assert h.run() == monitor.EXIT_LOCKED
    finally:
        os.kill(holder.pid, signal.SIGKILL)                  # crash brutal, aucun nettoyage possible
        holder.wait()
        holder.stdout.close()
    assert lock_file.exists(), "le fichier verrou périmé est toujours là..."
    assert json.loads(lock_file.read_text())["pid"] == holder.pid
    assert h.run() == 0                                        # ...et ne bloque rien : le noyau l'a libéré
    assert json.loads(lock_file.read_text())["pid"] == os.getpid()


def test_lock_is_released_even_if_the_run_raises(tmp_path):
    h = Harness(tmp_path)

    def broken():
        raise RuntimeError("collecte cassée")
    cfg = monitor.MonitorConfig(
        baseline_name="n", baseline=h.baseline, inventory=Inventory(routers={}), state_file=h.state_file,
        reports_dir=h.reports)
    with pytest.raises(RuntimeError):
        monitor.run_monitor(cfg, monitor.MonitorIO(collect=broken, send=h.send, now=h.now))
    with monitor.RunLock(monitor.lock_path_for(h.state_file)):
        pass


# ------------------------------------------------------------------------------------------
# Envoi en échec : ni plantage, ni changement du code retour, réessai à l'exécution suivante
# ------------------------------------------------------------------------------------------

def test_send_failure_keeps_the_exit_code_and_retries_on_the_next_run(tmp_path, capsys):
    h = Harness(tmp_path)
    h.run()
    h.results = ospf_lost()
    h.send_ok = False
    assert h.run() == 2                                        # le code retour est le statut, pas l'envoi
    captured = capsys.readouterr()
    assert "échec d'envoi (délai dépassé)" in captured.err
    assert h.state["notified"]["status"] == "OK"               # NON annoncé : on réessaiera
    h.send_ok = True
    assert h.run() == 2 and len(h.sent) == 2                   # 1 échec + 1 réussite
    assert h.state["notified"]["status"] == "ECHEC"
    h.run()
    assert len(h.sent) == 2                                    # puis le silence


def test_a_lost_alert_is_not_resent_after_the_incident_is_over(tmp_path):
    h = Harness(tmp_path)
    h.run()
    h.results = ospf_lost()
    h.send_ok = False
    h.run()
    h.results = healthy()
    h.send_ok = True
    assert h.run() == 0
    assert len(h.sent) == 1, "rien n'a été annoncé, donc rien à annoncer en retour"


def test_no_webhook_configured_disables_alerts_but_keeps_the_pending_change(tmp_path, capsys):
    h = Harness(tmp_path, url=None)
    h.run()
    h.results = ospf_lost()
    assert h.run() == 2 and h.sent == []
    assert "alertes désactivées" in capsys.readouterr().err
    assert h.state["notified"]["status"] == "OK"
    h.url = URL
    h.run()
    assert len(h.sent) == 1 and h.payloads()[0]["status"] == "ECHEC"   # l'URL ajoutée, l'alerte part


def test_the_webhook_url_never_appears_anywhere(tmp_path, capsys):
    h = Harness(tmp_path)
    h.send_error = f"boom sur {URL} (via https://hooks.slack.com/services/T0/B0/leak)"
    h.run()
    h.results = ospf_lost()
    h.send_ok = False
    h.run()
    h.send_ok = True
    h.run()
    h.results = healthy()
    h.run()
    h.dry_run = True
    h.run()
    captured = capsys.readouterr()
    haystacks = [captured.out, captured.err, all_text(tmp_path), json.dumps(h.payloads())]
    for text in haystacks:
        assert "SENTINEL-SECRET" not in text and "hooks.example.org" not in text
        assert "slack.com/services" not in text


# ------------------------------------------------------------------------------------------
# --dry-run
# ------------------------------------------------------------------------------------------

def test_dry_run_prints_the_exact_message_and_writes_nothing(tmp_path, capsys):
    h = Harness(tmp_path, fmt="discord")
    h.run()
    capsys.readouterr()
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    state_before = h.state_file.read_text()
    h.dry_run = True
    h.results = ospf_lost()
    assert h.run() == 2
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("\n{") + 1:])
    assert payload["allowed_mentions"] == {"parse": []} and "embeds" in payload
    assert h.sent == []
    assert h.state_file.read_text() == state_before
    assert {p.relative_to(tmp_path) for p in tmp_path.rglob("*")} == before


def test_dry_run_leaves_a_corrupt_state_file_untouched(tmp_path, capsys):
    h = Harness(tmp_path)
    h.state_file.parent.mkdir(parents=True)
    h.state_file.write_text("garbage")
    h.dry_run = True
    assert h.run() == 0
    assert "fichier d'état illisible" in capsys.readouterr().out    # diagnostic quand même
    assert h.state_file.read_text() == "garbage"                    # mais rien n'est déplacé ni écrit
    assert not h.state_file.with_name(h.state_file.name + ".corrupt").exists()


def test_dry_run_without_transition_still_previews_the_format(tmp_path, capsys):
    h = Harness(tmp_path)
    h.dry_run = True
    h.results = healthy()
    assert h.run() == 0
    out = capsys.readouterr().out
    assert "aperçu (aucune alerte ne serait envoyée maintenant)" in out
    assert not h.state_file.exists() and not h.reports.exists()


# ------------------------------------------------------------------------------------------
# Contenu de l'alerte
# ------------------------------------------------------------------------------------------

def _many_findings_results(n):
    """r1 avec n routes de moins que la référence : n constats CRITIQUE (« préfixe injoignable »)."""
    base = device("r1")
    base.routes = [Route(f"10.9.{i}.0/24", "ospf", 20, 110, True, [NextHop("10.1.12.2", "eth1")])
                   for i in range(n)]
    return base


def test_alert_lists_at_most_10_findings_then_and_n_others(tmp_path):
    h = Harness(tmp_path)
    h.baseline = {"r1": _many_findings_results(14), "r2": device("r2")}
    h.results = {"r1": (True, device("r1")), "r2": (True, device("r2"))}
    h.run()
    payload = h.payloads()[0]
    assert len(payload["findings"]) == 10
    assert payload["more"] == 4
    assert payload["devices"] == ["r1"]


def test_discord_message_mentions_the_remaining_count(tmp_path):
    h = Harness(tmp_path, fmt="discord")
    h.baseline = {"r1": _many_findings_results(14), "r2": device("r2")}
    h.results = {"r1": (True, device("r1")), "r2": (True, device("r2"))}
    h.run()
    embed = h.payloads()[0]["embeds"][0]
    assert "… et 4 autres" in embed["description"]
    assert embed["description"].count("• [") == 10
    assert "**14 constats**" in embed["description"]


def test_alert_findings_are_sorted_worst_first(tmp_path):
    h = Harness(tmp_path)
    h.results = {"r1": (True, device("r1", ospf=(), nexthop="10.1.13.2")), "r2": (True, device("r2"))}
    h.run()
    statuses = [f["severity"] for f in h.payloads()[0]["findings"]]
    assert statuses == sorted(statuses, key=lambda s: {"CRITIQUE": 0, "ATTENTION": 1}[s])
    assert statuses[0] == "CRITIQUE"


def test_alert_never_contains_configuration_or_secrets(tmp_path):
    h = Harness(tmp_path)
    h.rules = [Rule("pw-clair", "mot de passe en clair interdit", "haute", "all", "line_absent",
                    params={"pattern": "^password "})]
    h.results = {
        "r1": (True, device("r1", config="password hunter2\nip ospf message-digest-key 1 md5 s3cretKEY")),
        "r2": (True, device("r2")),
    }
    h.baseline["r1"].running_config = "password hunter2\nip ospf message-digest-key 1 md5 s3cretKEY"
    h.run()
    text = json.dumps(h.payloads())
    assert "hunter2" not in text and "s3cretKEY" not in text
    assert "mot de passe en clair interdit" in text            # la description de la règle, oui
    assert "message-digest-key" not in text                    # jamais une ligne de configuration
    assert "hunter2" not in all_text(h.reports) or "****" in all_text(h.reports)


def test_alert_text_goes_through_secret_masking_and_truncation():
    finding = Finding(Severity.CRITIQUE, "config", "r1",
                      "ligne interdite : password hunter2 " + "x" * 400)
    status, contributions = monitor.diff_outcome([finding])
    ev = monitor.Evaluation(status, {"diff": status}, contributions, {}, [finding], "ÉCHEC")
    alert = monitor.build_alert("degradation", monitor.ECHEC, monitor.OK, ev, T0, "reports/x")
    message = alert.findings[0].message
    assert "hunter2" not in message and "password ****" in message
    assert len(message) <= monitor.MAX_MESSAGE_CHARS and message.endswith("…")


def test_unreachable_device_is_reported_without_its_error_text(tmp_path):
    h = Harness(tmp_path)
    h.results = r2_unreachable()
    h.run()
    payload = h.payloads()[0]
    assert payload["devices"] == ["r2"]
    messages = [f["message"] for f in payload["findings"]]
    assert messages == ["équipement injoignable (détail dans le rapport local)"]
    assert "10.0.0.2" not in json.dumps(payload) and "mot de passe" not in json.dumps(payload)


def test_discord_payload_blocks_mentions_and_stays_within_limits(tmp_path):
    h = Harness(tmp_path, fmt="discord")
    nasty = "@everyone *gras* _it_ `code` " + "y" * 150
    base = device("r1")
    base.interfaces[0].description = nasty
    h.baseline = {"r1": base, "r2": device("r2")}
    changed = device("r1")
    changed.interfaces[0].description = "autre"
    changed.ospf_neighbors = []
    h.results = {"r1": (True, changed), "r2": (True, device("r2"))}
    h.run()
    payload = h.payloads()[0]
    assert payload["allowed_mentions"] == {"parse": []}
    embed = payload["embeds"][0]
    assert len(embed["description"]) <= monitor.DISCORD_DESCRIPTION_MAX
    assert len(embed["title"]) <= 256 and embed["color"] == 15158332
    assert embed["timestamp"].endswith("+00:00")
    assert embed["footer"]["text"] == "diff ÉCHEC"
    json.dumps(payload)                                        # sérialisable


def test_discord_description_is_truncated_but_keeps_the_report_line():
    long_msg = "m" * 190
    contributions = [monitor.Contribution(monitor.ECHEC, "CRITIQUE", "diff", f"r{i}", "route", long_msg)
                     for i in range(40)]
    ev = monitor.Evaluation(monitor.ECHEC, {"diff": monitor.ECHEC}, contributions, {}, [], "ÉCHEC")
    alert = monitor.build_alert("degradation", monitor.ECHEC, monitor.OK, ev, T0, "reports/monitor_x")
    description = monitor.to_discord(alert)["embeds"][0]["description"]
    assert len(description) <= monitor.DISCORD_DESCRIPTION_MAX
    assert description.endswith("Rapport local : `reports/monitor_x`")


def test_discord_recovery_message():
    ev = monitor.Evaluation(monitor.OK, {"diff": monitor.OK, "assert": monitor.OK}, [], {}, [], "OK")
    alert = monitor.build_alert("recovery", monitor.OK, monitor.ECHEC, ev, T0 + timedelta(minutes=14),
                                "reports/x", incident_since=T0.isoformat())
    embed = monitor.to_discord(alert)["embeds"][0]
    assert embed["title"] == "🟢 netcheck : retour à la normale (ÉCHEC → OK)"
    assert "Plus aucun constat." in embed["description"] and "Incident : 14 min" in embed["description"]
    assert embed["color"] == 3066993


def test_generic_payload_shape(tmp_path):
    h = Harness(tmp_path)
    h.results = ospf_lost()
    h.run()
    p = h.payloads()[0]
    assert set(p) == {"source", "netcheck_version", "event", "kind", "status", "previous_status",
                      "timestamp", "components", "devices", "findings", "more", "report"}
    assert p["source"] == "netcheck" and p["components"]["diff"] == "ECHEC"
    assert p["findings"][0].keys() == {"severity", "component", "device", "category", "message"}


# ------------------------------------------------------------------------------------------
# Rapports locaux
# ------------------------------------------------------------------------------------------

def test_latest_report_is_rewritten_each_run_and_dated_only_when_alerting(tmp_path):
    h = Harness(tmp_path)
    h.run()
    latest = h.reports / "monitor_latest"
    assert (latest / "diff.json").is_file() and (latest / "diff.html").is_file()
    assert (latest / "summary.json").is_file() and not (latest / "assert.json").exists()
    assert not [p for p in h.reports.iterdir() if p.name != "monitor_latest"]   # rien de daté sans alerte

    h.results = ospf_lost()
    h.run()
    dated = [p for p in h.reports.iterdir() if p.name.startswith("monitor_2")]
    assert [p.name for p in dated] == ["monitor_2026-10-03_100500"]
    assert h.payloads()[0]["report"] == "reports/monitor_2026-10-03_100500"
    assert (dated[0] / "summary.json").is_file()
    assert json.loads((dated[0] / "summary.json").read_text())["status"] == "ECHEC"

    h.run()
    assert len([p for p in h.reports.iterdir() if p.name.startswith("monitor_2")]) == 1


def test_stale_report_files_are_removed_when_a_component_is_no_longer_run(tmp_path):
    h = Harness(tmp_path)
    h.intent = assertions.validate_assertions(
        [{"id": "a", "description": "d", "device": "r1", "type": "ospf_neighbors", "count": 1}], Path("x"))
    h.run()
    assert (h.reports / "monitor_latest" / "assert.json").is_file()
    h.intent = None
    h.run()
    assert not (h.reports / "monitor_latest" / "assert.json").exists()


# ------------------------------------------------------------------------------------------
# Lecture seule stricte (statique)
# ------------------------------------------------------------------------------------------

def _imports(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names |= {f"{node.module}.{a.name}" for a in node.names}
    return names


@pytest.mark.parametrize("module", ["monitor.py", "webhook.py"])
def test_monitor_never_imports_guard_nor_runs_subprocesses(module):
    imported = _imports(REPO_ROOT / "netcheck" / module)
    assert not {n for n in imported if n.endswith("guard")}, "monitor ne lance jamais guard"
    assert not {n for n in imported if n.split(".")[0] in ("subprocess", "os.system", "pty")}
    source = (REPO_ROOT / "netcheck" / module).read_text(encoding="utf-8")
    assert "os.system" not in source and "Popen" not in source and "run_script" not in source


# ------------------------------------------------------------------------------------------
# Ligne de commande : refus avant toute action, bout en bout avec un vrai serveur local
# ------------------------------------------------------------------------------------------

@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Snapshots, rapports et collecte redirigés ; `lab.results` choisit ce que « le réseau » répond."""
    class Lab:
        results = healthy()
        collected = 0

    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.delenv(webhook.ENV_VAR, raising=False)
    snapshot.save("nominal", healthy())

    def collect_all(*_a, **_k):
        Lab.collected += 1
        return Lab.results
    monkeypatch.setattr(collector, "collect_all", collect_all)
    return Lab


def _cli(*args):
    return cli.main(["monitor", "--baseline", "nominal", *args])


def test_cli_end_to_end_with_a_real_local_server(tmp_path, lab, monkeypatch, capsys):
    with Recorder() as server:
        monkeypatch.setenv(webhook.ENV_VAR, server.url)
        assert _cli("--webhook-format", "discord") == 0 and server.count == 0
        lab.results = ospf_lost()
        assert _cli("--webhook-format", "discord") == 2 and server.count == 1
        assert _cli("--webhook-format", "discord") == 2 and server.count == 1
        lab.results = healthy()
        assert _cli("--webhook-format", "discord") == 0 and server.count == 2
        assert server.requests[0]["path"] == SECRET_PATH
        titles = [m["embeds"][0]["title"] for m in server.messages]
        assert "ÉCHEC" in titles[0] and "retour à la normale" in titles[1]
    captured = capsys.readouterr()
    assert "SENTINEL-WEBHOOK-TOKEN" not in captured.out + captured.err + all_text(tmp_path / "reports")
    assert monitor.STATE_FILENAME in [p.name for p in (tmp_path / "reports").iterdir()]


def test_cli_real_webhook_failure_does_not_change_the_exit_code(tmp_path, lab, monkeypatch, capsys):
    monkeypatch.setattr(webhook, "RETRY_DELAY", 0.0)
    with Recorder(status=500) as server:
        monkeypatch.setenv(webhook.ENV_VAR, server.url)
        _cli()
        lab.results = ospf_lost()
        assert _cli() == 2
        assert server.count == 2                                # envoi + un seul réessai
    err = capsys.readouterr().err
    assert "échec d'envoi (HTTP 500) après 2 tentative(s)" in err
    assert "SENTINEL-WEBHOOK-TOKEN" not in err


DISCORD_URL = "https://discord.com/api/webhooks/123456789/SENTINEL-DISCORD-TOKEN"


@pytest.fixture
def fake_post(monkeypatch):
    """Remplace l'envoi réel : aucun appel vers discord.com, jamais. Enregistre les corps."""
    sent = []

    def post(url, payload, **_kwargs):
        sent.append(payload)
        return webhook.SendResult(True, 1)
    monkeypatch.setattr(webhook, "post", post)
    return sent


def test_cli_discord_url_selects_the_discord_format_automatically(lab, monkeypatch, fake_post, capsys):
    monkeypatch.setenv(webhook.ENV_VAR, DISCORD_URL)
    _cli()                                    # pas de --webhook-format
    lab.results = ospf_lost()
    assert _cli() == 2
    payload = fake_post[0]
    assert "embeds" in payload and payload["allowed_mentions"] == {"parse": []}
    assert "source" not in payload, "le corps generic ne doit pas partir vers Discord"
    captured = capsys.readouterr()
    assert "avertissement" not in captured.err
    assert "SENTINEL-DISCORD-TOKEN" not in captured.out + captured.err


def test_cli_other_url_keeps_the_generic_format_by_default(lab, monkeypatch, fake_post):
    monkeypatch.setenv(webhook.ENV_VAR, "https://hooks.example.org/services/x")
    _cli()
    lab.results = ospf_lost()
    _cli()
    assert fake_post[0]["source"] == "netcheck" and "embeds" not in fake_post[0]


def test_cli_explicit_discord_is_still_honoured_for_any_url(lab, monkeypatch, fake_post):
    monkeypatch.setenv(webhook.ENV_VAR, "https://hooks.example.org/services/x")
    _cli("--webhook-format", "discord")
    lab.results = ospf_lost()
    _cli("--webhook-format", "discord")
    assert "embeds" in fake_post[0]


def test_cli_generic_forced_towards_discord_warns_but_obeys(lab, monkeypatch, fake_post, capsys):
    monkeypatch.setenv(webhook.ENV_VAR, DISCORD_URL)
    _cli("--webhook-format", "generic")
    lab.results = ospf_lost()
    _cli("--webhook-format", "generic")
    err = capsys.readouterr().err
    assert "avertissement" in err and "HTTP 400" in err
    assert "SENTINEL-DISCORD-TOKEN" not in err
    assert fake_post[0]["source"] == "netcheck"     # respecté tel que demandé


def test_cli_dry_run_previews_the_discord_format_for_a_discord_url(lab, monkeypatch, capsys):
    monkeypatch.setenv(webhook.ENV_VAR, DISCORD_URL)
    lab.results = ospf_lost()
    assert _cli("--dry-run") == 2
    out = capsys.readouterr().out
    assert '"embeds"' in out and "SENTINEL-DISCORD-TOKEN" not in out


def test_cli_http_400_from_the_recipient_carries_the_format_hint(lab, monkeypatch, capsys):
    with Recorder(status=400) as server:
        monkeypatch.setenv(webhook.ENV_VAR, server.url)
        _cli()
        lab.results = ospf_lost()
        assert _cli() == 2
    err = capsys.readouterr().err
    assert "HTTP 400, format refusé par le destinataire : vérifier --webhook-format" in err
    assert "SENTINEL-WEBHOOK-TOKEN" not in err


def test_cli_state_file_option(tmp_path, lab):
    state = tmp_path / "ailleurs" / "etat.json"
    assert _cli("--state-file", str(state)) == 0
    assert state.is_file()


def test_cli_confirm_option(tmp_path, lab, monkeypatch):
    with Recorder() as server:
        monkeypatch.setenv(webhook.ENV_VAR, server.url)
        _cli("--confirm", "2")
        lab.results = ospf_lost()
        _cli("--confirm", "2")
        assert server.count == 0
        _cli("--confirm", "2")
        assert server.count == 1


@pytest.mark.parametrize("extra", [["--confirm", "0"], ["--confirm", "-1"]])
def test_cli_refuses_a_bad_confirm_before_collecting(lab, capsys, extra):
    assert _cli(*extra) == monitor.EXIT_USAGE
    assert lab.collected == 0 and ">= 1" in capsys.readouterr().err


def test_cli_refuses_a_missing_baseline_before_collecting(lab, capsys):
    assert cli.main(["monitor", "--baseline", "inexistant"]) == monitor.EXIT_USAGE
    assert lab.collected == 0 and "introuvable" in capsys.readouterr().err


def test_cli_refuses_an_invalid_intent_before_collecting(tmp_path, lab, capsys):
    bad = tmp_path / "intent.yml"
    bad.write_text("assertions:\n  - {id: a}\n")
    assert _cli("--intent", str(bad)) == monitor.EXIT_USAGE
    assert lab.collected == 0


def test_cli_refuses_an_invalid_rules_file_before_collecting(tmp_path, lab):
    bad = tmp_path / "rules.yml"
    bad.write_text("rules: [oups]\n")
    assert _cli("--rules", str(bad)) == monitor.EXIT_USAGE
    assert lab.collected == 0


@pytest.mark.parametrize("bad_url", [
    "http://hooks.example.org/SENTINEL-SECRET-TOKEN", "ftp://x/SENTINEL-SECRET-TOKEN",
    "https://user:SENTINEL-SECRET-TOKEN@example.org/h",
])
def test_cli_refuses_an_unsafe_webhook_url_without_quoting_it(lab, monkeypatch, capsys, bad_url):
    monkeypatch.setenv(webhook.ENV_VAR, bad_url)
    assert _cli() == monitor.EXIT_USAGE
    captured = capsys.readouterr()
    assert lab.collected == 0
    assert "SENTINEL-SECRET-TOKEN" not in captured.out + captured.err
    assert webhook.ENV_VAR in captured.err


SECRET_VALUE = "Sentinel-Secret-Value-4242"
WEBHOOK = "https://hooks.example.org/api/SENTINEL-WEBHOOK-TOKEN"


def _defect(monkeypatch, message=None):
    """Un défaut interne dans la collecte, dont le message recopie un mot de passe et l'URL du webhook."""
    from netcheck import secrets
    secrets.SecretStr(SECRET_VALUE, "test")
    monkeypatch.setenv(webhook.ENV_VAR, WEBHOOK)

    def boom(*_a, **_k):
        raise RuntimeError(message or f"panne inattendue {SECRET_VALUE} {WEBHOOK}")
    monkeypatch.setattr(collector, "collect_all", boom)


def test_internal_defect_is_code_70_with_nothing_on_stderr(lab, monkeypatch, capsys, tmp_path):
    _defect(monkeypatch)
    code = _cli()
    captured = capsys.readouterr()
    assert code == cli.EXIT_INTERNAL == monitor.EXIT_INTERNAL == 70
    assert code not in (0, 1, 2, monitor.EXIT_USAGE, monitor.EXIT_LOCKED)   # ni statut, ni refus, ni verrou
    assert captured.err == ""                          # cron enverrait stderr par courriel
    assert "Erreur interne" in captured.out and "RuntimeError" in captured.out
    assert "Traceback" not in captured.out and SECRET_VALUE not in captured.out   # une ligne, sans trace
    assert not (tmp_path / "reports" / monitor.STATE_FILENAME).exists()   # état inchangé, aucune alerte


def test_internal_defect_trace_goes_to_summary_json_masked(lab, monkeypatch, capsys, tmp_path):
    _defect(monkeypatch)
    _cli()
    capsys.readouterr()
    path = tmp_path / "reports" / monitor.LATEST_DIRNAME / "summary.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["status"] == monitor.INTERNAL_STATUS == "DEFAUT_INTERNE" and data["baseline"] == "nominal"
    assert data["internal_error"]["type"] == "RuntimeError"
    trace = data["internal_error"]["trace"]
    assert "Traceback" in trace and "RuntimeError" in trace and "panne inattendue" in trace
    text = path.read_text(encoding="utf-8")
    assert SECRET_VALUE not in text and "SENTINEL-WEBHOOK-TOKEN" not in text
    assert "****" in trace and "<webhook>" in trace
    assert (path.stat().st_mode & 0o777) == 0o600


def test_internal_defect_removes_the_stale_reports_of_a_previous_run(lab, monkeypatch, capsys, tmp_path):
    assert _cli() == 0                                 # exécution saine : rapports écrits
    latest = tmp_path / "reports" / monitor.LATEST_DIRNAME
    assert (latest / "diff.json").exists()
    _defect(monkeypatch, message="panne")
    assert _cli() == 70
    capsys.readouterr()
    assert [p.name for p in latest.iterdir()] == ["summary.json"]


def test_internal_defect_with_dry_run_writes_nothing_and_shows_the_masked_trace_on_stdout(
        lab, monkeypatch, capsys, tmp_path):
    _defect(monkeypatch)
    assert _cli("--dry-run") == 70
    captured = capsys.readouterr()
    assert captured.err == "" and "RuntimeError" in captured.out and "Traceback" in captured.out
    assert SECRET_VALUE not in captured.out and "SENTINEL-WEBHOOK-TOKEN" not in captured.out
    assert not (tmp_path / "reports" / monitor.LATEST_DIRNAME).exists()     # (le verrou, lui, existe)
    assert not (tmp_path / "reports" / monitor.STATE_FILENAME).exists()


def test_internal_defect_with_unwritable_reports_is_said_on_stdout(lab, monkeypatch, capsys, tmp_path):
    _defect(monkeypatch, message="panne")
    blocker = tmp_path / "blocker"
    blocker.write_text("fichier", encoding="utf-8")
    monkeypatch.setattr(cli, "REPORTS_DIR", blocker)
    assert _cli("--state-file", str(tmp_path / "state.json")) == 70
    captured = capsys.readouterr()
    assert captured.err == "" and "NON écrite" in captured.out


def test_internal_defect_outside_run_monitor_is_also_70_and_silent(lab, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(webhook, "resolve_format", lambda *_a, **_k: (_ for _ in ()).throw(KeyError("x")))
    assert _cli() == 70
    assert capsys.readouterr().err == ""
    assert json.loads((tmp_path / "reports" / monitor.LATEST_DIRNAME / "summary.json"
                       ).read_text(encoding="utf-8"))["internal_error"]["type"] == "KeyError"


def test_a_defect_while_loading_is_internal_not_a_usage_refusal(lab, monkeypatch, capsys):
    monkeypatch.setattr(snapshot, "load", lambda _name: (_ for _ in ()).throw(TypeError("bug")))
    assert _cli() == 70 and capsys.readouterr().err == ""


def test_usage_refusals_still_use_stderr_and_code_3(lab, capsys):
    assert cli.main(["monitor", "--baseline", "nosuch"]) == 3
    assert "introuvable" in capsys.readouterr().err


def test_cli_lock_held_is_code_4(tmp_path, lab, capsys):
    state = tmp_path / "reports" / monitor.STATE_FILENAME
    with monitor.RunLock(monitor.lock_path_for(state)):
        assert _cli() == monitor.EXIT_LOCKED
    assert lab.collected == 0


def test_cli_dry_run_writes_nothing(tmp_path, lab, capsys):
    lab.results = ospf_lost()
    assert _cli("--dry-run") == 2
    assert not (tmp_path / "reports" / monitor.STATE_FILENAME).exists()
    assert not (tmp_path / "reports" / monitor.LATEST_DIRNAME).exists()
    assert "aperçu" in capsys.readouterr().out


def test_compliance_and_assertions_are_used_through_the_cli(tmp_path, lab, monkeypatch):
    rules = tmp_path / "rules.yml"
    rules.write_text(
        "rules:\n  - id: pw\n    description: mot de passe interdit\n    severity: critique\n"
        "    applies_to: all\n    kind: line_absent\n    pattern: '^password '\n")
    intent = tmp_path / "intent.yml"
    intent.write_text(
        "assertions:\n  - {id: o, description: d, device: r1, type: ospf_neighbors, count: 1}\n")
    assert _cli("--rules", str(rules), "--intent", str(intent)) == 0
    state = json.loads((tmp_path / "reports" / monitor.STATE_FILENAME).read_text())
    assert state["components"] == {"collect": "OK", "diff": "OK", "assert": "OK", "check": "OK"}
    assert compliance.load_rules(rules)


def test_a_usage_error_raised_after_loading_is_a_refusal_not_an_internal_defect(lab, tmp_path, capsys):
    inventory_file = tmp_path / "inv.yml"      # pas de `host` : refus d'usage détecté juste avant la collecte
    inventory_file.write_text("defaults: {device_type: linux, username: u, password: pw-long-enough}\n"
                              "routers:\n  r1: {}\n", encoding="utf-8")
    assert _cli("-i", str(inventory_file)) == 3
    err = capsys.readouterr().err
    assert "host" in err and "Traceback" not in err
    assert not (tmp_path / "reports" / monitor.LATEST_DIRNAME).exists()
