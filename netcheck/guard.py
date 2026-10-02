"""Orchestration de `netcheck guard` : changement encadré, retour arrière optionnel (Phase D2,
SPEC_v3 §7, objectif O4).

Seule commande de netcheck qui exécute quelque chose de modifiant -- et ce sont toujours des
scripts FOURNIS PAR L'UTILISATEUR (changement, et désormais annulation), affichés et confirmés
ensemble avant toute action (C13). N'utiliser que sur un réseau dont on a l'autorisation écrite
(C16) : un retour arrière automatique reste une intervention sur des équipements.

Déroulé : snapshot avant -> script de changement -> convergence -> snapshot après -> diff (avec
--expect s'il est fourni) -> si le seuil est atteint OU si le script de changement a échoué :
script d'annulation (UNE seule fois, jamais en boucle) -> convergence -> preuve du retour (diff
avant <-> retour SANS --expect, zéro constat de toute gravité exigé).

Codes retour :
  0 succès                              3 erreur d'usage (avant toute action)
  1 attention, aucun rollback           4 échec annulé AVEC SUCCÈS (retour prouvé)
  2 échec, sans rollback                5 échec ET annulation échouée (état ≠ état initial)
                                        6 interrompu (Ctrl+C / SIGTERM) ou erreur interne :
                                          état du réseau inconnu, AUCUN rollback lancé

La logique de décision (rollback_reasons, outcome) est pure, et toutes les entrées/sorties
(snapshots, convergence, diff, exécution de script) sont injectées via GuardIO : la table des
issues se teste sans lab.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from netcheck import __version__, report
from netcheck.assertions import AssertionResult
from netcheck.diff import Finding
from netcheck.secrets import mask_secrets

EXIT_OK = 0
EXIT_ATTENTION = 1
EXIT_FAILED = 2
EXIT_USAGE = 3
EXIT_ROLLED_BACK = 4
EXIT_ROLLBACK_FAILED = 5
EXIT_INTERRUPTED = 6

STATE_CODES = {
    "SUCCESS": EXIT_OK,
    "ATTENTION": EXIT_ATTENTION,
    "FAILED_NO_ROLLBACK": EXIT_FAILED,
    "ROLLED_BACK": EXIT_ROLLED_BACK,
    "ROLLBACK_FAILED": EXIT_ROLLBACK_FAILED,
    "INTERRUPTED": EXIT_INTERRUPTED,
    "ERROR": EXIT_INTERRUPTED,
}

# --rollback-on : code de verdict minimal (diff.verdict) qui déclenche l'annulation.
ROLLBACK_THRESHOLDS = {"echec": 2, "attention": 1}
DEFAULT_SCRIPT_TIMEOUT = 120
PROOF_POLL_SECONDS = 3.0  # entre deux relevés de la preuve de retour (le script, lui, ne rejoue jamais)
_OUTPUT_TAIL_LINES = 50


# ------------------------------------------------------------------------------------------
# Décision pure
# ------------------------------------------------------------------------------------------

@dataclass
class ScriptResult:
    rc: int | None            # None = tué après dépassement du délai
    timed_out: bool = False
    duration: float = 0.0
    tail: list[str] = field(default_factory=list)  # dernières lignes de sortie (stdout+stderr)

    @property
    def failed(self) -> bool:
        return self.timed_out or self.rc != 0

    def as_dict(self) -> dict[str, Any]:
        return {"rc": self.rc, "timed_out": self.timed_out, "duration_s": round(self.duration, 2),
                "output_tail": self.tail}


def rollback_reasons(verdict_code: int, change: ScriptResult, rollback_on: str) -> list[str]:
    """Raisons de lancer l'annulation (liste vide = ne pas l'annuler)."""
    reasons = []
    if verdict_code >= ROLLBACK_THRESHOLDS[rollback_on]:
        label = {1: "ATTENTION", 2: "ÉCHEC"}.get(verdict_code, str(verdict_code))
        reasons.append(f"verdict {label} (seuil --rollback-on {rollback_on})")
    if change.timed_out:
        reasons.append("script de changement bloqué (délai dépassé)")
    elif change.rc != 0:
        reasons.append(f"script de changement terminé en code {change.rc}")
    return reasons


def outcome(verdict_code: int, change_failed: bool, rolled_back: bool, rollback_ok: bool) -> tuple[str, int]:
    """(état final, code retour). Un script de changement en échec vaut au minimum le code 2,
    même sans --rollback (comportement v0.3 : avant, un simple avertissement)."""
    if rolled_back:
        return ("ROLLED_BACK", EXIT_ROLLED_BACK) if rollback_ok else ("ROLLBACK_FAILED", EXIT_ROLLBACK_FAILED)
    if change_failed or verdict_code >= 2:
        return "FAILED_NO_ROLLBACK", EXIT_FAILED
    if verdict_code == 1:
        return "ATTENTION", EXIT_ATTENTION
    return "SUCCESS", EXIT_OK


# ------------------------------------------------------------------------------------------
# Exécution d'un script utilisateur, avec délai
# ------------------------------------------------------------------------------------------

def _kill_group(proc: subprocess.Popen) -> None:
    """Arrête le groupe de processus entier (le script ET ses fils, ex. docker exec), pas
    seulement bash : sinon un fils bloqué survivrait au délai."""
    for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def run_script(path: Path, timeout: float, echo: Callable[[str], None] | None = None) -> ScriptResult:
    """Exécute `bash <path>` dans son propre groupe de processus, sortie relayée en direct
    (echo) et conservée en queue. Dépasse `timeout` -> groupe tué, résultat timed_out. Sur
    interruption (Ctrl+C / SIGTERM), le groupe est arrêté puis l'exception repart : on ne laisse
    jamais un script de changement continuer seul après la fin de guard."""
    start = time.monotonic()
    proc = subprocess.Popen(
        ["bash", str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", bufsize=1, start_new_session=True,
    )
    tail: deque[str] = deque(maxlen=_OUTPUT_TAIL_LINES)

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            tail.append(line)
            if echo:
                echo(line)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
    except BaseException:
        _kill_group(proc)
        reader.join(timeout=2)
        raise
    reader.join(timeout=5)
    return ScriptResult(rc=None if timed_out else proc.returncode, timed_out=timed_out,
                        duration=time.monotonic() - start, tail=list(tail))


@contextmanager
def sigterm_as_interrupt() -> Iterator[None]:
    """Traite SIGTERM comme Ctrl+C pendant guard : même chemin d'interruption (journal
    INTERRUPTED, aucun rollback). Sans effet hors du thread principal."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


# ------------------------------------------------------------------------------------------
# Journal reports/guard_<horodatage>.json
# ------------------------------------------------------------------------------------------

def script_record(path: Path) -> dict[str, str]:
    """Empreinte d'un script pour le journal : chemin, SHA-256 du fichier, contenu MASQUÉ (un
    script de changement peut contenir un secret, ex. 'neighbor X password ...')."""
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "content": mask_secrets(raw.decode("utf-8", errors="replace"))}


def _mask_deep(value: Any) -> Any:
    """Masque tous les secrets du journal en un seul point d'écriture -- jamais oublié dans une
    étape particulière."""
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, list):
        return [_mask_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: _mask_deep(v) for k, v in value.items()}
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Journal:
    """Journal JSON de l'exécution, réécrit après chaque étape : une interruption brutale laisse
    quand même la trace de l'étape en cours."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.path = path
        self.data: dict[str, Any] = {"netcheck_version": __version__, "started_at": _now(), **header,
                                     "steps": [], "final_state": "RUNNING"}
        self.current_step: str | None = None

    def set(self, **fields: Any) -> None:
        self.data.update(fields)
        self.write()

    def begin(self, name: str) -> None:
        self.current_step = name
        self.data["current_step"] = name
        self.data["steps"].append({"name": name, "started_at": _now(), "ended_at": None, "detail": {}})
        self.write()

    def end(self, **detail: Any) -> None:
        step = self.data["steps"][-1]
        step["ended_at"], step["detail"] = _now(), detail
        self.current_step = None
        self.data["current_step"] = None
        self.write()

    def interrupted_step(self) -> str:
        """Étape en cours au moment d'une interruption (ou où on en était)."""
        return self.current_step or ("entre deux étapes" if self.data["steps"] else "initialisation")

    def finish(self, final_state: str, exit_code: int, **extra: Any) -> None:
        self.data.update(final_state=final_state, exit_code=exit_code, finished_at=_now(), **extra)
        self.write()

    def write(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(_mask_deep(self.data), indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass  # le journal ne doit jamais faire échouer ni masquer le résultat de guard


# ------------------------------------------------------------------------------------------
# Orchestration
# ------------------------------------------------------------------------------------------

@dataclass
class DiffResult:
    findings: list[Finding]
    verdict_label: str
    code: int
    after_results: list[AssertionResult] | None = None


@dataclass
class SnapshotNames:
    before: str
    after: str
    back: str


@dataclass
class GuardIO:
    """Toutes les entrées/sorties de guard, injectées : en production le lab réel, dans les
    tests de simples doublures."""
    snapshot: Callable[[str], None]
    wait_convergence: Callable[[float], bool]
    diff: Callable[[str, str, bool], DiffResult]  # (avant, après, appliquer --expect ?)
    run_script: Callable[[Path, float], ScriptResult]
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic


class UI:
    """Affichage de guard. Les tests le remplacent par une doublure silencieuse."""

    def info(self, message: str) -> None:
        print(message)

    def script_output(self, line: str) -> None:
        print(f"  │ {line}")

    def show_diff(self, result: DiffResult) -> None:
        report.print_terminal(result.findings, result.verdict_label, after_results=result.after_results)

    def final(self, state: str, code: int, details: dict[str, Any]) -> None:
        report.print_guard_final(state, code, details)


@dataclass
class GuardResult:
    code: int
    state: str
    diff_after: DiffResult | None = None
    diff_back: DiffResult | None = None


def run_guard(
    *, change: Path, rollback: Path | None, rollback_on: str, wait: float, script_timeout: float,
    io: GuardIO, ui: UI, journal: Journal, names: SnapshotNames,
) -> GuardResult:
    diff_after: DiffResult | None = None
    diff_back: DiffResult | None = None
    change_started = False
    try:
        ui.info(f"\nSnapshot avant : {names.before}")
        journal.begin("snapshot_avant")
        io.snapshot(names.before)
        journal.end()

        ui.info(f"Exécution du script de changement : {change}")
        journal.begin("script_changement")
        change_started = True
        change_res = io.run_script(change, script_timeout)
        journal.end(**change_res.as_dict())
        if change_res.failed:
            ui.info("Attention : " + ("script de changement bloqué, arrêté après le délai"
                                      if change_res.timed_out
                                      else f"le script de changement a rendu le code {change_res.rc}"))

        ui.info(f"Attente de convergence (max {wait:g}s)...")
        journal.begin("convergence_apres")
        converged = io.wait_convergence(wait)
        journal.end(converged=converged)
        if not converged:
            ui.info("Attention : convergence non confirmée dans le délai imparti")

        ui.info(f"Snapshot après : {names.after}")
        journal.begin("snapshot_apres")
        io.snapshot(names.after)
        journal.end()

        journal.begin("diff_apres")
        diff_after = io.diff(names.before, names.after, True)
        journal.end(verdict=diff_after.verdict_label, code=diff_after.code,
                    report=report.to_dict(diff_after.findings, diff_after.verdict_label,
                                          diff_after.after_results))
        ui.show_diff(diff_after)

        reasons = rollback_reasons(diff_after.code, change_res, rollback_on) if rollback else []
        if not (rollback and reasons):
            state, code = outcome(diff_after.code, change_res.failed, False, False)
            # Sans --rollback, un échec reste un échec : on liste ce qui le constitue.
            failure = rollback_reasons(diff_after.code, change_res, "echec")
            return _finish(ui, journal, state, code, {"reasons": failure}, diff_after, diff_back)

        ui.info("\nRetour arrière déclenché : " + " ; ".join(reasons))
        journal.set(rollback_triggered=True, rollback_reasons=reasons)
        journal.begin("script_annulation")
        rb_res = io.run_script(rollback, script_timeout)  # UNE seule exécution, jamais rejouée
        journal.end(**rb_res.as_dict())
        if rb_res.failed:
            ui.info("Attention : " + ("script d'annulation bloqué, arrêté après le délai"
                                      if rb_res.timed_out
                                      else f"le script d'annulation a rendu le code {rb_res.rc}"))

        ui.info(f"Attente de convergence (max {wait:g}s)...")
        journal.begin("convergence_retour")
        journal.end(converged=io.wait_convergence(wait))

        journal.begin("preuve_retour")
        diff_back, attempts = _prove_return(io, ui, names, wait)
        proven = not diff_back.findings
        journal.end(clean=proven, attempts=attempts, findings=len(diff_back.findings),
                    report=report.to_dict(diff_back.findings, diff_back.verdict_label))

        rollback_ok = proven and not rb_res.failed
        state, code = outcome(diff_after.code, change_res.failed, True, rollback_ok)
        details = {"reasons": reasons, "rollback_script_failed": rb_res.failed,
                   "rollback_script_rc": rb_res.rc, "rollback_timed_out": rb_res.timed_out,
                   "proven": proven, "remaining_findings": len(diff_back.findings)}
        return _finish(ui, journal, state, code, details, diff_after, diff_back)

    except KeyboardInterrupt:
        details = {"step": journal.interrupted_step(), "change_started": change_started}
        return _finish(ui, journal, "INTERRUPTED", EXIT_INTERRUPTED, details, diff_after, diff_back)
    except Exception as e:  # noqa: BLE001 -- état inconnu : jamais de rollback sur une erreur interne
        details = {"step": journal.interrupted_step(), "change_started": change_started,
                   "error": f"{type(e).__name__}: {e}"}
        return _finish(ui, journal, "ERROR", EXIT_INTERRUPTED, details, diff_after, diff_back)


def _prove_return(io: GuardIO, ui: UI, names: SnapshotNames, wait: float) -> tuple[DiffResult, int]:
    """Relève l'état jusqu'à ce que le diff avant <-> retour soit vide ou que `wait` expire.
    Ce sont des RELEVÉS répétés (l'état finit parfois de se stabiliser après la convergence
    OSPF/BGP) : le script d'annulation, lui, n'est jamais rejoué."""
    ui.info(f"Snapshot retour : {names.back} (preuve : diff avant <-> retour, zéro constat exigé)")
    deadline = io.clock() + wait
    attempts = 0
    while True:
        attempts += 1
        io.snapshot(names.back)
        result = io.diff(names.before, names.back, False)
        if not result.findings or io.clock() >= deadline:
            return result, attempts
        io.sleep(PROOF_POLL_SECONDS)


def _finish(
    ui: UI, journal: Journal, state: str, code: int, details: dict[str, Any],
    diff_after: DiffResult | None, diff_back: DiffResult | None,
) -> GuardResult:
    journal.finish(state, code, outcome_details=details)
    details = {**details, "journal": str(journal.path),
               "remaining": diff_back if diff_back is not None and diff_back.findings else None}
    ui.final(state, code, details)
    return GuardResult(code=code, state=state, diff_after=diff_after, diff_back=diff_back)
