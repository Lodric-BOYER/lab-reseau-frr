"""Surveillance planifiée (`netcheck monitor`, Phase E, SPEC_v3 §8, objectif O5).

Exécution UNIQUE (pas de démon) : le planificateur est externe (cron ou timer systemd). Une
exécution = une collecte en direct, puis diff contre une référence, assertions et conformité sur
ces mêmes données, puis un statut global, puis -- seulement si le statut a changé -- une alerte.

LECTURE SEULE STRICTE : monitor ne lance jamais `guard`, ne lance aucun script, ne modifie aucun
équipement (la collecte passe par la liste blanche de commandes de collector.py). Il n'écrit que
son fichier d'état, son verrou et ses rapports locaux dans reports/ (ignoré par Git).

Statut global = le pire des composants, avec la correspondance validée :
  diff       OK / ATTENTION / ÉCHEC                       -> idem
  assert     ÉCHEC -> ÉCHEC ; NON ÉVALUABLE -> ATTENTION  (jamais un OK silencieux)
  check      critique/haute -> ÉCHEC ; moyenne/basse -> ATTENTION
  collecte   équipement injoignable -> ÉCHEC
Codes retour : 0 OK, 1 ATTENTION, 2 ÉCHEC, 3 configuration refusée ou exécution impossible,
4 exécution ignorée (un verrou est tenu par une exécution précédente encore en cours).

Anti-bruit (fichier d'état, deux statuts distincts) :
  observed : ce que le dernier relevé a vu ;
  notified : le dernier statut effectivement ANNONCÉ (webhook réussi).
Une alerte est due quand le statut observé diffère de `notified`, confirmé `--confirm N` fois de
suite (dans les deux sens : dégradation ET retour à la normale). Si l'envoi échoue, `notified` ne
bouge pas : la prochaine exécution réessaie -- c'est ce qui empêche une alerte perdue d'être
supprimée à jamais par l'anti-bruit.

Limite assumée : de NOUVEAUX constats pendant un ÉCHEC déjà annoncé n'envoient rien (le statut
n'a pas changé). Le rapport local est à jour, pas le salon.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from netcheck import __version__, assertions, compliance, diff, report, secrets, snapshot, webhook
from netcheck.inventory import Inventory
from netcheck.model import DeviceState

OK, ATTENTION, ECHEC = "OK", "ATTENTION", "ECHEC"
LABELS = {OK: "OK", ATTENTION: "ATTENTION", ECHEC: "ÉCHEC"}
_RANK = {OK: 0, ATTENTION: 1, ECHEC: 2}
EXIT_CODES = {OK: 0, ATTENTION: 1, ECHEC: 2}
EXIT_USAGE = 3
EXIT_LOCKED = 4

STATE_VERSION = 1
MAX_FINDINGS = 10          # constats listés dans une alerte, puis « et N autres »
MAX_MESSAGE_CHARS = 200
DISCORD_DESCRIPTION_MAX = 3500   # la limite de Discord est 4096 (6000 cumulés) : marge volontaire
_COMPONENT_ORDER = {"collect": 0, "diff": 1, "assert": 2, "check": 3}
_FORMATS = ("generic", "discord")

STATE_FILENAME = "monitor_state.json"
LATEST_DIRNAME = "monitor_latest"


def worst(*statuses: str) -> str:
    return max(statuses, key=lambda s: _RANK[s], default=OK)


# ------------------------------------------------------------------------------------------
# Évaluation : un statut par composant + la liste des constats qui l'expliquent
# ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Contribution:
    """Un constat qui pèse sur le statut. Liste blanche de champs : c'est tout ce qu'une alerte
    peut jamais contenir d'un constat (jamais de configuration, jamais `Violation.detail`)."""
    status: str      # ATTENTION | ECHEC
    severity: str    # libellé d'origine : CRITIQUE, ATTENTION, haute, moyenne, NON ÉVALUABLE...
    component: str   # collect | diff | assert | check
    device: str
    category: str
    message: str


@dataclass
class Evaluation:
    """Résultats bruts des composants (pour les rapports locaux) + conclusion."""
    status: str
    components: dict[str, str | None]
    contributions: list[Contribution]
    unreachable: dict[str, str]
    diff_findings: list[diff.Finding]
    diff_label: str
    assert_results: list[assertions.AssertionResult] | None = None
    assert_label: str | None = None
    violations: list[compliance.Violation] | None = None
    compliant: bool | None = None
    not_applicable: list[compliance.NotApplicable] | None = None


def diff_outcome(findings: list[diff.Finding]) -> tuple[str, list[Contribution]]:
    label, code = diff.verdict(findings)
    status = {0: OK, 1: ATTENTION, 2: ECHEC}[code]
    contributions = [
        Contribution(ECHEC if f.severity == diff.Severity.CRITIQUE else ATTENTION, f.severity.name,
                     "diff", f.device, f.category, f.message)
        for f in findings if f.expected_by is None and f.severity >= diff.Severity.ATTENTION
    ]
    return status, contributions


def assert_outcome(results: list[assertions.AssertionResult]) -> tuple[str, list[Contribution]]:
    contributions = []
    for r in results:
        if r.status == assertions.Status.OK:
            continue
        status = ECHEC if r.status == assertions.Status.ECHEC else ATTENTION  # NON ÉVALUABLE
        contributions.append(Contribution(status, r.status.value, "assert", r.assertion.device,
                                          r.assertion.id, r.detail or r.assertion.description))
    return worst(OK, *(c.status for c in contributions)), contributions


def check_outcome(violations: list[compliance.Violation]) -> tuple[str, list[Contribution]]:
    contributions = [
        Contribution(ECHEC if v.rule.severity in ("critique", "haute") else ATTENTION, v.rule.severity,
                     "check", v.device, v.rule.id, v.rule.description)  # description, jamais `detail`
        for v in violations
    ]
    return worst(OK, *(c.status for c in contributions)), contributions


def devices_from_collection(results: dict) -> tuple[dict[str, DeviceState], dict[str, DeviceState],
                                                     dict[str, str]]:
    """({tous}, {joignables}, {injoignables: erreur}) d'après collector.collect_all()."""
    everything: dict[str, DeviceState] = {}
    reachable: dict[str, DeviceState] = {}
    unreachable: dict[str, str] = {}
    for name, (ok, value) in sorted(results.items()):
        if ok:
            everything[name] = reachable[name] = value
        else:
            unreachable[name] = str(value)
            everything[name] = DeviceState(
                name=name, host="?", timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                reachable=False, error=str(value))
    return everything, reachable, unreachable


def evaluate(
    results: dict, baseline: dict[str, DeviceState], mgmt: set[str],
    intent: list[assertions.Assertion] | None, rules: list[compliance.Rule] | None,
) -> Evaluation:
    everything, reachable, unreachable = devices_from_collection(results)

    findings = diff.compare(baseline, everything, management_interfaces=mgmt)
    diff_status, contributions = diff_outcome(findings)
    # Un équipement injoignable devient UNE contribution explicite (ÉCHEC, validé) ; le constat
    # « équipement injoignable » du diff, qui dit la même chose, est retiré de la liste d'alerte.
    contributions = [c for c in contributions
                     if not (c.category == "device" and c.device in unreachable)]
    contributions += [
        Contribution(ECHEC, "INJOIGNABLE", "collect", name, "device",
                     "équipement injoignable (détail dans le rapport local)")
        for name in unreachable
    ]
    components: dict[str, str | None] = {
        "collect": ECHEC if unreachable else OK, "diff": diff_status, "assert": None, "check": None,
    }
    ev = Evaluation(OK, components, contributions, unreachable, findings, LABELS[diff_status])

    if intent is not None:
        ev.assert_results = assertions.evaluate(intent, reachable, management_interfaces=mgmt)
        ev.assert_label = assertions.verdict(ev.assert_results)[0]
        components["assert"], extra = assert_outcome(ev.assert_results)
        contributions += extra
    if rules is not None:
        ev.violations, ev.not_applicable = compliance.evaluate(rules, reachable, management_interfaces=mgmt)
        ev.compliant = compliance.verdict(ev.violations)[0]
        components["check"], extra = check_outcome(ev.violations)
        contributions += extra

    ev.status = worst(OK, *(s for s in components.values() if s is not None))
    return ev


# ------------------------------------------------------------------------------------------
# Fichier d'état (observed / notified / candidate) et décision d'alerte
# ------------------------------------------------------------------------------------------

@dataclass
class State:
    observed: dict | None = None      # {"status", "since", "at"}
    notified: dict | None = None      # {"status", "at"}
    candidate: dict | None = None     # {"status", "count", "since"} : changement en cours de confirmation
    incident_since: str | None = None
    components: dict = field(default_factory=dict)
    baseline: str | None = None
    last_report: str | None = None

    def to_dict(self) -> dict:
        return {
            "version": STATE_VERSION, "observed": self.observed, "notified": self.notified,
            "candidate": self.candidate, "incident_since": self.incident_since,
            "components": self.components, "baseline": self.baseline, "last_report": self.last_report,
        }


def _valid_status(value: object) -> bool:
    return isinstance(value, str) and value in _RANK


def _validate_state(raw: object) -> State:
    """Valide un état lu sur disque ; lève ValueError (message court, sans valeur du fichier)."""
    if not isinstance(raw, dict):
        raise ValueError("structure invalide")
    if raw.get("version") != STATE_VERSION:
        raise ValueError("version inconnue")
    for key, required in (("observed", ("status", "since", "at")), ("notified", ("status", "at")),
                          ("candidate", ("status", "count", "since"))):
        item = raw.get(key)
        if item is None:
            continue
        if not isinstance(item, dict) or not all(k in item for k in required) or not _valid_status(
                item["status"]):
            raise ValueError(f"champ '{key}' invalide")
        if any(not isinstance(item[k], str) for k in required if k not in ("status", "count")):
            raise ValueError(f"champ '{key}' invalide")
    candidate = raw.get("candidate")
    if candidate is not None and (not isinstance(candidate["count"], int) or isinstance(
            candidate["count"], bool) or candidate["count"] < 1):
        raise ValueError("champ 'candidate' invalide")
    if raw.get("incident_since") is not None and not isinstance(raw["incident_since"], str):
        raise ValueError("champ 'incident_since' invalide")
    return State(
        observed=raw.get("observed"), notified=raw.get("notified"), candidate=candidate,
        incident_since=raw.get("incident_since"),
        components=raw.get("components") if isinstance(raw.get("components"), dict) else {},
        baseline=raw.get("baseline") if isinstance(raw.get("baseline"), str) else None,
        last_report=raw.get("last_report") if isinstance(raw.get("last_report"), str) else None,
    )


def load_state(path: Path, quarantine: bool = True) -> tuple[State, str | None]:
    """(état, avertissement). Absent -> première exécution, sans avertissement. Illisible ou
    corrompu -> JAMAIS d'exception : copie conservée en <fichier>.corrupt, traité comme une
    première exécution, et l'avertissement est affiché dans la sortie. `quarantine=False`
    (--dry-run) : même diagnostic, mais le fichier n'est pas déplacé -- rien n'est écrit."""
    if not path.exists():
        return State(), None
    try:
        return _validate_state(json.loads(path.read_text(encoding="utf-8"))), None
    except json.JSONDecodeError:
        reason = "JSON invalide"
    except ValueError as e:  # inclut UnicodeDecodeError et nos propres refus de validation
        reason = str(e) if not isinstance(e, UnicodeDecodeError) else "encodage invalide"
    except OSError as e:
        reason = f"lecture impossible ({type(e).__name__})"
    if quarantine:
        try:
            path.replace(path.with_name(path.name + ".corrupt"))
        except OSError:
            pass
    return State(), f"fichier d'état illisible ({reason}) : traité comme une première exécution"


def save_state(path: Path, state: State) -> None:
    """Écriture atomique (fichier temporaire puis os.replace), droits 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@dataclass
class Decision:
    state: State                       # nouvel état (avant envoi éventuel)
    transition: tuple[str | None, str] | None   # (précédent annoncé, nouveau) si une alerte est due
    kind: str | None                   # first_report | degradation | improvement | recovery
    note: str                          # phrase affichée dans la sortie


def decide(state: State, status: str, now: str, confirm: int) -> Decision:
    """Cœur de l'anti-bruit (fonction pure). `now` : horodatage ISO de l'exécution."""
    new = State(**{**state.__dict__})
    obs = state.observed
    if obs is None or obs["status"] != status:
        new.observed = {"status": status, "since": now, "at": now}
    else:
        new.observed = {**obs, "at": now}

    announced = (state.notified or {}).get("status")
    if announced is None and status == OK:
        new.notified, new.candidate = {"status": OK, "at": now}, None
        return Decision(new, None, None, "premier relevé : OK, rien à annoncer")
    reference = announced or OK
    if status == reference:
        new.candidate = None
        return Decision(new, None, None, f"statut inchangé ({LABELS[status]}) : aucune alerte")

    cand = state.candidate
    if cand and cand["status"] == status:
        count, since = cand["count"] + 1, cand["since"]
    else:
        count, since = 1, now
    new.candidate = {"status": status, "count": count, "since": since}
    if count < confirm:
        return Decision(new, None, None,
                        f"changement vers {LABELS[status]} observé {count}/{confirm} fois : "
                        "en attente de confirmation, aucune alerte")

    if announced is None:
        kind = "first_report"
    elif status == OK:
        kind = "recovery"
    elif _RANK[status] > _RANK[announced]:
        kind = "degradation"
    else:
        kind = "improvement"
    return Decision(new, (announced, status), kind, f"changement confirmé : {_arrow(announced, status)}")


def apply_sent(state: State, status: str, now: str) -> None:
    """Enregistre un envoi réussi : `notified` avance, le compteur de confirmation repart à zéro."""
    previous = (state.notified or {}).get("status", OK)
    since = (state.candidate or {}).get("since", now)
    if status == OK:
        state.incident_since = None
    elif previous == OK or state.incident_since is None:
        state.incident_since = since
    state.notified = {"status": status, "at": now}
    state.candidate = None


def _arrow(previous: str | None, status: str) -> str:
    return f"{LABELS[previous] if previous else 'inconnu'} -> {LABELS[status]}"


# ------------------------------------------------------------------------------------------
# Verrou : une seule exécution à la fois
# ------------------------------------------------------------------------------------------

class LockHeld(Exception):
    """Un verrou est tenu par une autre exécution encore vivante."""

    def __init__(self, pid: int | None, since: str | None):
        super().__init__("verrou tenu")
        self.pid, self.since = pid, since


class RunLock:
    """flock(2) non bloquant sur <état>.lock, tenu pendant TOUTE l'exécution (collecte comprise).

    Verrou orphelin : le noyau libère un flock à la mort du processus (même par SIGKILL ou
    coupure de courant de la VM), donc un crash ne peut jamais laisser un verrou qui bloque les
    exécutions suivantes -- contrairement à un fichier .pid qu'il faudrait deviner périmé. Le
    descripteur n'est pas héritable (PEP 446) : un processus fils ne peut pas le garder vivant.
    Le fichier lui-même reste en place (le supprimer ouvrirait une course) ; pid et heure de
    début n'y sont écrits que pour le diagnostic."""

    def __init__(self, path: Path):
        self.path = path
        self._fd: int | None = None

    def __enter__(self) -> RunLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pid, since = self._read_info(fd)
            os.close(fd)
            raise LockHeld(pid, since) from None
        os.ftruncate(fd, 0)
        info = {"pid": os.getpid(), "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        os.write(fd, json.dumps(info).encode())
        self._fd = fd
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    @staticmethod
    def _read_info(fd: int) -> tuple[int | None, str | None]:
        try:
            info = json.loads(os.pread(fd, 4096, 0).decode())
            pid, since = info.get("pid"), info.get("started_at")
            return (pid if isinstance(pid, int) else None), (since if isinstance(since, str) else None)
        except (OSError, ValueError, AttributeError):
            return None, None


def lock_path_for(state_file: Path) -> Path:
    return state_file.with_name(state_file.name + ".lock")


def lock_held_message(error: LockHeld, now: datetime) -> str:
    parts = ["une exécution précédente de monitor est encore en cours"]
    detail = []
    if error.pid is not None:
        detail.append(f"pid {error.pid}")
    if error.since:
        try:
            age = int((now - datetime.fromisoformat(error.since)).total_seconds())
            detail.append(f"depuis {_human_duration(max(age, 0))}")
        except ValueError:
            pass
    if detail:
        parts.append(f"({', '.join(detail)})")
    return " ".join(parts) + " : exécution ignorée, aucune alerte, état inchangé"


# ------------------------------------------------------------------------------------------
# Alerte : contenu (liste blanche) et formats de webhook
# ------------------------------------------------------------------------------------------

_ICONS = {OK: "🟢", ATTENTION: "🟠", ECHEC: "🔴"}
_COLORS = {OK: 3066993, ATTENTION: 15965202, ECHEC: 15158332}   # 0x2ECC71, 0xF39C12, 0xE74C3C


@dataclass
class Alert:
    kind: str                    # first_report | degradation | improvement | recovery
    status: str
    previous: str | None
    local_time: str              # ISO avec fuseau local
    utc_time: str                # ISO UTC (champ `timestamp` d'un embed Discord)
    components: dict[str, str | None]
    devices: list[str]
    findings: list[Contribution]   # au plus MAX_FINDINGS, déjà masqués et tronqués
    more: int
    total: int
    report: str
    incident_seconds: int | None = None
    incident_since_hhmm: str | None = None


def _clean(text: str) -> str:
    """Passage obligatoire de tout texte d'alerte : masquage des secrets, une seule ligne, tronqué."""
    text = " ".join(secrets.mask_secrets(str(text)).split())
    return text if len(text) <= MAX_MESSAGE_CHARS else text[:MAX_MESSAGE_CHARS - 1] + "…"


def _sort_key(c: Contribution) -> tuple:
    return (-_RANK[c.status], _COMPONENT_ORDER.get(c.component, 9), c.device, c.category, c.message)


def build_alert(
    kind: str, decision_status: str, previous: str | None, evaluation: Evaluation, now: datetime,
    report_path: str, incident_since: str | None = None,
) -> Alert:
    unique = sorted(set(evaluation.contributions), key=_sort_key)
    shown = [Contribution(c.status, _clean(c.severity), c.component, _clean(c.device),
                          _clean(c.category), _clean(c.message)) for c in unique[:MAX_FINDINGS]]
    seconds = hhmm = None
    if incident_since:
        try:
            started = datetime.fromisoformat(incident_since)
            seconds = max(int((now - started).total_seconds()), 0)
            hhmm = started.astimezone().strftime("%H:%M")
        except ValueError:
            pass
    return Alert(
        kind=kind, status=decision_status, previous=previous,
        local_time=now.isoformat(timespec="seconds"),
        utc_time=now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        components=dict(evaluation.components),
        devices=sorted({_clean(c.device) for c in unique}),
        findings=shown, more=max(len(unique) - MAX_FINDINGS, 0), total=len(unique),
        report=report_path, incident_seconds=seconds, incident_since_hhmm=hhmm,
    )


def _human_duration(seconds: int) -> str:
    if seconds < 60:
        return "moins d'1 min"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60:02d}"


def to_generic(alert: Alert) -> dict:
    data = {
        "source": "netcheck", "netcheck_version": __version__,
        "event": "recovery" if alert.kind == "recovery" else "status_change",
        "kind": alert.kind, "status": alert.status, "previous_status": alert.previous,
        "timestamp": alert.local_time, "components": alert.components, "devices": alert.devices,
        "findings": [{"severity": c.severity, "component": c.component, "device": c.device,
                      "category": c.category, "message": c.message} for c in alert.findings],
        "more": alert.more, "report": alert.report,
    }
    if alert.kind == "recovery" and alert.incident_seconds is not None:
        data["incident_duration_s"] = alert.incident_seconds
    return data


_DISCORD_MARKDOWN = re.compile(r"([\\*_~`|>])")


def _discord_escape(text: str) -> str:
    return _DISCORD_MARKDOWN.sub(r"\\\1", text)


def _discord_title(alert: Alert) -> str:
    label = LABELS[alert.status]
    icon = _ICONS[alert.status]
    if alert.kind == "recovery":
        return f"{icon} netcheck : retour à la normale ({LABELS[alert.previous]} → OK)"
    if alert.kind == "first_report":
        return f"{icon} netcheck : premier relevé {label}"
    prefix = "amélioration, " if alert.kind == "improvement" else ""
    return f"{icon} netcheck : {prefix}{label} ({LABELS[alert.previous]} → {label})"


def to_discord(alert: Alert) -> dict:
    """Corps d'un webhook Discord (champs et limites vérifiés dans la documentation : « Webhook
    Resource » et « Message Resource », docs.discord.com). `allowed_mentions: {parse: []}` est
    OBLIGATOIRE : les textes viennent d'équipements, aucun « @everyone » ne doit pouvoir sonner."""
    footer_lines = [f"{name} {LABELS[state]}" for name, state in alert.components.items()
                    if state is not None and (name != "collect" or state != OK)]
    tail = f"\n\nRapport local : `{alert.report}`"
    if alert.kind == "recovery":
        head = "Plus aucun constat."
        if alert.incident_seconds is not None:
            head += f"\nIncident : {_human_duration(alert.incident_seconds)}"
            if alert.incident_since_hhmm:
                head += f" (depuis {alert.incident_since_hhmm})"
    else:
        plural = "constat" if alert.total == 1 else "constats"
        lines = [f"**{alert.total} {plural}** sur {_discord_escape(', '.join(alert.devices))}"]
        lines += [f"• [{_discord_escape(c.severity)}] {_discord_escape(c.device)} : "
                  f"{_discord_escape(c.message)}" for c in alert.findings]
        if alert.more:
            lines.append(f"… et {alert.more} autres")
        head = "\n".join(lines)
    room = DISCORD_DESCRIPTION_MAX - len(tail)
    if len(head) > room:
        head = head[:room - 1] + "…"
    return {
        "username": "netcheck",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": _discord_title(alert),
            "description": head + tail,
            "color": _COLORS[alert.status],
            "timestamp": alert.utc_time,
            "footer": {"text": " · ".join(footer_lines)},
        }],
    }


def payload_for(alert: Alert, fmt: str) -> dict:
    return to_discord(alert) if fmt == "discord" else to_generic(alert)


# ------------------------------------------------------------------------------------------
# Rapports locaux (réutilise report.write_*, qui masquent déjà les secrets)
# ------------------------------------------------------------------------------------------

def write_reports(directory: Path, evaluation: Evaluation, baseline_name: str,
                  intent_path: str | None, rules_path: str | None, now: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    managed = ["diff.json", "diff.html", "assert.json", "assert.html", "check.json", "check.html",
               "summary.json"]
    for name in managed:   # pas de fichier périmé d'une exécution précédente (ex. --intent retiré)
        (directory / name).unlink(missing_ok=True)

    report.write_json(evaluation.diff_findings, evaluation.diff_label, str(directory / "diff.json"))
    report.write_html(evaluation.diff_findings, evaluation.diff_label, baseline_name, "relevé en direct",
                      str(directory / "diff.html"))
    if evaluation.assert_results is not None:
        report.write_assert_json(evaluation.assert_results, evaluation.assert_label,
                                 str(directory / "assert.json"))
        report.write_assert_html(evaluation.assert_results, evaluation.assert_label, intent_path or "",
                                 str(directory / "assert.html"))
    if evaluation.violations is not None:
        report.write_compliance_json(evaluation.violations, evaluation.compliant,
                                     str(directory / "check.json"), evaluation.not_applicable)
        report.write_compliance_html(evaluation.violations, evaluation.compliant, rules_path or "",
                                     str(directory / "check.html"), evaluation.not_applicable)
    summary = {
        "timestamp": now, "status": evaluation.status, "baseline": baseline_name,
        "components": evaluation.components,
        "unreachable": sorted(evaluation.unreachable),
        "contributions": [
            {"status": c.status, "severity": _clean(c.severity), "component": c.component,
             "device": _clean(c.device), "category": _clean(c.category), "message": _clean(c.message)}
            for c in sorted(set(evaluation.contributions), key=_sort_key)
        ],
    }
    (directory / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


# ------------------------------------------------------------------------------------------
# Orchestration d'une exécution
# ------------------------------------------------------------------------------------------

@dataclass
class MonitorConfig:
    baseline_name: str
    baseline: dict[str, DeviceState]
    inventory: Inventory
    state_file: Path
    reports_dir: Path
    intent: list[assertions.Assertion] | None = None
    intent_path: str | None = None
    rules: list[compliance.Rule] | None = None
    rules_path: str | None = None
    webhook_url: str | None = None
    webhook_format: str = "generic"
    confirm: int = 1
    dry_run: bool = False
    repo_root: Path = snapshot.REPO_ROOT


@dataclass
class MonitorIO:
    collect: Callable[[], dict]
    send: Callable[[str, dict], webhook.SendResult]
    now: Callable[[], datetime]


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _component_line(components: dict[str, str | None]) -> str:
    parts = [f"{name} {LABELS[s] if s else 'non exécuté'}" for name, s in components.items()
             if name != "collect" or s != OK]
    return " · ".join(parts)


def run_monitor(cfg: MonitorConfig, io: MonitorIO) -> int:
    """Une exécution complète. Renvoie le code retour (voir le docstring de module)."""
    if cfg.webhook_format not in _FORMATS or cfg.confirm < 1:
        print("Erreur : paramètres de monitor invalides", file=sys.stderr)
        return EXIT_USAGE

    try:
        with RunLock(lock_path_for(cfg.state_file)):
            return _run_locked(cfg, io)
    except LockHeld as e:
        print(lock_held_message(e, io.now()), file=sys.stderr)
        return EXIT_LOCKED


def _run_locked(cfg: MonitorConfig, io: MonitorIO) -> int:
    now = io.now()
    now_iso = now.isoformat(timespec="seconds")
    state, warning = load_state(cfg.state_file, quarantine=not cfg.dry_run)
    if warning:
        print(f"Attention : {warning}")

    evaluation = evaluate(io.collect(), cfg.baseline, set(cfg.inventory.management_interfaces),
                          cfg.intent, cfg.rules)
    decision = decide(state, evaluation.status, now_iso, cfg.confirm)

    print(f"[{now_iso}] netcheck monitor : {LABELS[evaluation.status]} "
          f"({_component_line(evaluation.components)})")
    for c in sorted(set(evaluation.contributions), key=_sort_key)[:3]:
        print(f"  [{_clean(c.severity)}] {_clean(c.device)} : {_clean(c.message)}")
    if len(set(evaluation.contributions)) > 3:
        print(f"  … et {len(set(evaluation.contributions)) - 3} autres (voir le rapport local)")
    print(f"  → {decision.note}")

    latest = cfg.reports_dir / LATEST_DIRNAME
    stamp = now.strftime("%Y-%m-%d_%H%M%S")
    dated = cfg.reports_dir / f"monitor_{stamp}"

    if cfg.dry_run:
        _print_preview(cfg, decision, evaluation, now, dated)
        return EXIT_CODES[evaluation.status]

    try:
        write_reports(latest, evaluation, cfg.baseline_name, cfg.intent_path, cfg.rules_path, now_iso)
        print(f"  rapport : {_display_path(latest, cfg.repo_root)}")
    except OSError as e:
        print(f"Attention : rapport local non écrit ({type(e).__name__})", file=sys.stderr)
    state = decision.state
    state.components = dict(evaluation.components)
    state.baseline = cfg.baseline_name
    state.last_report = _display_path(latest, cfg.repo_root)

    if decision.transition is not None:
        _send_alert(cfg, io, decision, evaluation, state, now, now_iso, dated)

    try:
        save_state(cfg.state_file, state)
    except OSError as e:
        print(f"Erreur : état non enregistré ({type(e).__name__}) : une alerte pourrait être renvoyée "
              "à la prochaine exécution", file=sys.stderr)
    return EXIT_CODES[evaluation.status]


def _build(cfg: MonitorConfig, decision: Decision, evaluation: Evaluation, now: datetime,
           report_dir: Path) -> Alert:
    previous, status = decision.transition or ((decision.state.notified or {}).get("status"),
                                               evaluation.status)
    return build_alert(
        decision.kind or ("recovery" if status == OK else "degradation"), status, previous, evaluation,
        now, _display_path(report_dir, cfg.repo_root), incident_since=decision.state.incident_since,
    )


def _send_alert(cfg: MonitorConfig, io: MonitorIO, decision: Decision, evaluation: Evaluation,
                state: State, now: datetime, now_iso: str, dated: Path) -> None:
    previous, status = decision.transition
    if not cfg.webhook_url:
        print(f"  alerte due ({_arrow(previous, status)}) mais {webhook.ENV_VAR} n'est pas défini : "
              "alertes désactivées, rien n'est envoyé", file=sys.stderr)
        return
    try:
        write_reports(dated, evaluation, cfg.baseline_name, cfg.intent_path, cfg.rules_path, now_iso)
    except OSError as e:
        print(f"Attention : rapport daté non écrit ({type(e).__name__})", file=sys.stderr)
    alert = _build(cfg, decision, evaluation, now, dated)
    result = io.send(cfg.webhook_url, payload_for(alert, cfg.webhook_format))
    if result.ok:
        apply_sent(state, status, now_iso)
        state.last_report = _display_path(dated, cfg.repo_root)
        print(f"  alerte envoyée ({alert.kind} : {_arrow(previous, status)}), "
              f"{result.attempts} tentative(s)")
    else:
        error = webhook.redact(result.error or "erreur inconnue", cfg.webhook_url)
        print(f"  webhook : échec d'envoi ({error}) après {result.attempts} tentative(s) ; "
              "nouvelle tentative à la prochaine exécution", file=sys.stderr)


def _print_preview(cfg: MonitorConfig, decision: Decision, evaluation: Evaluation, now: datetime,
                   dated: Path) -> None:
    """--dry-run : montre EXACTEMENT le message qui serait envoyé. Rien n'est écrit ni envoyé.
    Sans transition due, l'aperçu montre le message qu'un changement de statut produirait."""
    if decision.transition is None:
        status = evaluation.status
        previous = (decision.state.notified or {}).get("status")
        kind = "recovery" if status == OK else "degradation"
        print("  aperçu (aucune alerte ne serait envoyée maintenant) :")
        alert = build_alert(kind, status, previous or (ECHEC if status == OK else OK), evaluation, now,
                            _display_path(dated, cfg.repo_root))
    else:
        print("  aperçu de l'alerte qui serait envoyée :")
        alert = _build(cfg, decision, evaluation, now, dated)
    print(json.dumps(payload_for(alert, cfg.webhook_format), indent=2, ensure_ascii=False))
    if not cfg.webhook_url:
        print(f"  ({webhook.ENV_VAR} n'est pas défini : aucune alerte réelle ne partirait)")
