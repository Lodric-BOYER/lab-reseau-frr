"""Sorties de netcheck : terminal (rich), JSON, HTML autonome.

Sécurité : les messages des constats contiennent du texte venant directement des
équipements (lignes de config, descriptions d'interface, etc.) — jamais de confiance.
L'autoescape Jinja2 est donc activé explicitement (pas seulement par défaut d'une
extension de fichier), et aucune valeur n'est marquée `|safe` nulle part dans le
template. Le filtrage (gravité/équipement) se fait en JavaScript pur, en montrant ou
masquant des lignes déjà rendues et échappées côté serveur (attribut `hidden`) :
aucune donnée n'est réinjectée via innerHTML.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from netcheck import __version__
from netcheck.assertions import AssertionResult, Status
from netcheck.diff import Finding, Severity
from netcheck.ruletypes import CAUSE_NO_MODEL, CAUSE_NOT_IMPLEMENTED, ConfigWarning, NotApplicable, Violation
from netcheck.secrets import mask_secrets

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,  # explicite : ne dépend pas de l'extension du fichier gabarit
)

_STYLE = {Severity.CRITIQUE: "bold red", Severity.ATTENTION: "yellow", Severity.INFO: "cyan"}
_COMPLIANCE_STYLE = {"critique": "bold red", "haute": "red", "moyenne": "yellow", "basse": "cyan"}
_COMPLIANCE_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "basse": 1}


# ------------------------------------------------------------------------------------------
# Masquage des secrets (Phase A, suite) : un seul point d'entrée par type de rapport, appliqué
# avant toute autre transformation (tri, comptage, gabarit) -- jamais oublié dans l'une des
# trois sorties puisque les trois fonctions de chaque rapport partent des mêmes objets masqués.
# ------------------------------------------------------------------------------------------

def _masked_findings(findings: list[Finding]) -> list[Finding]:
    return [replace(f, message=mask_secrets(f.message)) for f in findings]


def _masked_violations(violations: list[Violation]) -> list[Violation]:
    return [replace(v, detail=mask_secrets(v.detail)) for v in violations]


def _masked_not_applicable(not_applicable: list[NotApplicable]) -> list[NotApplicable]:
    return [replace(n, reason=mask_secrets(n.reason)) for n in not_applicable]


def _masked_warnings(warnings: list[ConfigWarning] | None) -> list[ConfigWarning]:
    """Avertissements d'analyse de la configuration (texte déjà masqué par confparse, remasqué ici :
    le point d'entrée du rapport ne fait confiance à personne)."""
    return [replace(w, warning=replace(w.warning, text=mask_secrets(w.warning.text),
                                       reason=mask_secrets(w.warning.reason)))
            for w in (warnings or [])]


def _summary_counts(
    violations: list[Violation], not_applicable: list[NotApplicable], warnings: list[ConfigWarning],
) -> dict[str, int]:
    """Synthèse des trois sorties. Chaque famille est comptée À PART : une règle « non implémentée »
    par un driver est un trou de couverture, pas une règle hors sujet ; une ligne non lue pèse sur le
    verdict, une ligne ambiguë non."""
    not_implemented = sum(1 for n in not_applicable if n.cause == CAUSE_NOT_IMPLEMENTED)
    no_model = sum(1 for n in not_applicable if n.cause == CAUSE_NO_MODEL)
    # Une entrée de dossier (ligne 0) n'est pas une ligne : un fichier que `check --config-dir` n'a pas pu
    # lire est « non audité », compté à part des lignes non lues ; les deux bloquent le verdict.
    not_audited = sum(1 for w in warnings if w.blocks_verdict and w.warning.line == 0)
    unread = sum(1 for w in warnings if w.blocks_verdict) - not_audited
    return {
        "violations": len(violations),
        "config_lines_unread": unread,
        "config_files_not_audited": not_audited,
        "config_notes": len(warnings) - unread - not_audited,
        "not_applicable": len(not_applicable),
        "not_applicable_not_implemented": not_implemented,
        "not_applicable_no_model": no_model,
        "not_applicable_out_of_scope": len(not_applicable) - not_implemented - no_model,
    }


def _status(violations: list[Violation], compliant: bool, warnings: list[ConfigWarning]) -> str:
    """Libellé du verdict (voir compliance.status_label) : NON CONFORME seulement s'il y a une
    violation réelle ; une ligne non lue sans violation donne ANALYSE INCOMPLÈTE."""
    if violations:
        return "NON CONFORME"
    if any(w.blocks_verdict for w in warnings):
        return "ANALYSE INCOMPLÈTE"
    return "CONFORME" if compliant else "NON CONFORME"


def _warning_status(w: ConfigWarning, markup: bool = False) -> str:
    """Statut affiché d'un avertissement d'analyse : NON LUE, STRUCTURE INCERTAINE ou information (pour un
    fichier de `check --config-dir`, ligne 0 : NON AUDITÉ ou information)."""
    if w.warning.line == 0:
        label, style = (("NON AUDITÉ", "bold yellow") if w.blocks_verdict
                        else ("information (fichier)", "cyan"))
    elif not w.kept:
        label, style = "NON LUE", "bold yellow"
    elif w.blocks_verdict:
        label, style = "STRUCTURE INCERTAINE", "bold yellow"
    else:
        label, style = "information (lue, ambiguë)", "cyan"
    return f"[{style}]{label}[/]" if markup else label


def _na_label(n: NotApplicable) -> str:
    if n.cause == CAUSE_NOT_IMPLEMENTED:
        return "NON IMPLÉMENTÉ"
    if n.cause == CAUSE_NO_MODEL:
        return "ÉTAT REQUIS (hors ligne)"
    return "hors sujet (driver)"


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Compteurs par gravité des constats NON prévus (les PRÉVUS sont comptés à part)."""
    return {s: sum(1 for f in findings if f.severity == s and f.expected_by is None) for s in Severity}


def _planned_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.expected_by is not None)


def _sort_key(f: Finding) -> tuple[bool, int]:
    """Constats à traiter d'abord (non prévus, du plus grave au moins grave), PRÉVUS ensuite."""
    return (f.expected_by is not None, -f.severity)


def _after_list(after_results: list[AssertionResult]) -> list[dict]:
    return [
        {"id": r.assertion.id, "device": r.assertion.device, "type": r.assertion.type,
         "status": r.status.value, "detail": r.detail}
        for r in after_results
    ]


def print_terminal(
    findings: list[Finding], verdict_label: str, console: Console | None = None,
    after_results: list[AssertionResult] | None = None,
) -> None:
    console = console or Console()
    findings = _masked_findings(findings)

    if findings:
        any_planned = _planned_count(findings) > 0
        table = Table(show_lines=False)
        table.add_column("Gravité")
        table.add_column("Équipement")
        table.add_column("Catégorie")
        table.add_column("Message", overflow="fold")
        if any_planned:
            table.add_column("Prévu par")
        for f in sorted(findings, key=_sort_key):
            if f.expected_by is None:
                label = f"[{_STYLE[f.severity]}]{f.severity.name}[/]"
            else:
                label = f"[green]PRÉVU[/] ({f.severity.name.lower()})"
            row = [label, f.device, f.category, f.message]
            if any_planned:
                row.append(f.expected_by or "")
            table.add_row(*row)
        console.print(table)
    else:
        console.print("Aucun constat.")

    if after_results:
        ok = sum(1 for r in after_results if r.status == Status.OK)
        ko = sum(1 for r in after_results if r.status == Status.ECHEC)
        ne = sum(1 for r in after_results if r.status == Status.NON_EVALUABLE)
        console.print(f"États attendus : {ok} OK, {ko} échec(s), {ne} non évaluable(s)")

    counts = _severity_counts(findings)
    planned = _planned_count(findings)
    extra = f", {planned} prévu(s)" if planned else ""
    console.print(
        f"Verdict : [bold]{verdict_label}[/bold]  "
        f"({counts[Severity.CRITIQUE]} critique(s), {counts[Severity.ATTENTION]} attention, "
        f"{counts[Severity.INFO]} info{extra})"
    )


def to_dict(
    findings: list[Finding], verdict_label: str, after_results: list[AssertionResult] | None = None,
) -> dict:
    findings = _masked_findings(findings)
    data: dict = {
        "verdict": verdict_label,
        "findings": [
            {
                "severity": f.severity.name, "category": f.category, "device": f.device,
                "message": f.message, "planned": f.expected_by is not None,
                "expected_by": f.expected_by,
            }
            for f in findings
        ],
    }
    if after_results is not None:
        data["after"] = _after_list(after_results)
    return data


def write_json(
    findings: list[Finding], verdict_label: str, path: str,
    after_results: list[AssertionResult] | None = None,
) -> None:
    Path(path).write_text(
        json.dumps(to_dict(findings, verdict_label, after_results), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def render_html(
    findings: list[Finding], verdict_label: str, before_name: str, after_name: str,
    after_results: list[AssertionResult] | None = None,
) -> str:
    """Rend le rapport HTML autonome (aucune ressource externe, CSS/JS intégrés)."""
    findings = _masked_findings(findings)
    template = _ENV.get_template("report.html.j2")
    counts = {s.name: n for s, n in _severity_counts(findings).items()}
    devices = sorted({f.device for f in findings})
    return template.render(
        verdict=verdict_label,
        findings=sorted(findings, key=_sort_key),
        counts=counts,
        planned_count=_planned_count(findings),
        after_results=after_results or [],
        devices=devices,
        before_name=before_name,
        after_name=after_name,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        netcheck_version=__version__,
    )


def write_html(
    findings: list[Finding], verdict_label: str, before_name: str, after_name: str, path: str,
    after_results: list[AssertionResult] | None = None,
) -> None:
    Path(path).write_text(
        render_html(findings, verdict_label, before_name, after_name, after_results), encoding="utf-8",
    )


# ------------------------------------------------------------------------------------------
# Conformité (netcheck check) : mêmes principes, vocabulaire de gravité différent (§5.4)
# ------------------------------------------------------------------------------------------

def print_compliance_terminal(
    violations: list[Violation], compliant: bool,
    not_applicable: list[NotApplicable] | None = None,
    console: Console | None = None,
    config_warnings: list[ConfigWarning] | None = None,
    source: dict | None = None,
) -> None:
    console = console or Console()
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])
    warnings = _masked_warnings(config_warnings)

    if source:
        # Mode hors ligne (check --config-dir) : dire d'où vient chaque équipement et ce que cela change.
        devices = source["devices"]
        console.print(f"[bold]Mode hors ligne[/bold] (--config-dir) : {len(devices)} équipement(s) lu(s) "
                      "depuis des fichiers, aucun équipement interrogé.")
        for name, info in devices.items():
            console.print(f"  {name:<8} {info['driver']:<8} {escape(info['file'])}")
        console.print("Les règles qui lisent l'état collecté (interfaces) sont "
                      "[bold yellow]non évaluables[/] hors ligne : voir « Non applicable », cause "
                      "« ÉTAT REQUIS (hors ligne) ».\n")

    if violations:
        table = Table(show_lines=False)
        table.add_column("Gravité")
        table.add_column("Équipement")
        table.add_column("Catégorie")
        table.add_column("Règle")
        table.add_column("Détail", overflow="fold")
        for v in sorted(violations, key=lambda v: -_COMPLIANCE_ORDER[v.rule.severity]):
            style = _COMPLIANCE_STYLE[v.rule.severity]
            table.add_row(f"[{style}]{v.rule.severity.upper()}[/]", v.device,
                          v.rule.category or "—", v.rule.id, v.detail)
        console.print(table)
    else:
        console.print("Aucune non-conformité.")

    # Analyse de la configuration (Phase A3) : une ligne NON lue empêche de conclure « conforme » ;
    # une ligne lue mais ambiguë n'est qu'une information.
    if warnings:
        analysis = Table(show_lines=False, title="Analyse de la configuration")
        analysis.add_column("Équipement")
        analysis.add_column("Ligne")
        analysis.add_column("Statut")
        analysis.add_column("Raison", overflow="fold")
        analysis.add_column("Texte", overflow="fold")
        for w in sorted(warnings, key=lambda w: (not w.blocks_verdict, w.device, w.warning.line)):
            status = _warning_status(w, markup=True)
            analysis.add_row(w.device, str(w.warning.line) if w.warning.line else "—", status,
                             escape(w.warning.reason), escape(w.warning.text))
        console.print(analysis)

    # Références (Phase A, C14) : une ligne par règle concernée, titres seulement (les URLs
    # complètes sont dans le JSON/HTML) -- pas de doublon si plusieurs équipements violent la
    # même règle.
    rules_with_refs = {v.rule.id: v.rule for v in violations if v.rule.references}
    if rules_with_refs:
        console.print("\n[bold]Références :[/bold]")
        for rule in sorted(rules_with_refs.values(), key=lambda r: r.id):
            titles = ", ".join(ref["title"] for ref in rule.references)
            console.print(f"  {rule.id} : {titles}")

    if not_applicable:
        na_table = Table(show_lines=False, title="Non applicable (Phase D2)")
        na_table.add_column("Équipement")
        na_table.add_column("Règle")
        na_table.add_column("Cause")
        na_table.add_column("Raison", overflow="fold")
        for na in sorted(not_applicable, key=lambda n: (n.device, n.rule.id)):
            gap = na.cause in (CAUSE_NOT_IMPLEMENTED, CAUSE_NO_MODEL)
            cause = f"[bold yellow]{_na_label(na)}[/]" if gap else _na_label(na)
            na_table.add_row(na.device, na.rule.id, cause, na.reason)
        console.print(na_table)

    counts = _summary_counts(violations, not_applicable, warnings)
    label = _status(violations, compliant, warnings)
    parts = [f"{counts['violations']} non-conformité(s)"]
    if counts["config_lines_unread"]:
        parts.append(f"{counts['config_lines_unread']} ligne(s) de configuration non lue(s) ou incertaine(s)")
    if counts["config_files_not_audited"]:
        parts.append(f"{counts['config_files_not_audited']} fichier(s) non audité(s)")
    if counts["config_notes"]:
        parts.append(f"{counts['config_notes']} information(s) d'analyse")
    if counts["not_applicable"]:
        na_part = f"{counts['not_applicable']} non applicable(s)"
        if counts["not_applicable_not_implemented"]:
            na_part += f" dont {counts['not_applicable_not_implemented']} non implémentée(s) par leur driver"
        if counts["not_applicable_no_model"]:
            na_part += (f" dont {counts['not_applicable_no_model']} non évaluable(s) hors ligne "
                        "(état requis)")
        parts.append(na_part)
    console.print(f"Conformité : [bold]{label}[/bold]  ({', '.join(parts)})")


def compliance_to_dict(
    violations: list[Violation], compliant: bool, not_applicable: list[NotApplicable] | None = None,
    config_warnings: list[ConfigWarning] | None = None, source: dict | None = None,
) -> dict:
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])
    warnings = _masked_warnings(config_warnings)
    data = {
        "compliant": compliant,
        # CONFORME | NON CONFORME (violation réelle) | ANALYSE INCOMPLÈTE (ligne non lue, aucune violation)
        "status": _status(violations, compliant, warnings),
        "violations": [
            {
                "severity": v.rule.severity, "rule_id": v.rule.id, "device": v.device, "detail": v.detail,
                "category": v.rule.category, "references": v.rule.references,
            }
            for v in violations
        ],
        "not_applicable": [
            {
                "rule_id": n.rule.id, "device": n.device, "reason": n.reason, "cause": n.cause,
                "category": n.rule.category, "references": n.rule.references,
            }
            for n in (not_applicable or [])
        ],
        # Phase A3 : lignes de configuration que l'analyse n'a pas classées proprement. `kept` faux =
        # ligne NON lue (le verdict ne peut plus être « conforme ») ; vrai = lue mais ambiguë.
        "config_analysis": [
            {"device": w.device, "line": w.warning.line, "kept": w.kept, "blocks_verdict": w.blocks_verdict,
             "reason": w.warning.reason, "text": w.warning.text}
            for w in warnings
        ],
        "summary": _summary_counts(violations, not_applicable, warnings),
    }
    if source:
        # Présent seulement hors ligne (check --config-dir) : d'où vient chaque équipement.
        data["source"] = source
    return data


def write_compliance_json(
    violations: list[Violation], compliant: bool, path: str,
    not_applicable: list[NotApplicable] | None = None,
    config_warnings: list[ConfigWarning] | None = None, source: dict | None = None,
) -> None:
    Path(path).write_text(
        json.dumps(compliance_to_dict(violations, compliant, not_applicable, config_warnings, source),
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def render_compliance_html(
    violations: list[Violation], compliant: bool, rules_path: str,
    not_applicable: list[NotApplicable] | None = None,
    config_warnings: list[ConfigWarning] | None = None,
    source: dict | None = None,
) -> str:
    """Rend le rapport HTML de conformité, autonome (aucune ressource externe)."""
    template = _ENV.get_template("compliance.html.j2")
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])
    warnings = _masked_warnings(config_warnings)
    counts = {sev: sum(1 for v in violations if v.rule.severity == sev) for sev in _COMPLIANCE_ORDER}
    devices = sorted({v.device for v in violations} | {n.device for n in not_applicable}
                     | {w.device for w in warnings})
    # Regroupement par catégorie (Phase A, C14) : None -> "(sans catégorie)" pour les règles
    # antérieures à la Phase A, qui n'ont jamais ce champ.
    categories = sorted({v.rule.category or "(sans catégorie)" for v in violations})
    return template.render(
        compliant=compliant,
        status=_status(violations, compliant, warnings),
        violations=sorted(violations, key=lambda v: -_COMPLIANCE_ORDER[v.rule.severity]),
        not_applicable=sorted(not_applicable, key=lambda n: (n.device, n.rule.id)),
        not_implemented=CAUSE_NOT_IMPLEMENTED,
        no_model=CAUSE_NO_MODEL,
        source=source,
        config_warnings=sorted(warnings, key=lambda w: (not w.blocks_verdict, w.device, w.warning.line)),
        warning_status=_warning_status,
        summary=_summary_counts(violations, not_applicable, warnings),
        counts=counts,
        devices=devices,
        categories=categories,
        rules_path=str(rules_path),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        netcheck_version=__version__,
    )


def write_compliance_html(
    violations: list[Violation], compliant: bool, rules_path: str, path: str,
    not_applicable: list[NotApplicable] | None = None,
    config_warnings: list[ConfigWarning] | None = None, source: dict | None = None,
) -> None:
    Path(path).write_text(
        render_compliance_html(violations, compliant, rules_path, not_applicable, config_warnings, source),
        encoding="utf-8",
    )


# ------------------------------------------------------------------------------------------
# État attendu (netcheck assert, Phase C) : mêmes principes que diff/check, un troisième
# vocabulaire de statut (OK / ÉCHEC / NON ÉVALUABLE, §6). Le "detail" d'un résultat "path" ne
# contient jamais de texte de config (assert ne lit que le modèle normalisé) : pas de masquage
# de secrets nécessaire ici, contrairement à diff/check.
# ------------------------------------------------------------------------------------------

_ASSERT_STYLE = {Status.OK: "bold green", Status.ECHEC: "bold red", Status.NON_EVALUABLE: "yellow"}
_ASSERT_ORDER = {Status.ECHEC: 3, Status.NON_EVALUABLE: 2, Status.OK: 1}


def print_assert_terminal(
    results: list[AssertionResult], verdict_label: str, console: Console | None = None,
) -> None:
    console = console or Console()

    if results:
        table = Table(show_lines=False)
        table.add_column("Statut")
        table.add_column("Équipement")
        table.add_column("Assertion")
        table.add_column("Détail", overflow="fold")
        for r in sorted(results, key=lambda r: -_ASSERT_ORDER[r.status]):
            style = _ASSERT_STYLE[r.status]
            table.add_row(f"[{style}]{r.status.value}[/]", r.assertion.device, r.assertion.id,
                          r.detail or r.assertion.description)
        console.print(table)
    else:
        console.print("Aucune assertion.")

    counts = {s: sum(1 for r in results if r.status == s) for s in Status}
    console.print(
        f"Verdict : [bold]{verdict_label}[/bold]  "
        f"({counts[Status.OK]} OK, {counts[Status.ECHEC]} échec(s), "
        f"{counts[Status.NON_EVALUABLE]} non évaluable(s))"
    )


def assert_to_dict(results: list[AssertionResult], verdict_label: str) -> dict:
    return {
        "verdict": verdict_label,
        "results": [
            {
                "id": r.assertion.id, "device": r.assertion.device, "type": r.assertion.type,
                "status": r.status.value, "detail": r.detail,
            }
            for r in results
        ],
    }


def write_assert_json(results: list[AssertionResult], verdict_label: str, path: str) -> None:
    Path(path).write_text(
        json.dumps(assert_to_dict(results, verdict_label), indent=2, ensure_ascii=False), encoding="utf-8",
    )


def render_assert_html(results: list[AssertionResult], verdict_label: str, intent_path: str) -> str:
    """Rend le rapport HTML autonome (aucune ressource externe)."""
    template = _ENV.get_template("assert.html.j2")
    counts = {s.value: sum(1 for r in results if r.status == s) for s in Status}
    devices = sorted({r.assertion.device for r in results})
    return template.render(
        verdict=verdict_label,
        results=sorted(results, key=lambda r: -_ASSERT_ORDER[r.status]),
        counts=counts,
        devices=devices,
        intent_path=str(intent_path),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        netcheck_version=__version__,
    )


def write_assert_html(
    results: list[AssertionResult], verdict_label: str, intent_path: str, path: str,
) -> None:
    Path(path).write_text(render_assert_html(results, verdict_label, intent_path), encoding="utf-8")


# ------------------------------------------------------------------------------------------
# Message final de `guard` (Phase D2) : l'annulation échouée et l'interruption doivent être
# IMPOSSIBLES À RATER -- cadre rouge sur stderr, code retour dédié rappelé dans le message.
# ------------------------------------------------------------------------------------------

_GUARD_STEP_LABELS = {
    "snapshot_avant": "le snapshot avant",
    "script_changement": "le script de changement",
    "convergence_apres": "l'attente de convergence après le changement",
    "snapshot_apres": "le snapshot après",
    "diff_apres": "le diff après changement",
    "script_annulation": "le script d'annulation",
    "convergence_retour": "l'attente de convergence après l'annulation",
    "preuve_retour": "la preuve du retour (diff avant <-> retour)",
}
_GUARD_ALARM_STATES = {"FAILED_NO_ROLLBACK", "ROLLBACK_FAILED", "INTERRUPTED", "ERROR"}


def guard_final_message(state: str, code: int, details: dict) -> tuple[str, list[str]]:
    """(titre, lignes de détail) du message final de guard -- pur, donc testable sans console."""
    reasons = list(details.get("reasons", []))
    step = _GUARD_STEP_LABELS.get(details.get("step", ""), details.get("step", "?"))
    lines: list[str] = []

    if state == "SUCCESS":
        title = "✅ CHANGEMENT RÉUSSI"
    elif state == "ATTENTION":
        title = "⚠️  CHANGEMENT TERMINÉ AVEC ATTENTION"
        lines.append("aucun retour arrière déclenché (seuil non atteint, ou pas de --rollback)")
    elif state == "FAILED_NO_ROLLBACK":
        title = "❌ CHANGEMENT ÉCHOUÉ — AUCUN RETOUR ARRIÈRE LANCÉ"
        lines += reasons
        lines.append("pas de --rollback fourni : le réseau est resté dans l'état « après »")
    elif state == "ROLLED_BACK":
        title = "↩️  CHANGEMENT ÉCHOUÉ — ANNULÉ AVEC SUCCÈS"
        lines += [f"déclenché par : {r}" for r in reasons]
        lines.append("état initial PROUVÉ : le diff avant <-> retour ne contient aucun constat")
    elif state == "ROLLBACK_FAILED":
        title = "🚨 CHANGEMENT ÉCHOUÉ ET ANNULATION ÉCHOUÉE"
        lines.append("LE RÉSEAU N'EST PAS DANS SON ÉTAT INITIAL")
        lines += [f"déclenché par : {r}" for r in reasons]
        if details.get("rollback_timed_out"):
            lines.append("le script d'annulation était bloqué (arrêté après le délai)")
        elif details.get("rollback_script_failed"):
            lines.append(f"le script d'annulation a rendu le code {details.get('rollback_script_rc')}")
        if not details.get("proven"):
            lines.append(f"{details.get('remaining_findings', '?')} écart(s) restant(s) entre l'état "
                         f"initial et l'état actuel (détail ci-dessus)")
        lines.append("INTERVENTION MANUELLE REQUISE")
    elif state == "INTERRUPTED":
        # Titre COURT, phrase clé sur sa propre ligne : un titre de cadre trop long est tronqué
        # à la largeur du terminal, et c'est justement la fin de la phrase qui se perdrait.
        title = f"⛔ INTERROMPU pendant {step}"
        lines.append("vérifie l'état du réseau : l'annulation n'a PAS été lancée")
        if not details.get("change_started"):
            lines.append("le script de changement n'avait pas démarré : guard n'a rien modifié")
    else:  # ERROR
        title = f"⛔ ERREUR INTERNE pendant {step}"
        lines.append("état du réseau inconnu : l'annulation n'a PAS été lancée")
        lines.append(str(details.get("error", "")))
        if not details.get("change_started"):
            lines.append("le script de changement n'avait pas démarré : guard n'a rien modifié")

    if details.get("journal"):
        lines.append(f"journal : {details['journal']}")
    lines.append(f"code retour : {code}")
    return title, lines


def print_guard_final(
    state: str, code: int, details: dict,
    console: Console | None = None, err_console: Console | None = None,
) -> None:
    title, lines = guard_final_message(state, code, details)
    out, err = console or Console(), err_console or Console(stderr=True)
    remaining = details.get("remaining")
    if remaining is not None:
        out.print("\nÉcarts restants entre l'état initial (avant) et l'état actuel :")
        print_terminal(remaining.findings, remaining.verdict_label, console=out)
    # escape() : un message d'erreur ou un nom de script ne doit jamais être lu comme du balisage rich.
    if state in _GUARD_ALARM_STATES:
        style = "bold white on red" if state in {"ROLLBACK_FAILED", "INTERRUPTED", "ERROR"} else "bold red"
        # Le message va dans le CORPS du cadre (replié proprement), pas dans son titre.
        err.print(Panel(escape(title + "\n\n" + "\n".join(lines)), title=f"netcheck guard : code {code}",
                        border_style="bold red", style=style, expand=True))
    else:
        out.print(f"\n[bold]{escape(title)}[/bold]")
        for line in lines:
            out.print(f"  {escape(line)}")
