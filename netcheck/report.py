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
from rich.table import Table

from netcheck import __version__
from netcheck.assertions import AssertionResult, Status
from netcheck.compliance import NotApplicable, Violation
from netcheck.diff import Finding, Severity
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


def print_terminal(findings: list[Finding], verdict_label: str, console: Console | None = None) -> None:
    console = console or Console()
    findings = _masked_findings(findings)

    if findings:
        table = Table(show_lines=False)
        table.add_column("Gravité")
        table.add_column("Équipement")
        table.add_column("Catégorie")
        table.add_column("Message", overflow="fold")
        for f in sorted(findings, key=lambda f: -f.severity):
            table.add_row(f"[{_STYLE[f.severity]}]{f.severity.name}[/]", f.device, f.category, f.message)
        console.print(table)
    else:
        console.print("Aucun constat.")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    console.print(
        f"Verdict : [bold]{verdict_label}[/bold]  "
        f"({counts[Severity.CRITIQUE]} critique(s), {counts[Severity.ATTENTION]} attention, "
        f"{counts[Severity.INFO]} info)"
    )


def to_dict(findings: list[Finding], verdict_label: str) -> dict:
    findings = _masked_findings(findings)
    return {
        "verdict": verdict_label,
        "findings": [
            {"severity": f.severity.name, "category": f.category, "device": f.device, "message": f.message}
            for f in findings
        ],
    }


def write_json(findings: list[Finding], verdict_label: str, path: str) -> None:
    Path(path).write_text(
        json.dumps(to_dict(findings, verdict_label), indent=2, ensure_ascii=False), encoding="utf-8",
    )


def render_html(findings: list[Finding], verdict_label: str, before_name: str, after_name: str) -> str:
    """Rend le rapport HTML autonome (aucune ressource externe, CSS/JS intégrés)."""
    findings = _masked_findings(findings)
    template = _ENV.get_template("report.html.j2")
    counts = {s.name: sum(1 for f in findings if f.severity == s) for s in Severity}
    devices = sorted({f.device for f in findings})
    return template.render(
        verdict=verdict_label,
        findings=sorted(findings, key=lambda f: -f.severity),
        counts=counts,
        devices=devices,
        before_name=before_name,
        after_name=after_name,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        netcheck_version=__version__,
    )


def write_html(
    findings: list[Finding], verdict_label: str, before_name: str, after_name: str, path: str,
) -> None:
    Path(path).write_text(render_html(findings, verdict_label, before_name, after_name), encoding="utf-8")


# ------------------------------------------------------------------------------------------
# Conformité (netcheck check) : mêmes principes, vocabulaire de gravité différent (§5.4)
# ------------------------------------------------------------------------------------------

def print_compliance_terminal(
    violations: list[Violation], compliant: bool,
    not_applicable: list[NotApplicable] | None = None,
    console: Console | None = None,
) -> None:
    console = console or Console()
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])

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
        na_table.add_column("Raison", overflow="fold")
        for na in sorted(not_applicable, key=lambda n: (n.device, n.rule.id)):
            na_table.add_row(na.device, na.rule.id, na.reason)
        console.print(na_table)

    label = "CONFORME" if compliant else "NON CONFORME"
    extra = f", {len(not_applicable)} non applicable(s)" if not_applicable else ""
    console.print(f"Conformité : [bold]{label}[/bold]  ({len(violations)} non-conformité(s){extra})")


def compliance_to_dict(
    violations: list[Violation], compliant: bool, not_applicable: list[NotApplicable] | None = None,
) -> dict:
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])
    return {
        "compliant": compliant,
        "violations": [
            {
                "severity": v.rule.severity, "rule_id": v.rule.id, "device": v.device, "detail": v.detail,
                "category": v.rule.category, "references": v.rule.references,
            }
            for v in violations
        ],
        "not_applicable": [
            {
                "rule_id": n.rule.id, "device": n.device, "reason": n.reason,
                "category": n.rule.category, "references": n.rule.references,
            }
            for n in (not_applicable or [])
        ],
    }


def write_compliance_json(
    violations: list[Violation], compliant: bool, path: str,
    not_applicable: list[NotApplicable] | None = None,
) -> None:
    Path(path).write_text(
        json.dumps(compliance_to_dict(violations, compliant, not_applicable), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def render_compliance_html(
    violations: list[Violation], compliant: bool, rules_path: str,
    not_applicable: list[NotApplicable] | None = None,
) -> str:
    """Rend le rapport HTML de conformité, autonome (aucune ressource externe)."""
    template = _ENV.get_template("compliance.html.j2")
    violations = _masked_violations(violations)
    not_applicable = _masked_not_applicable(not_applicable or [])
    counts = {sev: sum(1 for v in violations if v.rule.severity == sev) for sev in _COMPLIANCE_ORDER}
    devices = sorted({v.device for v in violations} | {n.device for n in not_applicable})
    # Regroupement par catégorie (Phase A, C14) : None -> "(sans catégorie)" pour les règles
    # antérieures à la Phase A, qui n'ont jamais ce champ.
    categories = sorted({v.rule.category or "(sans catégorie)" for v in violations})
    return template.render(
        compliant=compliant,
        violations=sorted(violations, key=lambda v: -_COMPLIANCE_ORDER[v.rule.severity]),
        not_applicable=sorted(not_applicable, key=lambda n: (n.device, n.rule.id)),
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
) -> None:
    Path(path).write_text(
        render_compliance_html(violations, compliant, rules_path, not_applicable), encoding="utf-8",
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
