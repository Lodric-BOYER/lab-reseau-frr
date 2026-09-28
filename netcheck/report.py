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
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table

from netcheck import __version__
from netcheck.compliance import Violation
from netcheck.diff import Finding, Severity

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,  # explicite : ne dépend pas de l'extension du fichier gabarit
)

_STYLE = {Severity.CRITIQUE: "bold red", Severity.ATTENTION: "yellow", Severity.INFO: "cyan"}
_COMPLIANCE_STYLE = {"critique": "bold red", "haute": "red", "moyenne": "yellow", "basse": "cyan"}
_COMPLIANCE_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "basse": 1}


def print_terminal(findings: list[Finding], verdict_label: str, console: Console | None = None) -> None:
    console = console or Console()

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


def write_html(findings: list[Finding], verdict_label: str, before_name: str, after_name: str, path: str) -> None:
    Path(path).write_text(render_html(findings, verdict_label, before_name, after_name), encoding="utf-8")


# ------------------------------------------------------------------------------------------
# Conformité (netcheck check) : mêmes principes, vocabulaire de gravité différent (§5.4)
# ------------------------------------------------------------------------------------------

def print_compliance_terminal(violations: list[Violation], compliant: bool, console: Console | None = None) -> None:
    console = console or Console()

    if violations:
        table = Table(show_lines=False)
        table.add_column("Gravité")
        table.add_column("Équipement")
        table.add_column("Règle")
        table.add_column("Détail", overflow="fold")
        for v in sorted(violations, key=lambda v: -_COMPLIANCE_ORDER[v.rule.severity]):
            style = _COMPLIANCE_STYLE[v.rule.severity]
            table.add_row(f"[{style}]{v.rule.severity.upper()}[/]", v.device, v.rule.id, v.detail)
        console.print(table)
    else:
        console.print("Aucune non-conformité.")

    label = "CONFORME" if compliant else "NON CONFORME"
    console.print(f"Conformité : [bold]{label}[/bold]  ({len(violations)} non-conformité(s))")


def compliance_to_dict(violations: list[Violation], compliant: bool) -> dict:
    return {
        "compliant": compliant,
        "violations": [
            {"severity": v.rule.severity, "rule_id": v.rule.id, "device": v.device, "detail": v.detail}
            for v in violations
        ],
    }


def write_compliance_json(violations: list[Violation], compliant: bool, path: str) -> None:
    Path(path).write_text(
        json.dumps(compliance_to_dict(violations, compliant), indent=2, ensure_ascii=False), encoding="utf-8",
    )


def render_compliance_html(violations: list[Violation], compliant: bool, rules_path: str) -> str:
    """Rend le rapport HTML de conformité, autonome (aucune ressource externe)."""
    template = _ENV.get_template("compliance.html.j2")
    counts = {sev: sum(1 for v in violations if v.rule.severity == sev) for sev in _COMPLIANCE_ORDER}
    devices = sorted({v.device for v in violations})
    return template.render(
        compliant=compliant,
        violations=sorted(violations, key=lambda v: -_COMPLIANCE_ORDER[v.rule.severity]),
        counts=counts,
        devices=devices,
        rules_path=str(rules_path),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        netcheck_version=__version__,
    )


def write_compliance_html(violations: list[Violation], compliant: bool, rules_path: str, path: str) -> None:
    Path(path).write_text(render_compliance_html(violations, compliant, rules_path), encoding="utf-8")
