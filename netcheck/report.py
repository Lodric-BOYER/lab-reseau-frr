"""Sorties de netcheck : terminal (rich), JSON. Le rapport HTML autonome arrive en phase 3."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from netcheck.diff import Finding, Severity

_STYLE = {Severity.CRITIQUE: "bold red", Severity.ATTENTION: "yellow", Severity.INFO: "cyan"}


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
