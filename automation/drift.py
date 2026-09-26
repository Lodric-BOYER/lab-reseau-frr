#!/usr/bin/env python3
"""Détecte les dérives de configuration : running-config actuelle vs référence (baseline/).

  python drift.py                     -> diff dans le terminal
  python drift.py --report rapport.md -> rapport Markdown en plus
Code retour : 0 = conforme, 1 = dérive détectée, 2 = erreur (routeur injoignable, baseline absente)
"""
import argparse
import difflib
import sys
from datetime import datetime

from labtools import BASE, Router, clean_config, load_inventory, run_parallel

COLORS = {"+": "\033[32m", "-": "\033[31m", "@": "\033[36m"}


def fetch(r):
    with Router(r) as rt:
        return rt.running_config()


def colorize(line):
    if not sys.stdout.isatty():
        return line
    c = COLORS.get(line[:1])
    return f"{c}{line}\033[0m" if c and not line.startswith(("+++", "---")) else line


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-r", "--routers", nargs="+", help="routeurs ciblés (défaut : tous)")
    p.add_argument("--report", help="écrire un rapport Markdown dans ce fichier")
    args = p.parse_args()

    baseline_dir = BASE / "baseline"
    if not baseline_dir.is_dir():
        raise SystemExit("Pas de baseline : lance d'abord  python backup.py --baseline")

    routers = load_inventory(args.routers)
    results = run_parallel(fetch, routers)

    # Comparaison ligne à ligne sur les configs nettoyées ; '-' = attendu, '+' = trouvé en production
    status, diffs = {}, {}
    for name, (ok, data) in results.items():
        ref = baseline_dir / f"{name}.conf"
        if not ok:
            status[name] = f"ERREUR ({data})"
            continue
        if not ref.exists():
            status[name] = "ERREUR (pas de baseline pour ce routeur)"
            continue
        diff = list(difflib.unified_diff(
            clean_config(ref.read_text(encoding="utf-8")), clean_config(data),
            fromfile=f"baseline/{name}.conf", tofile=f"{name} (running)", lineterm="", n=2,
        ))
        status[name] = "DÉRIVE" if diff else "CONFORME"
        if diff:
            diffs[name] = diff

    for name, st in status.items():
        print(f"{name:<6} {st}")
    for name, diff in diffs.items():
        print(f"\n=== {name} ===")
        print("\n".join(colorize(l) for l in diff))

    # Rapport Markdown : pratique à joindre à un ticket ou à committer
    if args.report:
        md = [f"# Rapport de dérive – {datetime.now():%Y-%m-%d %H:%M}", "", "| Routeur | Statut |", "|---|---|"]
        md += [f"| {n} | {s} |" for n, s in status.items()]
        for name, diff in diffs.items():
            md += ["", f"## {name}", "```diff", *diff, "```"]
        (BASE / args.report).write_text("\n".join(md) + "\n", encoding="utf-8")
        print(f"\nRapport écrit : {args.report}")

    errors = any(s.startswith("ERREUR") for s in status.values())
    raise SystemExit(2 if errors else 1 if diffs else 0)


if __name__ == "__main__":
    main()
