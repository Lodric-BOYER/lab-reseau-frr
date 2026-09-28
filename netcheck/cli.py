"""Interface en ligne de commande : `python -m netcheck <sous-commande> ...`.

Phase 4 : `snapshot`, `list`, `diff` et `check` sont actives. `guard` arrive en phase 5.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from netcheck import collector, compliance, diff, inventory, report, snapshot
from netcheck.drivers.frr import FrrDriver

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules" / "default.yml"


def cmd_snapshot(args: argparse.Namespace) -> int:
    inv = inventory.load(args.devices)
    driver = FrrDriver()
    results = collector.collect_all(inv.routers, driver)

    try:
        out_dir = snapshot.save(args.name, results, force=args.force)
    except FileExistsError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    print(f"Snapshot '{args.name}' écrit dans {out_dir.relative_to(inventory.REPO_ROOT)}")
    failed = 0
    for name, (ok, value) in sorted(results.items()):
        if ok:
            print(f"  {name:<8} OK")
        else:
            failed += 1
            print(f"  {name:<8} INJOIGNABLE : {value}")
    return 1 if failed else 0


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        before = snapshot.load(args.before)
        after = snapshot.load(args.after)
    except FileNotFoundError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    inv = inventory.load()
    findings = diff.compare(before, after, management_interfaces=set(inv.management_interfaces))
    verdict_label, code = diff.verdict(findings)

    report.print_terminal(findings, verdict_label)
    if args.json:
        report.write_json(findings, verdict_label, args.json)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_html(findings, verdict_label, args.before, args.after, args.html)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_check(args: argparse.Namespace) -> int:
    rules_path = Path(args.rules) if args.rules else DEFAULT_RULES_PATH
    try:
        rules = compliance.load_rules(rules_path)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    inv = inventory.load()
    if args.snapshot:
        try:
            devices = snapshot.load(args.snapshot)
        except FileNotFoundError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
    else:
        results = collector.collect_all(inv.routers, FrrDriver())
        devices = {}
        for name, (ok, value) in results.items():
            if ok:
                devices[name] = value
            else:
                print(f"  {name:<8} INJOIGNABLE : {value}", file=sys.stderr)

    violations = compliance.evaluate(rules, devices, management_interfaces=set(inv.management_interfaces))
    compliant, code = compliance.verdict(violations)

    report.print_compliance_terminal(violations, compliant)
    if args.json:
        report.write_compliance_json(violations, compliant, args.json)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_compliance_html(violations, compliant, rules_path, args.html)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_list(_args: argparse.Namespace) -> int:
    snaps = snapshot.list_snapshots()
    if not snaps:
        print("Aucun snapshot.")
        return 0
    print(f"{'Nom':<20} {'Horodatage':<22} Équipements")
    for meta in snaps:
        print(f"{meta['name']:<20} {meta['timestamp']:<22} {len(meta['devices'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m netcheck", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    p_snap = sub.add_parser("snapshot", help="capture l'état de tous les équipements (ou -d)")
    p_snap.add_argument("name", help="nom du snapshot (dossier snapshots/<name>/)")
    p_snap.add_argument("-d", "--devices", nargs="+", help="équipements ciblés (défaut : tous)")
    p_snap.add_argument("--force", action="store_true", help="écraser un snapshot existant")
    p_snap.set_defaults(func=cmd_snapshot)

    p_list = sub.add_parser("list", help="liste les snapshots existants")
    p_list.set_defaults(func=cmd_list)

    p_diff = sub.add_parser("diff", help="compare deux snapshots")
    p_diff.add_argument("before", help="nom du snapshot avant")
    p_diff.add_argument("after", help="nom du snapshot après")
    p_diff.add_argument("--json", help="écrire les constats au format JSON dans ce fichier")
    p_diff.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    p_diff.set_defaults(func=cmd_diff)

    p_check = sub.add_parser("check", help="audite la conformité des configurations")
    p_check.add_argument("--snapshot", help="auditer un snapshot existant (hors ligne, sans connexion)")
    p_check.add_argument("--rules", help=f"fichier de règles YAML (défaut : {DEFAULT_RULES_PATH.name})")
    p_check.add_argument("--json", help="écrire les non-conformités au format JSON dans ce fichier")
    p_check.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    p_check.set_defaults(func=cmd_check)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
