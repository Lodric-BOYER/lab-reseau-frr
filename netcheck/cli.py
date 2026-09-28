"""Interface en ligne de commande : `python -m netcheck <sous-commande> ...`.

Phase 2 : `snapshot`, `list` et `diff` sont actives. `check` et `guard` seront ajoutées aux
phases suivantes.
"""
from __future__ import annotations

import argparse
import sys

from netcheck import collector, diff, inventory, report, snapshot
from netcheck.drivers.frr import FrrDriver


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
    p_diff.set_defaults(func=cmd_diff)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
