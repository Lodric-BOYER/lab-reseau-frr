"""Interface en ligne de commande : `python -m netcheck <sous-commande> ...`.

Phase 1 : seules `snapshot` et `list` sont actives. `diff`, `check` et `guard` seront ajoutées
aux phases suivantes.
"""
from __future__ import annotations

import argparse
import sys

from netcheck import collector, inventory, snapshot
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

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
