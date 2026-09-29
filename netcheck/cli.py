"""Interface en ligne de commande : `python -m netcheck <sous-commande> ...`.

Six sous-commandes : snapshot, list, diff, check, guard, assert.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from netcheck import assertions, collector, compliance, diff, inventory, report, snapshot

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules" / "default.yml"


def cmd_snapshot(args: argparse.Namespace) -> int:
    inv = inventory.load(args.devices, path=args.inventory)
    results = collector.collect_all(inv.routers)

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

    inv = inventory.load(path=args.inventory)
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

    inv = inventory.load(path=args.inventory)
    if args.snapshot:
        try:
            devices = snapshot.load(args.snapshot)
        except FileNotFoundError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
    else:
        results = collector.collect_all(inv.routers)
        devices = {}
        for name, (ok, value) in results.items():
            if ok:
                devices[name] = value
            else:
                print(f"  {name:<8} INJOIGNABLE : {value}", file=sys.stderr)

    violations, not_applicable = compliance.evaluate(
        rules, devices, management_interfaces=set(inv.management_interfaces))
    compliant, code = compliance.verdict(violations)

    report.print_compliance_terminal(violations, compliant, not_applicable)
    if args.json:
        report.write_compliance_json(violations, compliant, args.json, not_applicable)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_compliance_html(violations, compliant, rules_path, args.html, not_applicable)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_guard(args: argparse.Namespace) -> int:
    """Encadre une intervention : c'est le script --change qui modifie, jamais netcheck (§5.5)."""
    change_script = Path(args.change)
    if not change_script.is_file():
        print(f"Erreur : script introuvable : {change_script}", file=sys.stderr)
        return 3

    print(f"Ce script va être exécuté : {change_script}")
    print("--- contenu ---")
    print(change_script.read_text(encoding="utf-8").rstrip())
    print("---------------")
    if not args.yes:
        reply = input("Confirmer l'exécution ? [o/N] ").strip().lower()
        if reply not in ("o", "oui", "y", "yes"):
            print("Annulé.")
            return 3

    inv = inventory.load(path=args.inventory)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    name_before, name_after = f"guard_{stamp}_avant", f"guard_{stamp}_apres"

    print(f"\nSnapshot avant : {name_before}")
    snapshot.save(name_before, collector.collect_all(inv.routers))

    print(f"Exécution de {change_script}...")
    result = subprocess.run(["bash", str(change_script)])
    if result.returncode != 0:
        print(f"Attention : le script de changement a rendu le code {result.returncode}", file=sys.stderr)

    print(f"Attente de convergence (max {args.wait}s)...")
    if not collector.wait_for_convergence(inv.routers, timeout=args.wait):
        print("Attention : convergence non confirmée dans le délai imparti", file=sys.stderr)

    print(f"Snapshot après : {name_after}")
    snapshot.save(name_after, collector.collect_all(inv.routers))

    before, after = snapshot.load(name_before), snapshot.load(name_after)
    findings = diff.compare(before, after, management_interfaces=set(inv.management_interfaces))
    verdict_label, code = diff.verdict(findings)

    report.print_terminal(findings, verdict_label)
    if args.json:
        report.write_json(findings, verdict_label, args.json)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_html(findings, verdict_label, name_before, name_after, args.html)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_assert(args: argparse.Namespace) -> int:
    """Vérifie l'état attendu (Phase C, SPEC_v3 §6, O2) : en direct ou hors ligne (--snapshot),
    identique aux autres sous-commandes de collecte/lecture."""
    try:
        intent = assertions.load_intent(args.intent)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    inv = inventory.load(path=args.inventory)
    if args.snapshot:
        try:
            devices = snapshot.load(args.snapshot)
        except FileNotFoundError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
    else:
        results = collector.collect_all(inv.routers)
        devices = {}
        for name, (ok, value) in results.items():
            if ok:
                devices[name] = value
            else:
                print(f"  {name:<8} INJOIGNABLE : {value}", file=sys.stderr)

    try:
        results = assertions.evaluate(intent, devices, management_interfaces=set(inv.management_interfaces))
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3
    verdict_label, code = assertions.verdict(results)

    report.print_assert_terminal(results, verdict_label)
    if args.json:
        report.write_assert_json(results, verdict_label, args.json)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_assert_html(results, verdict_label, args.intent, args.html)
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


def _add_inventory_arg(sub_parser: argparse.ArgumentParser) -> None:
    """-i/--inventory : fichier d'inventaire (défaut : automation/inventory.yml). Ajouté à
    toute sous-commande qui contacte les équipements ou lit management_interfaces (Phase D1,
    nécessaire pour cibler automation/inventory-multivendor.yml sur le lab mixte)."""
    sub_parser.add_argument(
        "-i", "--inventory",
        help="fichier d'inventaire YAML (défaut : automation/inventory.yml)",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m netcheck", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    p_snap = sub.add_parser("snapshot", help="capture l'état de tous les équipements (ou -d)")
    p_snap.add_argument("name", help="nom du snapshot (dossier snapshots/<name>/)")
    p_snap.add_argument("-d", "--devices", nargs="+", help="équipements ciblés (défaut : tous)")
    p_snap.add_argument("--force", action="store_true", help="écraser un snapshot existant")
    _add_inventory_arg(p_snap)
    p_snap.set_defaults(func=cmd_snapshot)

    p_list = sub.add_parser("list", help="liste les snapshots existants")
    p_list.set_defaults(func=cmd_list)

    p_diff = sub.add_parser("diff", help="compare deux snapshots")
    p_diff.add_argument("before", help="nom du snapshot avant")
    p_diff.add_argument("after", help="nom du snapshot après")
    p_diff.add_argument("--json", help="écrire les constats au format JSON dans ce fichier")
    p_diff.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_diff)
    p_diff.set_defaults(func=cmd_diff)

    p_check = sub.add_parser("check", help="audite la conformité des configurations")
    p_check.add_argument("--snapshot", help="auditer un snapshot existant (hors ligne, sans connexion)")
    p_check.add_argument("--rules", help=f"fichier de règles YAML (défaut : {DEFAULT_RULES_PATH.name})")
    p_check.add_argument("--json", help="écrire les non-conformités au format JSON dans ce fichier")
    p_check.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_check)
    p_check.set_defaults(func=cmd_check)

    p_guard = sub.add_parser("guard", help="encadre une intervention (snapshot avant/après + diff)")
    p_guard.add_argument(
        "--change", required=True,
        help="script exécuté par guard (lui seul modifie, pas netcheck)",
    )
    p_guard.add_argument(
        "--wait", type=int, default=30,
        help="délai maximum de convergence, en secondes (défaut : 30)",
    )
    p_guard.add_argument(
        "--yes", action="store_true",
        help="ne pas demander de confirmation avant d'exécuter le script",
    )
    p_guard.add_argument("--json", help="écrire les constats au format JSON dans ce fichier")
    p_guard.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_guard)
    p_guard.set_defaults(func=cmd_guard)

    p_assert = sub.add_parser("assert", help="vérifie l'état attendu (Phase C, --intent)")
    p_assert.add_argument("--intent", required=True, help="fichier d'intent YAML (intents/*.yml)")
    p_assert.add_argument("--snapshot", help="vérifier un snapshot existant (hors ligne, sans connexion)")
    p_assert.add_argument("--json", help="écrire les résultats au format JSON dans ce fichier")
    p_assert.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_assert)
    p_assert.set_defaults(func=cmd_assert)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
