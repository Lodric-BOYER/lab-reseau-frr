#!/usr/bin/env python3
"""Sauvegarde la running-config de chaque routeur.

  python backup.py                 -> backups/AAAA-MM-JJ_HHMMSS/<routeur>.conf
  python backup.py --baseline      -> fige aussi la config de référence dans baseline/
  python backup.py -r r1 r3        -> seulement certains routeurs
"""
import argparse
import hashlib
from datetime import datetime

from labtools import BASE, Router, load_inventory, run_parallel


def fetch(r):
    with Router(r) as rt:
        return rt.running_config()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-r", "--routers", nargs="+", help="routeurs ciblés (défaut : tous)")
    p.add_argument("--baseline", action="store_true", help="enregistrer aussi comme référence (golden config)")
    args = p.parse_args()

    routers = load_inventory(args.routers)
    results = run_parallel(fetch, routers)

    # Un dossier horodaté par exécution : historique lisible et versionnable avec git
    out_dir = BASE / "backups" / datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.baseline:
        (BASE / "baseline").mkdir(exist_ok=True)

    print(f"{'Routeur':<8} {'Statut':<7} {'Lignes':>6}  SHA-256")
    failures = 0
    for name, (ok, data) in results.items():
        if not ok:
            failures += 1
            print(f"{name:<8} {'ÉCHEC':<7} {'-':>6}  {data}")
            continue
        text = data.strip() + "\n"
        (out_dir / f"{name}.conf").write_text(text, encoding="utf-8")
        if args.baseline:
            (BASE / "baseline" / f"{name}.conf").write_text(text, encoding="utf-8")
        digest = hashlib.sha256(text.encode()).hexdigest()[:12]
        print(f"{name:<8} {'OK':<7} {len(text.splitlines()):>6}  {digest}")

    print(f"\nSauvegardes : {out_dir.relative_to(BASE)}" + ("  (+ baseline/ mise à jour)" if args.baseline else ""))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
