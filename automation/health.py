#!/usr/bin/env python3
"""Vérifie l'état du routage : voisins OSPF en Full et sessions BGP établies, comparés à l'inventaire.

  python health.py        -> tableau de synthèse, code retour 0 si tout est conforme
"""
import argparse

from labtools import Router, load_inventory, run_parallel


def check(r):
    """Collecte l'état OSPF/BGP via les sorties JSON de FRR et le compare aux valeurs attendues."""
    problems = []
    with Router(r) as rt:
        nbrs = rt.vtysh_json("show ip ospf neighbor").get("neighbors", {})
        full = [rid for rid, lst in nbrs.items()
                if any((n.get("nbrState") or n.get("state", "")).startswith("Full") for n in lst)]
        if len(full) < r.get("ospf_neighbors", 0):
            problems.append(f"OSPF {len(full)}/{r['ospf_neighbors']} voisins Full")

        bgp_view = []
        expected = r.get("bgp_peers") or {}
        if expected:
            peers = rt.vtysh_json("show bgp ipv4 unicast summary").get("peers", {})
            for ip, min_pfx in expected.items():
                p = peers.get(ip, {})
                state, pfx = p.get("state", "absent"), p.get("pfxRcd", 0)
                bgp_view.append(f"{ip} {state} ({pfx} pfx)")
                if state != "Established":
                    problems.append(f"BGP {ip} {state}")
                elif pfx < min_pfx:
                    problems.append(f"BGP {ip} {pfx}/{min_pfx} préfixes reçus")
    return {"ospf": f"{len(full)}/{r.get('ospf_neighbors', 0)}", "bgp": ", ".join(bgp_view) or "-",
            "problems": problems}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-r", "--routers", nargs="+", help="routeurs ciblés (défaut : tous)")
    args = p.parse_args()

    results = run_parallel(check, load_inventory(args.routers))
    print(f"{'Routeur':<8} {'OSPF Full':<10} {'BGP':<40} Verdict")
    bad = 0
    for name, (ok, res) in results.items():
        if not ok:
            bad += 1
            print(f"{name:<8} {'?':<10} {'?':<40} INJOIGNABLE : {res}")
            continue
        verdict = "OK" if not res["problems"] else "KO : " + " ; ".join(res["problems"])
        bad += bool(res["problems"])
        print(f"{name:<8} {res['ospf']:<10} {res['bgp']:<40} {verdict}")
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
