#!/usr/bin/env python3
"""Vérifie l'état du routage : voisins OSPF en Full et sessions BGP établies, comparés à l'inventaire.

Double pile (phase B) : `ospf6_neighbors` (voisins OSPFv3 en Full) et `bgp6_peers` (voisin BGP IPv6 -> nombre
minimal de préfixes reçus) sont facultatifs dans l'inventaire ; absents, la vérification IPv6 est ignorée.

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

        ospf6 = "-"
        if "ospf6_neighbors" in r:
            nbrs6 = rt.vtysh_json("show ipv6 ospf6 neighbor").get("neighbors", [])
            full6 = [n for n in nbrs6 if str(n.get("state", "")).startswith("Full")]
            ospf6 = f"{len(full6)}/{r['ospf6_neighbors']}"
            if len(full6) < r["ospf6_neighbors"]:
                problems.append(f"OSPFv3 {len(full6)}/{r['ospf6_neighbors']} voisins Full")

        bgp_view = []
        for family, key in (("ipv4", "bgp_peers"), ("ipv6", "bgp6_peers")):
            expected = r.get(key) or {}
            if not expected:
                continue
            peers = rt.vtysh_json(f"show bgp {family} unicast summary").get("peers", {})
            for ip, min_pfx in expected.items():
                p = peers.get(str(ip), {})
                state, pfx = p.get("state", "absent"), p.get("pfxRcd", 0)
                bgp_view.append(f"{ip} {state} ({pfx} pfx)")
                if state != "Established":
                    problems.append(f"BGP {ip} {state}")
                elif pfx < min_pfx:
                    problems.append(f"BGP {ip} {pfx}/{min_pfx} préfixes reçus")
    return {"ospf": f"{len(full)}/{r.get('ospf_neighbors', 0)}", "ospf6": ospf6,
            "bgp": ", ".join(bgp_view) or "-", "problems": problems}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-r", "--routers", nargs="+", help="routeurs ciblés (défaut : tous)")
    args = p.parse_args()

    results = run_parallel(check, load_inventory(args.routers))
    print(f"{'Routeur':<8} {'OSPF Full':<10} {'OSPFv3':<8} {'BGP':<62} Verdict")
    bad = 0
    for name, (ok, res) in results.items():
        if not ok:
            bad += 1
            print(f"{name:<8} {'?':<10} {'?':<8} {'?':<62} INJOIGNABLE : {res}")
            continue
        verdict = "OK" if not res["problems"] else "KO : " + " ; ".join(res["problems"])
        bad += bool(res["problems"])
        print(f"{name:<8} {res['ospf']:<10} {res['ospf6']:<8} {res['bgp']:<62} {verdict}")
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
