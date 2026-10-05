#!/usr/bin/env python3
"""Produit l'inventaire « alimenté par NetBox » d'un lab à partir de son inventaire YAML d'origine.

    make_inventory.py LAB [--url URL] [--page-size N] [--local-only NOM,...] [--out FICHIER]

LAB : frr, multivendor ou ceos. Le fichier produit garde ce que NetBox ne fournit JAMAIS (`lab`,
`defaults`, interfaces de management, attendus de convergence, identifiants propres à un routeur) et
remplace `host`, `driver` et `device_type` par un bloc `netbox:` (site du lab, rôle `router`, étiquette
`netcheck`, table des plateformes). `--local-only r8` ajoute un routeur qui n'est PAS dans NetBox
(scénario d'erreur). Bibliothèque standard + PyYAML : aucun accès à NetBox ici."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LABS = {
    "frr": ("automation/inventory.yml", "lab-frr"),
    "multivendor": ("automation/inventory-multivendor.yml", "lab-multivendor"),
    "ceos": ("automation/inventory-ceos.yml", "lab-ceos"),
}
PLATFORMS = {"frr": "frr", "srlinux": "srlinux", "eos": "eos"}
NETBOX_FACTS = ("host", "driver", "device_type")  # ce que NetBox fournit : retiré du fichier local


def build_inventory(
    lab: str,
    url: str = "http://127.0.0.1:8000",
    page_size: int | None = None,
    local_only: tuple[str, ...] = (),
    repo: Path = ROOT,
) -> dict:
    relative, site = LABS[lab]
    original = yaml.safe_load((repo / relative).read_text(encoding="utf-8"))
    routers = {
        name: {k: v for k, v in (attrs or {}).items() if k not in NETBOX_FACTS}
        for name, attrs in original["routers"].items()
    }
    for name in local_only:
        routers[name] = {"ospf_neighbors": 1}
    block = {"url": url, "site": site, "role": "router", "tag": "netcheck", "platforms": dict(PLATFORMS)}
    if page_size is not None:
        block["page_size"] = page_size
    inventory = {key: value for key, value in original.items() if key not in ("routers", "netbox")}
    inventory["netbox"] = block
    inventory["routers"] = routers
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument("lab", choices=sorted(LABS))
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--page-size", type=int)
    parser.add_argument("--local-only", default="")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    names = tuple(n for n in args.local_only.split(",") if n)
    text = yaml.safe_dump(
        build_inventory(args.lab, args.url, args.page_size, names), sort_keys=False, allow_unicode=True
    )
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
