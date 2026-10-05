#!/usr/bin/env python3
"""Opérations d'administration SUR NOTRE NetBox de lab, pour les scénarios (jamais utilisées par netcheck).

    netbox_admin.py add-device    --site lab-frr --name r9 --ip 172.20.20.11 [--driver frr] [--vrf lab-dup]
    netbox_admin.py remove-device --site lab-frr --name r9 [--vrf lab-dup]
    netbox_admin.py devices       --site lab-frr          (noms triés, séparés par des espaces)
    netbox_admin.py new-ro-token  --out FICHIER           (un jeton lecture seule SUPPLÉMENTAIRE,
      fichier 0600)
    netbox_admin.py revoke-ro-token --file FICHIER        (révoque CE jeton ; les autres ne bougent pas)

`add-device --vrf` pose l'IP dans une VRF : NetBox refuse deux fois la même adresse hors VRF, et un
équipement « de NetBox seulement » doit pouvoir pointer vers un routeur réel du lab pour que `guard` le
collecte."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import load_lab
import nblab
import pynetbox


def _api(admin: nblab.Admin):
    nb = pynetbox.api(admin.base, token=admin.token)
    nb.http_session = admin.session
    return nb


def add_device(admin, site, name, ip, driver, vrf) -> None:
    nb = _api(admin)
    ids = load_lab.ensure_reference_objects(nb)
    _, device_type, platform, interface_name = load_lab.DRIVERS[driver]
    device = nb.dcim.devices.get(name=name, site_id=ids["site"][site])
    if device is not None:
        nblab.fail(f"{name} existe déjà dans {site}")
    device = nb.dcim.devices.create(
        name=name,
        role=ids["role"],
        device_type=ids["device_type"][device_type],
        site=ids["site"][site],
        platform=ids["platform"][platform],
        status="active",
        tags=[ids["tag"]],
    )
    interface = nb.dcim.interfaces.create(device=device.id, name=interface_name, type="virtual")
    fields = {
        "address": f"{ip}/24",
        "status": "active",
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface.id,
    }
    if vrf:
        fields["vrf"] = load_lab.get_or_create(nb.ipam.vrfs, {"name": vrf})[0].id
    address = nb.ipam.ip_addresses.create(**fields)
    device.primary_ip4 = address.id
    device.save()
    print(f"équipement {name} ajouté dans {site} (NetBox seulement)")


def remove_device(admin, site, name, vrf) -> None:
    nb = _api(admin)
    site_obj = nb.dcim.sites.get(slug=site)
    device = nb.dcim.devices.get(name=name, site_id=site_obj.id) if site_obj else None
    if device is None:
        nblab.fail(f"{name} introuvable dans {site}")
    addresses = list(nb.ipam.ip_addresses.filter(device_id=device.id))
    device.delete()
    for address in addresses:  # NetBox supprime déjà l'adresse de l'interface avec l'équipement (mesuré)
        if nb.ipam.ip_addresses.get(address.id) is not None:
            address.delete()
    if vrf:
        found = nb.ipam.vrfs.get(name=vrf)
        if found is not None and not list(nb.ipam.ip_addresses.filter(vrf_id=found.id)):
            found.delete()
    print(f"équipement {name} supprimé de {site}")


def list_devices(admin, site) -> None:
    nb = _api(admin)
    print(" ".join(sorted(d.name for d in nb.dcim.devices.filter(site=site))))


def _ro_user_id(admin) -> int:
    users = admin.json("/api/users/users/", params={"username": nblab.RO_USER})["results"]
    if not users:
        nblab.fail(f"le compte {nblab.RO_USER} n'existe pas : lancez load_lab.py")
    return users[0]["id"]


def new_ro_token(admin, out) -> None:
    reply = admin.call(
        "POST",
        "/api/users/tokens/",
        json={
            "user": _ro_user_id(admin),
            "write_enabled": False,
            "description": "netcheck, lecture seule (preuve de révocation)",
        },
    )
    if reply.status_code not in (200, 201):
        nblab.fail(f"création du jeton refusée (HTTP {reply.status_code})")
    nblab.write_token_file(out, nblab.bearer_from(reply.json()))
    print(f"jeton lecture seule supplémentaire écrit : {out}")


def revoke_ro_token(admin, token_file) -> None:
    token = Path(token_file).read_text(encoding="utf-8").strip()
    key = token.removeprefix("nbt_").split(".", 1)[0]
    tokens = admin.json("/api/users/tokens/", params={"user_id": _ro_user_id(admin), "limit": 1000})[
        "results"
    ]
    target = [t for t in tokens if t.get("key") == key]
    if len(target) != 1:
        nblab.fail("le jeton à révoquer n'a pas été retrouvé (ou n'est pas unique)")
    answer = admin.call("DELETE", f"/api/users/tokens/{target[0]['id']}/")
    if answer.status_code not in (200, 204):
        nblab.fail(f"révocation refusée (HTTP {answer.status_code})")
    print("jeton révoqué")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument("--netbox", default=nblab.DEFAULT_URL)
    parser.add_argument("--env-file", default=str(nblab.DEFAULT_ENV_FILE))
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add-device", allow_abbrev=False)
    add.add_argument("--site", required=True, choices=sorted(nblab.LAB_SITES.values()))
    add.add_argument("--name", required=True)
    add.add_argument("--ip", required=True)
    add.add_argument("--driver", default="frr", choices=sorted(load_lab.DRIVERS))
    add.add_argument("--vrf")
    remove = sub.add_parser("remove-device", allow_abbrev=False)
    remove.add_argument("--site", required=True, choices=sorted(nblab.LAB_SITES.values()))
    remove.add_argument("--name", required=True)
    remove.add_argument("--vrf")
    listing = sub.add_parser("devices", allow_abbrev=False)
    listing.add_argument("--site", required=True, choices=sorted(nblab.LAB_SITES.values()))
    new = sub.add_parser("new-ro-token", allow_abbrev=False)
    new.add_argument("--out", required=True)
    revoke = sub.add_parser("revoke-ro-token", allow_abbrev=False)
    revoke.add_argument("--file", required=True)
    args = parser.parse_args(argv)
    with nblab.Admin(args.netbox, args.env_file) as admin:
        if args.command == "add-device":
            add_device(admin, args.site, args.name, args.ip, args.driver, args.vrf)
        elif args.command == "remove-device":
            remove_device(admin, args.site, args.name, args.vrf)
        elif args.command == "devices":
            list_devices(admin, args.site)
        elif args.command == "new-ro-token":
            new_ro_token(admin, args.out)
        else:
            revoke_ro_token(admin, args.file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
