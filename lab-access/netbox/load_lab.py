#!/usr/bin/env python3
"""Charge NOTRE NetBox de lab avec les équipements des trois labs, et crée le jeton en lecture seule de
netcheck.

    PYTHONPATH=lab-access/netbox/.pylib netcheck/.venv/bin/python lab-access/netbox/load_lab.py
    [--labs frr,ceos]
                                                                  [--rotate-token] [--token-file FICHIER]

ÉCRITURE : uniquement sur l'instance de lab (127.0.0.1:8000 par défaut), avec un jeton d'administration
éphémère (une heure, supprimé à la fin). pynetbox ne vit QUE dans ce dossier ; il n'est jamais importé
par netcheck/. Idempotent : on peut le rejouer ; il ne crée que ce qui manque.

Ce que le lab contient ensuite : trois sites (lab-frr, lab-multivendor, lab-ceos), un rôle `router`, une
étiquette `netcheck`, trois plateformes dont les `slug` (frr, srlinux, eos) sont ceux de la table
`platforms:` des inventaires, et les routeurs de chaque inventaire avec une interface de management
portant l'IP primaire.

Le compte `netcheck-ro` n'a AUCUN droit d'administration ni de connexion utile (mot de passe aléatoire
jeté) : une seule permission, `view` sur `dcim.device`. Son jeton v2 est en lecture seule
(`write_enabled` faux) et va dans un fichier 0600 hors dépôt (~/.config/netcheck/netbox-ro.token).
`allowed_ips` n'est pas posé : derrière le proxy de Docker, NetBox voit l'adresse de la passerelle du
pont, pas 127.0.0.1."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

import nblab
import pynetbox
import yaml

ROOT = Path(__file__).resolve().parents[2]
INVENTORIES = {
    "frr": ROOT / "automation" / "inventory.yml",
    "multivendor": ROOT / "automation" / "inventory-multivendor.yml",
    "ceos": ROOT / "automation" / "inventory-ceos.yml",
}
# driver netcheck -> (fabricant, type d'équipement, plateforme, interface de management)
DRIVERS = {
    "frr": ("frrouting", "frr-container", "frr", "eth0"),
    "srlinux": ("nokia", "srlinux-ixr-d2l", "srlinux", "mgmt0"),
    "eos": ("arista", "ceos", "eos", "Management0"),
}
MANUFACTURERS = {"frrouting": "FRRouting", "nokia": "Nokia", "arista": "Arista"}
DEVICE_TYPES = {
    "frr-container": ("frrouting", "FRR (conteneur)"),
    "srlinux-ixr-d2l": ("nokia", "SR Linux IXR-D2L (simulé)"),
    "ceos": ("arista", "cEOS"),
}
PLATFORMS = {"frr": ("FRR", "frrouting"), "srlinux": ("SR Linux", "nokia"), "eos": ("EOS", "arista")}
PERMISSION = "netcheck-ro-view-devices"


def get_or_create(endpoint, lookup: dict, extra: dict | None = None):
    found = endpoint.get(**lookup)
    if found is not None:
        return found, False
    return endpoint.create({**lookup, **(extra or {})}), True


def ensure_reference_objects(nb) -> dict:
    ids: dict = {"manufacturer": {}, "device_type": {}, "platform": {}}
    for slug, name in MANUFACTURERS.items():
        ids["manufacturer"][slug] = get_or_create(nb.dcim.manufacturers, {"slug": slug}, {"name":
        name})[0].id
    for slug, (manufacturer, model) in DEVICE_TYPES.items():
        ids["device_type"][slug] = get_or_create(
            nb.dcim.device_types,
            {"slug": slug},
            {"manufacturer": ids["manufacturer"][manufacturer], "model": model},
        )[0].id
    for slug, (name, manufacturer) in PLATFORMS.items():
        ids["platform"][slug] = get_or_create(
            nb.dcim.platforms,
            {"slug": slug},
            {"name": name, "manufacturer": ids["manufacturer"][manufacturer]},
        )[0].id
    ids["role"] = get_or_create(
        nb.dcim.device_roles, {"slug": "router"}, {"name": "Router", "color": "2196f3"}
    )[0].id
    ids["tag"] = get_or_create(nb.extras.tags, {"slug": "netcheck"}, {"name": "netcheck"})[0].id
    ids["site"] = {
        slug: get_or_create(nb.dcim.sites, {"slug": slug}, {"name": slug, "status": "active"})[0].id
        for slug in nblab.LAB_SITES.values()
    }
    return ids


def ensure_device(nb, ids: dict, site: str, name: str, host: str, driver: str) -> bool:
    """Crée (ou complète) un équipement avec son interface de management et son IP primaire. True
    s'il est créé."""
    _, device_type, platform, interface_name = DRIVERS[driver]
    created = False
    device = nb.dcim.devices.get(name=name, site_id=ids["site"][site])
    if device is None:
        device = nb.dcim.devices.create(
            name=name,
            role=ids["role"],
            device_type=ids["device_type"][device_type],
            site=ids["site"][site],
            platform=ids["platform"][platform],
            status="active",
            tags=[ids["tag"]],
        )
        created = True
    # `device_id` filtre, `device` crée : deux champs différents pour NetBox
    interface = nb.dcim.interfaces.get(device_id=device.id, name=interface_name) or nb.dcim.interfaces.create(
        device=device.id, name=interface_name, type="virtual"
    )
    address = f"{host}/24"
    ip = nb.ipam.ip_addresses.get(address=address, device_id=device.id) or nb.ipam.ip_addresses.get(
        address=address
    )
    if ip is None:
        ip = nb.ipam.ip_addresses.create(
            address=address,
            status="active",
            assigned_object_type="dcim.interface",
            assigned_object_id=interface.id,
        )
    elif ip.assigned_object_id != interface.id:
        ip.assigned_object_type, ip.assigned_object_id = "dcim.interface", interface.id
        ip.save()
    if not device.primary_ip4 or device.primary_ip4.id != ip.id:
        device.primary_ip4 = ip.id
        device.save()
    return created


def load_labs(nb, ids: dict, labs: list[str]) -> dict[str, int]:
    counts = {}
    for lab in labs:
        inventory = yaml.safe_load(INVENTORIES[lab].read_text(encoding="utf-8"))
        defaults = inventory.get("defaults") or {}
        created = 0
        for name, attrs in inventory["routers"].items():
            attrs = attrs or {}
            driver = attrs.get("driver", defaults.get("driver", "frr"))
            created += ensure_device(nb, ids, nblab.LAB_SITES[lab], name, attrs["host"], driver)
        counts[lab] = created
    return counts


def ensure_readonly_user(admin: nblab.Admin, nb) -> int:
    user = nb.users.users.get(username=nblab.RO_USER)
    if user is None:
        # Mot de passe aléatoire JETÉ : le compte ne sert qu'à porter un jeton, personne ne s'y connecte.
        user = nb.users.users.create(
            username=nblab.RO_USER,
            password=secrets.token_urlsafe(40),
            is_active=True,
            is_staff=False,
            is_superuser=False,
        )
    permission = nb.users.permissions.get(name=PERMISSION)
    if permission is None:
        nb.users.permissions.create(
            name=PERMISSION, enabled=True, object_types=["dcim.device"], actions=["view"], users=[user.id]
        )
    elif user.id not in [u if isinstance(u, int) else u.id for u in permission.users]:
        permission.users = [*(u if isinstance(u, int) else u.id for u in permission.users), user.id]
        permission.save()
    return user.id


def token_is_valid(base: str, token_file: Path) -> bool:
    if not token_file.is_file():
        return False
    session = nblab.new_session()
    session.headers["Authorization"] = f"Bearer {token_file.read_text(encoding='utf-8').strip()}"
    return session.get(f"{base}/api/status/", timeout=15).status_code == 200


def ensure_readonly_token(admin: nblab.Admin, user_id: int, token_file: Path, rotate: bool) -> str:
    if not rotate and token_is_valid(admin.base, token_file):
        return "conservé (encore valide)"
    previous = admin.json("/api/users/tokens/", params={"user_id": user_id, "limit": 1000})["results"]
    reply = admin.call(
        "POST",
        "/api/users/tokens/",
        json={"user": user_id, "write_enabled": False, "description": "netcheck, lecture seule (lab)"},
    )
    if reply.status_code not in (200, 201):
        nblab.fail(f"création du jeton en lecture seule refusée (HTTP {reply.status_code})")
    body = reply.json()
    nblab.write_token_file(token_file, nblab.bearer_from(body))
    for old in previous:  # l'ancien jeton est révoqué : un seul jeton valide à la fois
        admin.call("DELETE", f"/api/users/tokens/{old['id']}/")
    return "créé (lecture seule), ancien révoqué" if previous else "créé (lecture seule)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument(
        "--labs", default="frr,multivendor,ceos", help="labs à charger, séparés par des virgules"
    )
    parser.add_argument("--netbox", default=nblab.DEFAULT_URL)
    parser.add_argument("--env-file", default=str(nblab.DEFAULT_ENV_FILE))
    parser.add_argument("--token-file", default=str(nblab.DEFAULT_TOKEN_FILE))
    parser.add_argument(
        "--rotate-token", action="store_true", help="créer un nouveau jeton et révoquer l'ancien"
    )
    args = parser.parse_args(argv)
    labs = args.labs.split(",")
    unknown = [lab for lab in labs if lab not in INVENTORIES]
    if unknown:
        nblab.fail(f"lab(s) inconnu(s) : {', '.join(unknown)} (attendus : {', '.join(INVENTORIES)})")
    with nblab.Admin(args.netbox, args.env_file) as admin:
        nb = pynetbox.api(args.netbox, token=admin.token)
        nb.http_session = admin.session
        ids = ensure_reference_objects(nb)
        counts = load_labs(nb, ids, labs)
        user_id = ensure_readonly_user(admin, nb)
        state = ensure_readonly_token(admin, user_id, Path(args.token_file), args.rotate_token)
        print("équipements créés : " + ", ".join(f"{lab} {n}" for lab, n in counts.items()))
        print(
            f"compte {nblab.RO_USER} : une permission (view sur dcim.device) ; "
            f"jeton {state} : {args.token_file}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
