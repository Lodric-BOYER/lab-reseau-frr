#!/usr/bin/env python3
"""Preuves NÉGATIVES du jeton en lecture seule de netcheck, sur NOTRE NetBox de lab (jamais netcheck : ce
script).

    prove_readonly.py [--token-file FICHIER] [--revoked-token-out FICHIER]

Chaque ligne affichée est « OK <contrôle> » ou « KO <contrôle> » ; code retour 1 s'il y a un KO.
Prouve avec le jeton :
  - la lecture marche (témoin) ; POST, PUT, PATCH et DELETE sur un équipement sont refusés (403) ;
  - NetBox est inchangé après ces essais (mêmes équipements, mêmes noms) ;
  - le moindre privilège : ni les jetons, ni les sites, ni les utilisateurs ne se lisent ;
  - un jeton RÉVOQUÉ n'ouvre plus rien (401/403) — le fichier du jeton révoqué est écrit pour que le
    scénario de
    shell vérifie que netcheck sort alors en code 3 « jeton refusé ».
Aucune valeur de jeton n'est affichée.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import nblab

KO = 0


def report(ok: bool, label: str) -> bool:
    global KO
    print(("OK " if ok else "KO ") + label)
    KO += 0 if ok else 1
    return ok


def ro_session(token_file: Path):
    session = nblab.new_session()
    session.headers["Authorization"] = f"Bearer {token_file.read_text(encoding='utf-8').strip()}"
    return session


def devices(session, base):
    reply = session.get(f"{base}/api/dcim/devices/", params={"limit": 1000}, timeout=30)
    return reply.status_code, (reply.json()["results"] if reply.status_code == 200 else [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument("--netbox", default=nblab.DEFAULT_URL)
    parser.add_argument("--env-file", default=str(nblab.DEFAULT_ENV_FILE))
    parser.add_argument("--token-file", default=str(nblab.DEFAULT_TOKEN_FILE))
    parser.add_argument("--revoked-token-out")
    args = parser.parse_args(argv)
    base = args.netbox.rstrip("/")
    session = ro_session(Path(args.token_file))

    status, before = devices(session, base)
    report(
        status == 200 and len(before) >= 1,
        f"témoin : la lecture des équipements marche ({len(before)} équipement(s))",
    )
    target = before[0]["id"] if before else 0
    names_before = sorted((d["id"], d["name"]) for d in before)

    attempts = [
        ("POST", "/api/dcim/devices/", {"name": "intrus", "role": 1, "device_type": 1, "site": 1}),
        ("PUT", f"/api/dcim/devices/{target}/", {"name": "intrus"}),
        ("PATCH", f"/api/dcim/devices/{target}/", {"comments": "modifié par un jeton en lecture seule"}),
        ("DELETE", f"/api/dcim/devices/{target}/", None),
    ]
    for method, path, body in attempts:
        reply = session.request(method, base + path, json=body, timeout=30)
        report(reply.status_code == 403, f"{method} sur un équipement refusé (403, reçu {reply.status_code})")

    status, after = devices(session, base)
    report(
        status == 200 and sorted((d["id"], d["name"]) for d in after) == names_before,
        "NetBox est inchangé après les quatre écritures refusées (mêmes équipements, mêmes noms)",
    )

    for path in ("/api/dcim/sites/", "/api/users/users/"):
        reply = session.get(base + path, timeout=30)
        report(
            reply.status_code == 403,
            f"moindre privilège : GET {path} refusé (403, reçu {reply.status_code})",
        )
    # NetBox laisse chaque compte lire la liste de SES jetons (mesuré : 200, pas 403) : on prouve qu'il ne
    # voit que les siens, sans aucune valeur secrète, et qu'il ne peut ni en créer ni en supprimer.
    reply = session.get(base + "/api/users/tokens/", timeout=30)
    mine = reply.json()["results"] if reply.status_code == 200 else []
    own_only = bool(mine) and all(item["user"]["username"] == nblab.RO_USER for item in mine)
    report(
        own_only and not any(item.get("token") for item in mine),
        "la liste des jetons ne montre que ceux de netcheck-ro, sans aucune valeur secrète",
    )
    reply = session.post(base + "/api/users/tokens/", json={"user": 1, "write_enabled": True}, timeout=30)
    report(
        reply.status_code == 403,
        f"créer un jeton, même en écriture, est refusé (403, reçu {reply.status_code})",
    )
    reply = session.delete(f"{base}/api/users/tokens/{mine[0]['id'] if mine else 0}/", timeout=30)
    report(reply.status_code == 403, f"supprimer son propre jeton est refusé (403, reçu {reply.status_code})")
    reply = session.get(base + "/api/status/", timeout=30)
    report(
        reply.status_code == 200,
        "GET /api/status/ reste permis (la seule autre lecture dont netcheck a besoin)",
    )

    with nblab.Admin(args.netbox, args.env_file) as admin:
        with tempfile.TemporaryDirectory() as tmp:
            temporary = Path(tmp) / "revoked.token"
            users = admin.json("/api/users/users/", params={"username": nblab.RO_USER})["results"]
            user_id = users[0]["id"]
            created = admin.call(
                "POST",
                "/api/users/tokens/",
                json={"user": user_id, "write_enabled": False, "description": "preuve de révocation"},
            )
            report(created.status_code in (200, 201), "un second jeton lecture seule se crée")
            body = created.json()
            nblab.write_token_file(temporary, nblab.bearer_from(body))
            doomed = ro_session(temporary)
            report(
                doomed.get(base + "/api/status/", timeout=30).status_code == 200,
                "le second jeton fonctionne (témoin)",
            )
            report(
                admin.call("DELETE", f"/api/users/tokens/{body['id']}/").status_code in (200, 204),
                "le second jeton est révoqué",
            )
            code = doomed.get(base + "/api/status/", timeout=30).status_code
            report(code in (401, 403), f"un jeton révoqué n'ouvre plus rien (HTTP {code})")
            if args.revoked_token_out:
                nblab.write_token_file(args.revoked_token_out, temporary.read_text(encoding="utf-8").strip())
    return 1 if KO else 0


if __name__ == "__main__":
    sys.exit(main())
