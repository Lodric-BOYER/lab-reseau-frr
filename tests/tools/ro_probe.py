#!/usr/bin/env python3
"""Sondes de lab du compte « netcheck-ro » (phase C5) : ce qu'il PEUT lire, ce qui lui est REFUSÉ.

Ce ne sont PAS des appels de netcheck : ce sont des sessions écrites à la main (paramiko, Netmiko, curl),
parce que netcheck, lui, ne tente jamais une commande refusée (il ne sort que sa liste blanche). Chaque
ligne affichée est
« OK <contrôle> » ou « KO <contrôle> » ; code retour 1 s'il y a un KO. Utilisé par tests/lib_ro.sh.

    ro_probe.py eos     --host IP --key CLÉ
    ro_probe.py srlinux --host IP --key CLÉ --admin-password-file F
    ro_probe.py services --host IP --user U --password-file F [--expect denied|pathz]  (gNMI, JSON-RPC)

Jamais `write` ni `copy running-config startup-config` : la famille « écriture » est représentée par
`copy running-config file:/tmp/...` (écrit un fichier dans /tmp du conteneur et rien d'autre).
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab-access"))
import labtls  # noqa: E402  (garde commune des outils de lab : TLS et clés d'hôte non vérifiés)

KO = 0


def report(ok: bool, label: str) -> bool:
    global KO
    print(("OK " if ok else "KO ") + label)
    KO += 0 if ok else 1
    return ok


def _key(path: str) -> paramiko.PKey:
    return paramiko.Ed25519Key.from_private_key_file(path)


# --- EOS ---------------------------------------------------------------------------------------------

EOS_ALLOWED = [
    "show interfaces | json",
    "show ipv6 interface | json",
    "show vrf | json",
    "show ip route vrf all | json",
    "show ipv6 route vrf all | json",
    "show ip ospf neighbor | json",
    "show ospfv3 neighbor | json",
    "show ip bgp summary | json",
    "show ip bgp | json",
    "show ipv6 bgp summary | json",
    "show ipv6 bgp | json",
    "show running-config",
]
EOS_DENIED = [
    "configure terminal",
    "configure session c5probe",
    "copy running-config file:/tmp/c5-copy",
    "delete flash:c5-nonexistent",
    "bash",
    "python-shell",
    "show version",
    "show startup-config",
    "show running-config sanitized",
    "show running-config all",
    "show ip route | json",
    "show ip bgp neighbors",
    "show ip bgp summary vrf all",
    "sh ver",
    # filtres et redirections : refusés (le filtre ne s'applique pas, rien n'est écrit)
    "show interfaces | grep Ethernet",
    "show running-config | redirect file:/tmp/c5-redirect",
    "show interfaces | tee file:/tmp/c5-tee",
    "show interfaces > file:/tmp/c5-gt",
]


def eos(args) -> None:
    from netmiko import ConnectHandler

    conn = ConnectHandler(
        device_type="arista_eos",
        host=args.host,
        username="netcheck-ro",
        pkey=_key(args.key),
        use_keys=False,
        allow_agent=False,
        ssh_strict=False,
        timeout=30,
    )
    report(
        True,
        "EOS : session ouverte par clé, `terminal width` et `terminal length` (Netmiko) permis par le rôle",
    )
    conn.enable()
    report(conn.find_prompt().endswith("#"), "EOS : enable() réussit (mode privilégié, privilege 15)")
    for cmd in EOS_ALLOWED:
        text = conn.send_command_timing(cmd, read_timeout=30)
        good = "Authorization denied" not in text and len(text) > 40
        if good and cmd.endswith("| json"):
            try:
                json.loads(text)
            except ValueError:
                good = False
        report(good, f"EOS : permis -> {cmd}")
    for cmd in EOS_DENIED:
        text = conn.send_command_timing(cmd, read_timeout=30)
        denied = "Authorization denied" in text
        no_mode = "(config" not in conn.find_prompt() and not conn.find_prompt().startswith("[")
        if "(config" in conn.find_prompt():
            conn.write_channel("end\n")
        report(denied and no_mode, f"EOS : refusé -> {cmd}")
    conn.disconnect()


# --- SR Linux ----------------------------------------------------------------------------------------

SRL_ALLOWED = [
    "info from state interface * | as json",
    "info from state network-instance * interface * | as json",
    "info from state network-instance * route-table | as json",
    "show network-instance default protocols ospf neighbor | as json",
    "info from running interface *",
    "info from running network-instance default protocols ospf",
    "info from running system authentication",
    "info from running system banner",
]
SRL_DENIED = [
    "enter candidate",
    "bash id",
    "save file /tmp/c5-save.json",
    "file cat /etc/passwd",
    "info from running /",
    "info from running system aaa",
    "show version",
    "info from running interface * | as json",
    "info from state system aaa authentication",
]


def _ssh(host: str, user: str, cmd: str, **kw) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )  # lab : la clé d'hôte est épinglée par netcheck
    client.connect(host, username=user, allow_agent=False, look_for_keys=False, timeout=20, **kw)
    try:
        _, o, e = client.exec_command(cmd, timeout=60)
        return (o.read() + e.read()).decode(errors="replace")
    finally:
        client.close()


def srlinux(args) -> None:
    pw = Path(args.admin_password_file).read_text(encoding="utf-8").strip()
    key = _key(args.key)
    for cmd in SRL_ALLOWED:
        ro = _ssh(args.host, "netcheck-ro", cmd, pkey=key)
        adm = _ssh(args.host, "admin", cmd, password=pw)
        same = abs(len(ro) - len(adm)) <= max(80, len(adm) // 40) and len(adm) > 0
        report(
            same and "not authorized" not in ro.lower(),
            f"SR Linux : mêmes données que admin ({len(ro)} / {len(adm)} o) -> {cmd}",
        )
    for cmd in SRL_DENIED:
        ro = _ssh(args.host, "netcheck-ro", cmd, pkey=key)
        report("Not authorized" in ro, f"SR Linux : refusé -> {cmd}")


# --- gNMI et JSON-RPC (curl), pour dire « refusé » avec un refus observé -----------------------------


def _curl_config(user: str, password: str, directory: str) -> str:
    path = Path(directory) / "curl.conf"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(f'header = "username: {user}"\nheader = "password: {password}"\n')
    return str(path)


def _gnmi(host: str, user: str, password: str, method: str, message: bytes, tls: list[str]) -> str:
    body = b"\x00" + struct.pack(">I", len(message)) + message
    with tempfile.TemporaryDirectory() as tmp:
        config = _curl_config(user, password, tmp)
        headers = Path(tmp) / "h"
        subprocess.run(
            [
                "curl",
                "-s",
                "--http2",
                *tls,
                "-m",
                "20",
                "-K",
                config,
                "-D",
                str(headers),
                "-o",
                "/dev/null",
                "-X",
                "POST",
                "-H",
                "content-type: application/grpc",
                "-H",
                "te: trailers",
                "--data-binary",
                "@-",
                f"https://{host}:57400/gnmi.gNMI/{method}",
            ],
            input=body,
            capture_output=True,
            timeout=40,
            check=False,
        )
        text = headers.read_text(encoding="utf-8", errors="replace") if headers.exists() else ""
    status = [
        ln.strip() for ln in text.splitlines() if ln.lower().startswith(("grpc-status", "grpc-message"))
    ]
    return " ".join(status)


def _path_msg(*names: str) -> bytes:
    def elem(n: str) -> bytes:
        return b"\x1a" + bytes([len(n) + 2]) + b"\x0a" + bytes([len(n)]) + n.encode()

    return b"".join(elem(n) for n in names)


def _jsonrpc(host: str, user: str, password: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "curl.conf"
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f'user = "{user}:{password}"\n')
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-m",
                "20",
                "-K",
                str(config),
                "-H",
                "Content-Type: application/json",
                f"http://{host}/jsonrpc",
                "-d",
                '{"jsonrpc":"2.0","id":1,"method":"get","params":{"commands":[{"path":"/system/name/host-name","datastore":"state"}]}}',
            ],
            capture_output=True,
            timeout=40,
            check=False,
        )
    return result.stdout.decode(errors="replace").strip()[:160]


def services(args) -> None:
    pw = Path(args.password_file).read_text(encoding="utf-8").strip()
    get_msg = b"\x12" + bytes([len(_path_msg("system", "name"))]) + _path_msg("system", "name")
    value = b'"c5-set-must-not-apply"'
    upd = (
        b"\x0a"
        + bytes([len(_path_msg("system", "name", "host-name"))])
        + _path_msg("system", "name", "host-name")
        + b"\x1a"
        + bytes([len(value) + 2])
        + b"\x5a"
        + bytes([len(value)])
        + value
    )  # gnmi.Update : path = 1, val = 3 (le champ 2 est l'ancien « value ») ; TypedValue.json_ietf_val = 11
    set_msg = b"\x22" + bytes([len(upd)]) + upd  # SetRequest.update
    results = {
        "gNMI Get": _gnmi(args.host, args.user, pw, "Get", get_msg, args.tls),
        "gNMI Set": _gnmi(args.host, args.user, pw, "Set", set_msg, args.tls),
        "JSON-RPC": _jsonrpc(args.host, args.user, pw),
    }
    for name, text in results.items():
        gnmi_refused = "grpc-status: 7" in text or "grpc-status: 16" in text
        if args.expect == "denied":  # services [ cli ] : ni gNMI ni JSON-RPC
            refused = (
                gnmi_refused
                if name.startswith("gNMI")
                else ("AuthenticationFailed" in text or "denied" in text.lower() or "error" in text.lower())
            )
            report(refused, f"{name} refusé pour {args.user} (services [ cli ]) : {text[:100]}")
        elif (
            name == "gNMI Set"
        ):  # services déclarés (témoin) : le service répond, mais la politique Pathz refuse l'écriture
            report(
                gnmi_refused,
                f"gNMI Set refusé par la politique Pathz même avec le service déclaré : {text[:100]}",
            )
        else:  # témoin : la couche de service laisse passer, le refus précédent venait bien du rôle
            reached = (not gnmi_refused) if name.startswith("gNMI") else ("result" in text)
            report(reached, f"{name} atteint avec le service déclaré (témoin) : {text[:90]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("eos", "srlinux"):
        p = sub.add_parser(name, allow_abbrev=False)
        p.add_argument("--host", required=True)
        p.add_argument("--key", required=True)
        p.add_argument("--lab-inventory", help="inventaire `lab: true` (clés d'hôte SSH non vérifiées)")
        if name == "srlinux":
            p.add_argument("--admin-password-file", required=True)
    s = sub.add_parser("services", allow_abbrev=False)
    s.add_argument("--host", required=True)
    s.add_argument("--user", required=True)
    s.add_argument("--password-file", required=True)
    s.add_argument("--expect", choices=["denied", "pathz"], default="denied")
    labtls.add_arguments(s)
    args = parser.parse_args(argv)
    try:
        if args.command == "services":
            args.tls = labtls.tls_from_args(args)
            # le mode strict de curl ne peut pas valider un certificat de lab : sans --insecure, rien ne part
            if not args.tls:
                raise labtls.TlsRefused(
                    "services : --insecure --lab-inventory <inventaire lab: true> (ou --cacert)"
                )
        else:
            labtls.require_lab(args.lab_inventory, "clés d'hôte SSH non vérifiées (AutoAddPolicy)")
    except labtls.TlsRefused as exc:
        print(f"refusé : {exc}", file=sys.stderr)
        return 3
    {"eos": eos, "srlinux": srlinux, "services": services}[args.command](args)
    return 1 if KO else 0


if __name__ == "__main__":
    sys.exit(main())
