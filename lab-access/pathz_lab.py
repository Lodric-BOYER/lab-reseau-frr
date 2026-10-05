#!/usr/bin/env python3
"""Politique gNSI Pathz de SR Linux pour le lab : JSON lisible -> protobuf -> `gnsi.pathz.v1.Pathz/Rotate`.

SR Linux 26.7 ne donne aucun accès aux données à un utilisateur qui n'est pas superutilisateur : les rôles
ne règlent que les services et les commandes (voir lab-access/accounts_lab.sh). L'accès aux CHEMINS vient
d'une politique Pathz, qui n'existe que dans l'état de l'équipement et ne se pousse que par gNSI (un appel
gRPC). Ce script est l'outil de lab qui la pousse, comme `pin_hostkeys.sh` épingle les clés : à rejouer
après chaque déploiement. Rien de tout cela n'est une dépendance de netcheck.

PÉRIMÈTRE. Outil de LAB, épinglé sur SR Linux 26.7.2 (VALIDATED_FOR) : le schéma `gnsi.pathz.v1` a été lu
sur cette version par réflexion gRPC. Il refuse un autre équipement (code 3) sauf `--allow-other-version`.
En production, une politique Pathz se pousse avec l'outillage gNSI officiel de l'équipementier, PAS avec
ce script. `gnsic` v0.0.4, essayé, n'a pas de commande `pathz`. netcheck n'importe rien d'ici.

Bibliothèque standard seulement. L'appel gRPC passe par `curl --http2` (HTTP/2 + trames de 5 octets) ;
les identifiants vont dans un fichier de configuration curl en 0600, jamais dans la ligne de commande.

TLS : vérification stricte par défaut. Le certificat de lab est auto-signé : `--insecure` doit être
demandé, exige `--lab-inventory` désignant un inventaire qui déclare `lab: true` (même règle que
`--host-keys accept-new`), et chaque usage est annoncé sur stderr (lab-access/labtls.py). `--cacert`
pour une autorité de confiance.

Après un envoi, le script RELIT l'état de l'équipement : version de la politique active, puis une sonde
Pathz par règle et par attendu de la politique (clé « attendus »). Un écart = message clair et code 1 :
jamais de succès silencieux.

    pathz_lab.py push   <politique.json> --target <ip> --user <u> --password-file <f> [TLS]
    pathz_lab.py verify <politique.json> ...      (sondes seules, sans rien envoyer : état « effectif ? »)
    pathz_lab.py get    --target <ip> --user <u> --password-file <f> ...
    pathz_lab.py probe  <utilisateur> <chemin> <read|write> --target ... (réponse de l'équipement)
    pathz_lab.py encode <politique.json>          (octets protobuf en hexadécimal : tests)
    [TLS] = --insecure --lab-inventory <inventaire lab: true>   ou   --cacert <autorité>

Codes : 0 effectif ; 1 refusé par l'équipement, politique NON effective ou droits du fichier de mot de
passe ; 3 usage refusé (TLS non vérifié sans inventaire lab, équipement hors version validée).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import labtls

ACTIONS = {"deny": 1, "permit": 2}
MODES = {"read": 1, "write": 2}
PORT = 57400
VALIDATED_FOR = (
    "26.7.2"  # version de SR Linux sur laquelle le schéma gNSI Pathz a été lu et les preuves faites
)


# --- protobuf à la main (varint et « longueur + octets » suffisent pour ces messages) -------------


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        low = n & 0x7F
        n >>= 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def f_bytes(number: int, data: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(data)) + data


def f_str(number: int, text: str) -> bytes:
    return f_bytes(number, text.encode("utf-8"))


def f_int(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


_ELEM = re.compile(r"([^/\[\]]+)((?:\[[^\]]+\])*)$")
_KEY = re.compile(r"\[([^=\]]+)=([^\]]*)\]")


def split_path(path: str) -> list[str]:
    """Éléments d'un chemin, coupés hors des crochets : `ethernet-1/1` est une valeur de clé."""
    parts, depth, current = [], 0, ""
    for char in path.lstrip("/"):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        if char == "/" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return [p for p in parts if p]


def encode_path(path: str) -> bytes:
    """`/network-instance[name=default]/protocols/ospf` -> gnmi.Path { elem { name, key } } ; `/` = racine."""
    if not path.startswith("/"):
        raise ValueError(f"chemin absolu attendu : {path!r}")
    out = b""
    for part in split_path(path):
        match = _ELEM.fullmatch(part)
        if not match:
            raise ValueError(f"élément de chemin illisible : {part!r}")
        elem = f_str(1, match.group(1))
        for key, value in _KEY.findall(match.group(2)):
            elem += f_bytes(
                2, f_str(1, key) + f_str(2, value)
            )  # map<string,string> : entrée {1: clé, 2: valeur}
        out += f_bytes(3, elem)
    return out


def encode_rule(rule: dict) -> bytes:
    for needed in ("id", "path", "action", "mode"):
        if needed not in rule:
            raise ValueError(f"règle {rule.get('id', '?')} : « {needed} » manque")
    if ("user" in rule) == ("group" in rule):
        raise ValueError(f"règle {rule['id']} : exactement un de « user » ou « group »")
    if rule["action"] not in ACTIONS or rule["mode"] not in MODES:
        raise ValueError(f"règle {rule['id']} : action {sorted(ACTIONS)}, mode {sorted(MODES)}")
    out = f_str(1, rule["id"])
    out += f_str(2, rule["user"]) if "user" in rule else f_str(3, rule["group"])
    out += f_bytes(4, encode_path(rule["path"]))
    out += f_int(5, ACTIONS[rule["action"]]) + f_int(6, MODES[rule["mode"]])
    return out


def encode_policy(policy: dict) -> bytes:
    out = b"".join(f_bytes(1, encode_rule(r)) for r in policy.get("rules", []))
    for group in policy.get("groups", []):
        users = b"".join(f_bytes(2, f_str(1, u)) for u in group.get("users", []))
        out += f_bytes(2, f_str(1, group["name"]) + users)
    return out


def encode_rotate(policy: dict, created_on: int) -> list[bytes]:
    """Les deux messages du flux : UploadRequest(version, created_on, policy) avec force_overwrite, puis
    FinalizeRequest. Sans force_overwrite, l'équipement refuse de remplacer une politique de même version."""
    upload = f_str(1, policy["version"]) + f_int(2, created_on) + f_bytes(3, encode_policy(policy))
    return [f_bytes(1, upload) + f_int(3, 1), f_bytes(2, b"")]  # force_overwrite : le script est rejouable


# --- appel gRPC par curl -----------------------------------------------------------------------------------


def _grpc(
    target: str,
    method: str,
    frames: list[bytes],
    user: str,
    password: str,
    tls: tuple[str, ...] | list[str] = (),
) -> tuple[list[bytes], dict]:
    """`tls` : options TLS de curl venant de labtls.curl_tls_args ; vide = vérification stricte."""
    body = b"".join(b"\x00" + struct.pack(">I", len(f)) + f for f in frames)
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "curl.conf"
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f'header = "username: {user}"\nheader = "password: {password}"\n')
        headers = Path(tmp) / "headers"
        result = subprocess.run(
            [
                "curl",
                "-s",
                "--http2",
                *tls,
                "-m",
                "30",
                "-K",
                str(config),
                "-D",
                str(headers),
                "-X",
                "POST",
                "-H",
                "content-type: application/grpc",
                "-H",
                "te: trailers",
                "--data-binary",
                "@-",
                f"https://{target}:{PORT}/{method}",
            ],
            input=body,
            capture_output=True,
            timeout=60,
            check=False,
        )
        text = headers.read_text(encoding="utf-8", errors="replace") if headers.exists() else ""
    out, i, data = [], 0, result.stdout
    while i + 5 <= len(data):
        n = struct.unpack(">I", data[i + 1 : i + 5])[0]
        out.append(data[i + 5 : i + 5 + n])
        i += 5 + n
    meta = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("HTTP"):
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
    meta["curl-rc"] = str(result.returncode)
    return out, meta


_TLS_CURL_RC = {35: "négociation TLS", 51: "identité du certificat", 58: "certificat local", 60: "certificat"}


def _check(meta: dict, what: str) -> None:
    if meta.get("grpc-status", "?") != "0":
        rc = int(meta.get("curl-rc", "0") or 0)
        hint = ""
        if rc in _TLS_CURL_RC:
            hint = (
                f" ; échec TLS ({_TLS_CURL_RC[rc]}) : certificat auto-signé du lab ? "
                "--insecure --lab-inventory <inventaire lab: true> ; sinon --cacert"
            )
        raise SystemExit(
            f"{what} : grpc-status {meta.get('grpc-status', '?')} "
            f"{meta.get('grpc-message', '')} (curl rc={meta.get('curl-rc')}){hint}"
        )


def decode_fields(data: bytes) -> list[tuple[int, int | bytes]]:
    """Champs de premier niveau d'un message protobuf : (numéro, entier | octets)."""
    out, i = [], 0
    while i < len(data):
        key, i = _read_varint(data, i)
        number, kind = key >> 3, key & 7
        if kind == 0:
            value, i = _read_varint(data, i)
        elif kind == 2:
            size, i = _read_varint(data, i)
            value, i = data[i : i + size], i + size
        else:
            raise ValueError(f"type de champ protobuf non géré : {kind}")
        out.append((number, value))
    return out


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    n, shift = 0, 0
    while True:
        if i >= len(data):
            raise ValueError("varint tronqué")
        byte = data[i]
        i += 1
        n |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return n, i


def push(target: str, user: str, password: str, policy: dict, tls=()) -> None:
    """Envoie la politique, puis RELIT l'équipement (verify) : SystemExit si elle n'est pas effective."""
    _, meta = _grpc(
        target, "gnsi.pathz.v1.Pathz/Rotate", encode_rotate(policy, time.time_ns()), user, password, tls
    )
    _check(meta, "Pathz.Rotate")
    verify(target, user, password, policy, tls)


def probe(target: str, user: str, password: str, who: str, path: str, mode: str, tls=()) -> str:
    msg = f_str(1, who) + f_bytes(2, encode_path(path)) + f_int(3, MODES[mode]) + f_int(4, 1)
    frames, meta = _grpc(target, "gnsi.pathz.v1.Pathz/Probe", [msg], user, password, tls)
    _check(meta, "Pathz.Probe")
    action = 0
    if frames:
        for number, value in decode_fields(frames[0]):
            if number == 1 and isinstance(value, int):
                action = value
    return {0: "UNSPECIFIED", 1: "DENY", 2: "PERMIT"}.get(action, str(action))


def get(target: str, user: str, password: str, tls=()) -> bytes:
    frames, meta = _grpc(target, "gnsi.pathz.v1.Pathz/Get", [f_int(1, 1)], user, password, tls)
    _check(meta, "Pathz.Get")
    return frames[0] if frames else b""


def active_version(target: str, user: str, password: str, tls=()) -> str:
    """Version de la politique ACTIVE sur l'équipement (GetResponse.version = champ 1)."""
    for number, value in decode_fields(get(target, user, password, tls)):
        if number == 1 and isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
    return ""


def device_version(target: str, user: str, password: str, tls=()) -> str:
    """Version logicielle de SR Linux (gNMI Get /system/information/version), « » si illisible."""
    msg = f_bytes(2, encode_path("/system/information/version")) + f_int(5, 4)  # encoding = JSON_IETF
    frames, meta = _grpc(target, "gnmi.gNMI/Get", [msg], user, password, tls)
    _check(meta, "gNMI.Get(version)")
    found = re.search(rb"(\d+\.\d+\.\d+)", frames[0] if frames else b"")
    return found.group(1).decode() if found else ""


class VersionRefused(Exception):
    """Équipement hors du périmètre validé (code 3)."""


def check_device(target: str, user: str, password: str, tls=(), allow_other: bool = False) -> str:
    version = device_version(target, user, password, tls)
    if version != VALIDATED_FOR and not allow_other:
        raise VersionRefused(
            f"SR Linux « {version or 'version illisible'} » : cet outil est validé pour "
            f"{VALIDATED_FOR} seulement "
            "(--allow-other-version pour passer outre ; la vérification qui suit décide)"
        )
    return version


def expected_probes(policy: dict) -> list[tuple[str, str, str, str, str]]:
    """(utilisateur, chemin, mode, action attendue, origine) : une sonde par règle (la règle doit être
    effective telle qu'écrite) et une par « attendus » (refus voulus, et accès qui ne doivent pas bouger)."""
    probes = []
    for rule in policy.get("rules", []):
        if "user" in rule:
            path = rule.get("sonde", rule["path"])  # Pathz.Probe refuse les jokers : chemin concret
            probes.append((rule["user"], path, rule["mode"], rule["action"].upper(), f"règle {rule['id']}"))
    for item in policy.get("attendus", []):
        probes.append(
            (
                item["user"],
                item["path"],
                item["mode"],
                item["action"].upper(),
                item.get("pourquoi", "attendu"),
            )
        )
    return probes


def verify(target: str, user: str, password: str, policy: dict, tls=()) -> None:
    """Relit l'équipement : politique ACTIVE = celle du fichier ET réponses prévues. Sinon SystemExit."""
    probes = expected_probes(policy)
    if not probes:
        raise SystemExit("vérification impossible : la politique ne déclare aucune règle ni aucun attendu")
    problems = []
    active = active_version(target, user, password, tls)
    if active != policy["version"]:
        problems.append(f"version active « {active or '(aucune)'} », attendue « {policy['version']} »")
    for who, path, mode, expected, origin in probes:
        got = probe(target, user, password, who, path, mode, tls)
        if got != expected:
            problems.append(f"{who} {mode} {path} : {got} au lieu de {expected} ({origin})")
    if problems:
        raise SystemExit(
            f"politique « {policy['version']} » NON EFFECTIVE sur {target} :\n  - " + "\n  - ".join(problems)
        )
    print(
        f"politique « {policy['version']} » effective sur {target} : version active relue, "
        f"{len(probes)} sonde(s) conformes ({len(policy.get('rules', []))} règle(s))"
    )


def _password(path: str) -> str:
    mode = os.stat(path).st_mode & 0o777
    if mode not in (0o600, 0o400):
        raise SystemExit(f"{path} : droits {oct(mode)} (0600 ou 0400 attendus)")
    return Path(path).read_text(encoding="utf-8").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("push", "verify", "get", "probe"):
        p = sub.add_parser(name, allow_abbrev=False)
        p.add_argument("--target", required=True)
        p.add_argument("--user", required=True)
        p.add_argument("--password-file", required=True)
        labtls.add_arguments(p)
        if name in ("push", "verify"):
            p.add_argument("policy")
            p.add_argument(
                "--allow-other-version",
                action="store_true",
                help=f"équipement autre que SR Linux {VALIDATED_FOR} (non validé)",
            )
        if name == "probe":
            p.add_argument("who")
            p.add_argument("path")
            p.add_argument("mode", choices=sorted(MODES))
    enc = sub.add_parser("encode")
    enc.add_argument("policy")
    args = parser.parse_args(argv)
    if args.command == "encode":
        print(b"".join(encode_rotate(json.loads(Path(args.policy).read_text(encoding="utf-8")), 0)).hex())
        return 0
    try:
        tls = labtls.tls_from_args(args)
        password = _password(args.password_file)
        if args.command in ("push", "verify"):
            version = check_device(args.target, args.user, password, tls, args.allow_other_version)
            print(f"équipement : SR Linux {version or '?'} (validé pour {VALIDATED_FOR})")
    except (labtls.TlsRefused, VersionRefused) as exc:
        print(f"refusé : {exc}", file=sys.stderr)
        return 3
    if args.command in ("push", "verify"):
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        if args.command == "push":
            push(args.target, args.user, password, policy, tls)
        else:
            verify(args.target, args.user, password, policy, tls)
    elif args.command == "get":
        raw = get(args.target, args.user, password, tls)
        print(f"{len(raw)} octets de politique active")
    else:
        print(probe(args.target, args.user, password, args.who, args.path, args.mode, tls))
    return 0


if __name__ == "__main__":
    sys.exit(main())
