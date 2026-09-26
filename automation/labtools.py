"""Briques communes aux scripts : inventaire, connexion SSH, exécution de vtysh en parallèle."""
import json
import os
import shlex
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml
from netmiko import ConnectHandler

BASE = Path(__file__).resolve().parent

# Lignes de la running-config qui changent sans modification réelle (version, bannières)
NOISE_PREFIXES = ("Building configuration", "Current configuration", "frr version")


def load_inventory(only=None, path=BASE / "inventory.yml"):
    """Fusionne defaults + attributs de chaque routeur ; filtre éventuel sur une liste de noms."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})
    routers = {}
    for name, attrs in data["routers"].items():
        if only and name not in only:
            continue
        r = {**defaults, **(attrs or {}), "name": name}
        r["username"] = os.environ.get("LAB_USER", r["username"])
        r["password"] = os.environ.get("LAB_PASS", r["password"])
        routers[name] = r
    if only and set(only) - set(routers):
        raise SystemExit(f"Routeur(s) inconnu(s) : {', '.join(sorted(set(only) - set(routers)))}")
    return routers


class Router:
    """Session SSH vers un routeur FRR ; s'utilise avec 'with Router(r) as rt:'."""

    def __init__(self, r):
        self.r = r
        self.conn = None

    def __enter__(self):
        self.conn = ConnectHandler(
            device_type=self.r["device_type"], host=self.r["host"],
            username=self.r["username"], password=self.r["password"],
            timeout=10, conn_timeout=10,
        )
        return self

    def __exit__(self, *exc):
        if self.conn:
            self.conn.disconnect()

    def vtysh(self, *commands):
        """Exécute une ou plusieurs commandes vtysh non interactives et renvoie la sortie brute."""
        args = " ".join(f"-c {shlex.quote(c)}" for c in commands)
        raw = self.conn.send_command(f"{self.r['vtysh']} {args}", read_timeout=30)
        # vtysh non-root peut avertir qu'il ne lit pas vtysh.conf : bruit sans conséquence, on l'écarte
        out = "\n".join(l for l in raw.splitlines() if not l.startswith("% Can't open configuration file"))
        for marker in ("command not found", "failed to connect to any daemons"):
            if marker in out.lower():
                raise RuntimeError(f"vtysh inutilisable : {out.strip()[:120]}")
        return out

    def vtysh_json(self, command):
        return json.loads(self.vtysh(f"{command} json"))

    def running_config(self):
        return self.vtysh("show running-config")


def clean_config(text):
    """Retire le bruit (bannières, version, séparateurs '!', lignes vides) pour comparer le fond."""
    lines = []
    for line in text.splitlines():
        s = line.rstrip()
        if not s.strip() or s.strip() == "!" or s.lstrip().startswith(NOISE_PREFIXES):
            continue
        lines.append(s)
    return lines


def run_parallel(task, routers, workers=5):
    """Lance task(router_dict) sur tous les routeurs ; renvoie {nom: (ok, résultat ou message d'erreur)}."""
    def safe(r):
        try:
            return r["name"], (True, task(r))
        except Exception as e:  # une panne sur un routeur ne doit pas bloquer les autres
            return r["name"], (False, f"{type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(sorted(pool.map(safe, routers.values())))
