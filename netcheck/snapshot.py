"""Sauvegarde et chargement JSON des snapshots (snapshots/<nom>/<équipement>.json + meta.json).

snapshots/ est dans .gitignore (C4) : ces fichiers contiennent des configurations complètes.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from netcheck import __version__
from netcheck.model import DeviceState

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS_DIR = REPO_ROOT / "snapshots"


def save(name: str, results: dict, force: bool = False) -> Path:
    """Écrit un snapshot à partir du résultat de collector.collect_all().

    results : {équipement: (True, DeviceState) ou (False, message d'erreur)}.
    Un équipement injoignable est quand même écrit, avec reachable=False (§5.1).
    """
    out_dir = SNAPSHOTS_DIR / name
    if out_dir.exists() and not force:
        raise FileExistsError(f"le snapshot '{name}' existe déjà (utilise --force pour écraser)")
    out_dir.mkdir(parents=True, exist_ok=True)

    errors = {}
    for device_name, (ok, value) in results.items():
        if ok:
            state = value
        else:
            errors[device_name] = str(value)
            state = DeviceState(
                name=device_name, host="?", timestamp=_now(), reachable=False, error=str(value),
            )
        (out_dir / f"{device_name}.json").write_text(
            json.dumps(state.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8",
        )

    meta = {
        "name": name,
        "timestamp": _now(),
        "devices": sorted(results),
        "errors": errors,
        "netcheck_version": __version__,
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    return out_dir


def load(name: str) -> dict[str, DeviceState]:
    """Charge tous les <équipement>.json d'un snapshot (hors meta.json)."""
    out_dir = SNAPSHOTS_DIR / name
    if not out_dir.is_dir():
        raise FileNotFoundError(f"snapshot '{name}' introuvable")
    devices = {}
    for f in sorted(out_dir.glob("*.json")):
        if f.name == "meta.json":
            continue
        devices[f.stem] = DeviceState.from_dict(json.loads(f.read_text(encoding="utf-8")))
    return devices


def load_meta(name: str) -> dict:
    meta_file = SNAPSHOTS_DIR / name / "meta.json"
    if not meta_file.is_file():
        raise FileNotFoundError(f"snapshot '{name}' introuvable")
    return json.loads(meta_file.read_text(encoding="utf-8"))


def list_snapshots() -> list[dict]:
    """Liste les snapshots existants (meta.json de chacun), triés par nom."""
    if not SNAPSHOTS_DIR.is_dir():
        return []
    out = []
    for d in sorted(SNAPSHOTS_DIR.iterdir()):
        meta_file = d / "meta.json"
        if d.is_dir() and meta_file.is_file():
            out.append(json.loads(meta_file.read_text(encoding="utf-8")))
    return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
