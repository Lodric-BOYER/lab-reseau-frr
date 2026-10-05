"""Sauvegarde et chargement JSON des snapshots (snapshots/<nom>/<équipement>.json + meta.json).

snapshots/ est dans .gitignore (C4) : ces fichiers contiennent des configurations complètes.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from netcheck import __version__
from netcheck.model import DeviceState
from netcheck.usage import UsageError

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS_DIR = REPO_ROOT / "snapshots"


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


def snapshot_dir(name: str) -> Path:
    """À L'ÉCRITURE, le nom d'un snapshot devient un nom de dossier : lettres, chiffres, point, tiret,
    souligné. Refuse `..`, un séparateur de chemin ou un nom vide, qui feraient écrire (--force) hors de
    snapshots/. La lecture accepte aussi un chemin (snapshots hors du dépôt) : lire n'écrase rien."""
    if not _NAME.fullmatch(name):
        raise UsageError(f"nom de snapshot invalide : {name!r} (lettres, chiffres, « . », « - » et « _ », "
                         "100 caractères au plus, commençant par une lettre ou un chiffre)")
    return SNAPSHOTS_DIR / name


def save(name: str, results: dict, force: bool = False, credentials: dict | None = None,
         scope: dict | None = None) -> Path:
    """Écrit un snapshot à partir du résultat de collector.collect_all().

    results : {équipement: (True, DeviceState) ou (False, message d'erreur)}.
    Un équipement injoignable est quand même écrit, avec reachable=False (§5.1).
    scope : `snapshotscope.scope_record(...)`, le périmètre du snapshot (v0.4) : l'inventaire au moment de
    la prise et les équipements demandés par `-d`. Sans lui, `check --snapshot` ne peut pas dire ce qui
    manque.
    """
    out_dir = snapshot_dir(name)
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
    if scope is not None:
        meta["scope"] = scope
    if credentials:
        meta["credential_sources"] = credentials   # d'où viennent les identifiants (jamais une valeur)
    (out_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    return out_dir


def load(name: str) -> dict[str, DeviceState]:
    """Charge tous les <équipement>.json d'un snapshot (hors meta.json)."""
    out_dir = SNAPSHOTS_DIR / name   # un chemin absolu est accepté en lecture (snapshots hors du dépôt)
    if not out_dir.is_dir():
        raise FileNotFoundError(f"snapshot '{name}' introuvable")
    devices = {}
    for f in sorted(out_dir.glob("*.json")):
        if f.name == "meta.json":
            continue
        try:
            devices[f.stem] = DeviceState.from_dict(json.loads(f.read_text(encoding="utf-8")))
        except (ValueError, KeyError, TypeError, AttributeError, OSError):
            # ValueError couvre JSONDecodeError et UnicodeDecodeError. Jamais le contenu dans le message.
            raise UsageError(f"snapshot '{name}' : {f.name} est corrompu ou illisible "
                             "(refaites le snapshot)") from None
    return devices


def load_meta(name: str) -> dict:
    meta_file = SNAPSHOTS_DIR / name / "meta.json"
    if not meta_file.is_file():
        raise FileNotFoundError(f"snapshot '{name}' introuvable")
    return _read_meta(meta_file, name)


def _read_meta(meta_file: Path, name: str) -> dict:
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise UsageError(f"snapshot '{name}' : meta.json est corrompu ou illisible") from None
    if not isinstance(meta, dict):
        raise UsageError(f"snapshot '{name}' : meta.json est corrompu (objet attendu)")
    return meta


def list_snapshots() -> list[dict]:
    """Liste les snapshots existants (meta.json de chacun), triés par nom."""
    if not SNAPSHOTS_DIR.is_dir():
        return []
    out = []
    for d in sorted(SNAPSHOTS_DIR.iterdir()):
        meta_file = d / "meta.json"
        if d.is_dir() and meta_file.is_file():
            out.append(_read_meta(meta_file, d.name))
    return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
