"""Lecture de fichiers de configuration hors ligne (SPEC_v4, Phase A5) : `netcheck check --config-dir`.

Aucun équipement n'est interrogé : on lit des fichiers, et seulement cela (lecture seule, aucun transport).
Deux dispositions de dossier, au choix, mélangeables :

    dossier/r1.conf            un fichier par équipement, le NOM de l'équipement est le nom du fichier
    dossier/r1/frr.conf        un sous-dossier par équipement

Le driver d'un équipement est celui de l'inventaire (`-i`), ou celui que donne `--driver` (pour tous). Pour un
sous-dossier qui contient plusieurs fichiers, on prend celui dont le nom est connu du driver
(`Driver.CONFIG_FILENAMES` : frr.conf, startup-config, config.cli). Plusieurs dossiers peuvent être donnés :
un équipement d'un dossier ultérieur remplace celui d'un dossier précédent (c'est ainsi qu'on audite le lab
mixte : `--config-dir configs --config-dir configs-multivendor`, r5 est alors lu en SR Linux).

Rien n'est ignoré en silence : une entrée que la lecture n'utilise pas devient un `ConfigWarning` (ligne 0 :
c'est un fichier, pas une ligne). Deux sortes, comme pour une ligne de configuration :
- « information » (lue, sans effet sur le verdict) : une entrée qui n'est pas une configuration (fichier
  caché, sans extension comme `daemons`, `.md`, `.yml`, `.json`), ou un équipement remplacé par un dossier
  ultérieur ;
- « non audité » (bloque le verdict, comme une ligne non lue) : une entrée qui ressemble à une configuration
  d'équipement mais que l'audit n'a pas pu lire (équipement inconnu de l'inventaire sans `--driver`, driver
  inconnu, plusieurs fichiers sans nom attendu, fichier vide, trop gros ou illisible en UTF-8). Un audit ne
  dit jamais « conforme » sur un équipement qu'il n'a pas lu.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from netcheck.confparse import make_warning
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import ConfigWarning

MAX_BYTES = 5 * 1024 * 1024
# Extensions qui ne sont jamais une configuration d'équipement : documentation et fichiers de données.
_NOT_CONFIG_SUFFIXES = {".md", ".yml", ".yaml", ".json"}


class ConfigDirError(ValueError):
    """Une erreur qui rend l'audit impossible (dossier absent, équipement défini deux fois...)."""


@dataclass(frozen=True)
class Source:
    device: str
    driver: str
    path: str


@dataclass
class Loaded:
    devices: dict[str, DeviceState] = field(default_factory=dict)
    sources: dict[str, Source] = field(default_factory=dict)
    warnings: list[ConfigWarning] = field(default_factory=list)

    def source_info(self, directories: list[str], forced_driver: str | None) -> dict:
        """Ce que les rapports disent du mode hors ligne : d'où vient chaque équipement."""
        return {"mode": "config-dir", "directories": list(directories), "driver_forced": forced_driver,
                "devices": {n: {"driver": s.driver, "file": s.path} for n, s in sorted(self.sources.items())}}


def _note(loaded: Loaded, name: str, path: Path, reason: str, blocking: bool) -> None:
    loaded.warnings.append(ConfigWarning(name, make_warning(0, str(path), reason, kept=not blocking)))


def _read(path: Path) -> tuple[str | None, str]:
    """(texte, "") ou (None, raison) : jamais de remplacement silencieux d'octets illisibles."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None, f"fichier de plus de {MAX_BYTES // (1024 * 1024)} Mo : non lu"
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None, "fichier illisible en UTF-8 : non lu"
    except OSError as e:
        return None, f"fichier illisible ({e.strerror or e.__class__.__name__}) : non lu"
    if not text.strip():
        return None, "fichier vide : aucune configuration à auditer"
    return text, ""


def _pick_in_folder(folder: Path, driver_name: str) -> tuple[Path | None, str]:
    files = sorted(f for f in folder.iterdir() if f.is_file() and not f.name.startswith("."))
    if not files:
        return None, "dossier sans fichier de configuration"
    if len(files) == 1:
        return files[0], ""
    expected = DRIVER_REGISTRY[driver_name].CONFIG_FILENAMES
    named = [f for f in files if f.name in expected]
    if len(named) == 1:
        return named[0], ""
    return None, (f"{len(files)} fichiers et {'aucun' if not named else 'plusieurs'} au nom attendu par le "
                  f"driver {driver_name} ({', '.join(expected) or 'aucun nom connu'})")


def load(directories: list[str | Path], inventory_drivers: dict[str, str] | None = None,
         forced_driver: str | None = None) -> Loaded:
    """Lit les dossiers dans l'ordre. `inventory_drivers` = {équipement: driver} (l'inventaire)."""
    if forced_driver is not None and forced_driver not in DRIVER_REGISTRY:
        raise ConfigDirError(f"driver inconnu : {forced_driver!r} (disponibles : {sorted(DRIVER_REGISTRY)})")
    inventory_drivers = inventory_drivers or {}
    loaded = Loaded()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Première passe : ce que contient chaque dossier. Les remplacements se règlent AVANT toute lecture : un
    # fichier remplacé par un dossier ultérieur n'est jamais lu (il pourrait être d'un autre constructeur que
    # le driver de l'inventaire : le lab mixte a un r5 FRR dans `configs` et un r5 SR Linux plus loin).
    candidates: dict[str, list[Path]] = {}
    for directory in map(Path, directories):
        if not directory.is_dir():
            raise ConfigDirError(f"{directory} n'est pas un dossier")
        found: dict[str, Path] = {}      # équipement -> son fichier (ou son sous-dossier) dans CE dossier
        for entry in sorted(directory.iterdir(), key=lambda e: e.name):
            if entry.name.startswith("."):
                _note(loaded, entry.name, entry, "entrée cachée ignorée (hors disposition)", blocking=False)
                continue
            if entry.is_dir():
                name = entry.name
            elif entry.is_file() and entry.suffix and entry.suffix.lower() not in _NOT_CONFIG_SUFFIXES:
                name = entry.stem
            else:
                _note(loaded, entry.name, entry, "ni un fichier `<équipement>.<extension>` ni un "
                      "sous-dossier `<équipement>/` : ignoré (hors disposition)", blocking=False)
                continue
            if name in found:
                raise ConfigDirError(f"équipement {name!r} défini deux fois dans {directory} : "
                                     f"{found[name].name} et {entry.name}")
            found[name] = entry
        for name, entry in found.items():
            candidates.setdefault(name, []).append(entry)

    # Seconde passe : ne lire que le dernier fichier de chaque équipement.
    for name, entries in candidates.items():
        *replaced, entry = entries
        for old in replaced:
            _note(loaded, name, old, f"équipement aussi défini dans {entry} : ce fichier est remplacé par "
                  "ce dossier ultérieur, il n'est pas lu", blocking=False)
        read = _audit(loaded, name, entry, inventory_drivers, forced_driver)
        if read is not None:
            driver_name, path, text = read
            loaded.devices[name] = DeviceState(name=name, host="-", timestamp=now, reachable=True,
                                               running_config=text, driver=driver_name)
            loaded.sources[name] = Source(name, driver_name, str(path))
    return loaded


def _audit(loaded: Loaded, name: str, entry: Path, inventory_drivers: dict[str, str],
           forced_driver: str | None) -> tuple[str, Path, str] | None:
    """Lit et reconnaît le fichier d'un équipement : (driver, fichier, texte), ou None après avoir dit
    pourquoi il n'est pas audité (note bloquante). Ajoute en information les lignes de premier niveau que
    le driver ne connaît pas."""
    driver_name = forced_driver or inventory_drivers.get(name)
    if driver_name is None:
        _note(loaded, name, entry, "équipement non audité : inconnu de l'inventaire, driver non "
              "déduit (ajoutez-le à l'inventaire ou donnez --driver)", blocking=True)
        return None
    if driver_name not in DRIVER_REGISTRY:
        _note(loaded, name, entry, f"équipement non audité : driver {driver_name!r} inconnu "
              f"(disponibles : {sorted(DRIVER_REGISTRY)})", blocking=True)
        return None
    path, why = entry, ""
    if entry.is_dir():
        path, why = _pick_in_folder(entry, driver_name)
    text = None
    if path is not None:
        text, why = _read(path)
    if text is None:
        _note(loaded, name, entry if path is None else path, f"équipement non audité : {why}", blocking=True)
        return None
    driver = DRIVER_REGISTRY[driver_name]()
    keywords = driver.ROOT_KEYWORDS
    if keywords is not None:
        config = driver.parse_config(text)
        statements = config.root_statements()
        known = sum(word in keywords for _, _, word in statements)
        if not statements or 2 * known < len(statements):
            _note(loaded, name, path, f"équipement non audité : {known} ligne(s) de premier niveau sur "
                  f"{len(statements)} commencent par un mot-clé connu du driver {driver_name} : ce fichier "
                  "n'est pas une configuration reconnue (des notes ? un autre équipement ?)", blocking=True)
            return None
        already = {w.line for w in config.warnings}    # déjà signalée par l'analyse (ligne `set` non lue)
        for number, line_text, word in statements:
            if word not in keywords and number not in already:
                reason = (f"ligne de premier niveau dont le premier mot « {word} » n'est pas un mot-clé "
                          f"connu du driver {driver_name} : lue, jamais prise pour une commande connue")
                warning = make_warning(number, line_text, reason, kept=True)
                loaded.warnings.append(ConfigWarning(name, warning))
    return driver_name, path, text
