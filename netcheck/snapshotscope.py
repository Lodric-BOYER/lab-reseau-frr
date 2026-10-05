"""Couverture et fraîcheur d'un snapshot lu hors ligne (`check --snapshot`, `assert --snapshot`, phase C6).

Un audit hors ligne ne vaut que pour ce que le snapshot contient. Trois pièges, tous déjà rencontrés :

- un snapshot PARTIEL (`snapshot -d r5`, ou une collecte en échec) audité contre tout l'inventaire donnait un
  résultat sans rien dire des équipements absents ;
- un snapshot d'un équipement INJOIGNABLE (`reachable: false`) est présent mais vide ;
- un snapshot COMPLET mais PÉRIMÉ (pris avant que la configuration ne change) est un faux « tout va bien ».

Ce module est pur (aucune entrée-sortie) : il compare ce que dit `meta.json` (date, version de netcheck, et
depuis la v0.4 `scope` = {inventory, requested}) à l'inventaire courant et aux équipements lus.

Règles :
- le périmètre est TOUJOURS affiché (équipements couverts, part de l'inventaire), avec la date et la
  version de netcheck du snapshot ;
- `requested` (un `-d` volontaire) est une information, sans effet sur le code ;
- un équipement de l'inventaire absent du snapshot sans avoir été demandé, ou présent mais injoignable :
  ATTENTION ;
- un snapshot sans `scope` (pris avant la v0.4) : « périmètre inconnu », ATTENTION s'il manque quelque
  chose de l'inventaire courant, simple information si tout est présent ;
- un équipement du snapshot absent de l'inventaire : information listée ;
- `--max-age JOURS` (aucune valeur par défaut) : un snapshot plus vieux est ATTENTION, avec son âge ; une date
  illisible ou dans le futur ne prouve pas la fraîcheur : ATTENTION.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from netcheck.model import DeviceState
from netcheck.usage import UsageError

_AGE = re.compile(r"[0-9]+(\.[0-9]+)?")
FUTURE_TOLERANCE = timedelta(hours=1)  # décalage d'horloge toléré avant de dire « date dans le futur »
MAX_LISTED = 12


def now() -> datetime:
    """L'heure courante (UTC). Les tests la remplacent : aucune date du jour dans les tests."""
    return datetime.now(timezone.utc)


def scope_record(inventory_names, requested) -> dict:
    """Ce que `snapshot.save` écrit dans `meta.json` : l'inventaire au moment de la prise (noms triés) et les
    équipements demandés par `-d` (None = tout l'inventaire)."""
    return {"inventory": sorted(inventory_names), "requested": sorted(requested) if requested else None}


def parse_max_age(raw) -> float:
    """`--max-age` : un nombre de jours strictement positif (« 7 », « 0.5 »). Tout le reste = code 3."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not _AGE.fullmatch(text) or float(text) <= 0:
        raise UsageError(
            f"--max-age : un nombre de jours strictement positif est attendu "
            f"(exemples : 7, 0.5), reçu : {raw!r}"
        )
    return float(text)


@dataclass
class Coverage:
    name: str
    timestamp: str | None
    version: str | None
    age_days: float | None
    max_age_days: float | None
    present: list[str]
    reachable: list[str]
    unreachable: list[str]
    inventory: list[str]  # inventaire courant (fichier local ; NetBox jamais contacté)
    recorded_inventory: list[str] | None  # inventaire au moment du snapshot (None : snapshot sans `scope`)
    requested: list[str] | None
    known: bool
    reference: list[str]  # inventaire courant + inventaire enregistré
    covered: list[str]  # équipements du snapshot qui sont dans `reference`
    missing: list[str]
    unreachable_expected: list[str]
    extra: list[str]
    too_old: bool = False
    age_unreadable: bool = False
    in_future: bool = False
    reasons: list[str] = field(default_factory=list)  # chaque raison d'ATTENTION
    notes: list[str] = field(default_factory=list)  # informations, sans effet sur le code

    @property
    def attention(self) -> bool:
        return bool(self.reasons)


def _parse_timestamp(raw) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _names(value) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return sorted(value)
    return None


def _listed(names: list[str]) -> str:
    shown = ", ".join(names[:MAX_LISTED])
    return shown + (f", … ({len(names) - MAX_LISTED} autre(s))" if len(names) > MAX_LISTED else "")


def assess(
    name: str,
    meta: dict | None,
    devices: dict[str, DeviceState],
    inventory_names,
    max_age_days: float | None = None,
    at: datetime | None = None,
) -> Coverage:
    """Compare un snapshot (équipements lus, `meta.json` ou None) à l'inventaire courant."""
    meta = meta if isinstance(meta, dict) else {}
    present = sorted(devices)
    unreachable = sorted(n for n, state in devices.items() if not state.reachable)
    reachable = sorted(set(present) - set(unreachable))
    inventory = sorted(inventory_names)

    scope = meta.get("scope")
    recorded = _names(scope.get("inventory")) if isinstance(scope, dict) else None
    known = recorded is not None and isinstance(scope, dict) and "requested" in scope
    requested = _names(scope.get("requested")) if known else None
    if known and scope.get("requested") is not None and requested is None:
        known, requested = False, None  # `requested` illisible : on ne sait pas, on ne devine pas
    recorded = recorded if known else None

    reference = sorted(set(inventory) | set(recorded or ()))
    expected = set(requested) if requested else set(reference)
    covered = sorted(set(present) & set(reference))
    missing = sorted(expected - set(present))
    unreachable_expected = sorted(set(unreachable) & expected)
    extra = sorted(set(present) - set(reference) - set(requested or ()))

    timestamp = meta.get("timestamp") if isinstance(meta.get("timestamp"), str) else None
    version = meta.get("netcheck_version") if isinstance(meta.get("netcheck_version"), str) else None
    taken = _parse_timestamp(timestamp)
    current = at or now()
    age_days = (current - taken).total_seconds() / 86400 if taken else None

    cov = Coverage(
        name=name,
        timestamp=timestamp,
        version=version,
        age_days=round(age_days, 2) if age_days is not None else None,
        max_age_days=max_age_days,
        present=present,
        reachable=reachable,
        unreachable=unreachable,
        inventory=inventory,
        recorded_inventory=recorded,
        requested=requested,
        known=known,
        reference=reference,
        covered=covered,
        missing=missing,
        unreachable_expected=unreachable_expected,
        extra=extra,
    )

    where = "demandés" if requested else "de l'inventaire"
    gaps = []
    if missing:
        how = (
            "demandés mais absents du snapshot"
            if requested
            else ("de l'inventaire absents du snapshot sans avoir été exclus volontairement (-d)")
        )
        gaps.append(f"équipement(s) {how} : {_listed(missing)}")
    if unreachable_expected:
        listed = _listed(unreachable_expected)
        gaps.append(f"équipement(s) {where} injoignable(s) lors du snapshot : {listed}")
    if known:
        cov.reasons += gaps
        if requested:
            cov.notes.append(f"périmètre demandé (-d) : {_listed(requested)}")
    elif gaps:
        cov.reasons.append("périmètre inconnu (snapshot sans métadonnée de périmètre) et " + "; ".join(gaps))
    else:
        cov.notes.append(
            f"périmètre inconnu (snapshot sans métadonnée de périmètre), "
            f"{len(covered)}/{len(reference)} présents"
        )
    if extra:
        cov.notes.append(f"équipement(s) du snapshot absents de l'inventaire : {_listed(extra)}")

    if max_age_days is not None:
        if taken is None:
            cov.age_unreadable = True
            cov.reasons.append(
                f"date du snapshot illisible : sa fraîcheur n'est pas vérifiable (--max-age {max_age_days:g})"
            )
        elif current - taken < -FUTURE_TOLERANCE:
            cov.in_future = True
            cov.reasons.append(f"date du snapshot dans le futur ({timestamp}) : fraîcheur non vérifiable")
        elif age_days is not None and age_days > max_age_days:
            cov.too_old = True
            cov.reasons.append(
                f"snapshot trop ancien : {age_days:.1f} jour(s) pour une limite de "
                f"{max_age_days:g} (--max-age)"
            )
    return cov


def describe(cov: Coverage) -> list[str]:
    """Les lignes affichées (terminal, HTML) : toujours la date et la version, toujours le périmètre."""
    taken = _parse_timestamp(cov.timestamp)
    when = taken.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if taken else "date inconnue"
    age = f", âge {cov.age_days:.1f} jour(s)" if cov.age_days is not None and cov.age_days >= 0 else ""
    lines = [f"Snapshot '{cov.name}' : pris le {when} avec netcheck {cov.version or 'version inconnue'}{age}"]
    share = f"{len(cov.covered)}/{len(cov.reference)} de l'inventaire"
    lines.append(f"périmètre du snapshot : {_listed(cov.covered) or 'aucun équipement'} ({share})")
    lines += [f"information : {note}" for note in cov.notes]
    lines += [f"ATTENTION : {reason}" for reason in cov.reasons]
    return lines


def as_dict(cov: Coverage) -> dict:
    """La clé `snapshot_scope` des rapports JSON (aucune valeur secrète : des noms, des dates)."""
    return {
        "snapshot": cov.name,
        "timestamp": cov.timestamp,
        "netcheck_version": cov.version,
        "age_days": cov.age_days,
        "max_age_days": cov.max_age_days,
        "devices": cov.present,
        "reachable": cov.reachable,
        "unreachable": cov.unreachable,
        "inventory": cov.inventory,
        "recorded_inventory": cov.recorded_inventory,
        "requested": cov.requested,
        "scope_known": cov.known,
        "coverage": f"{len(cov.covered)}/{len(cov.reference)}",
        "missing": cov.missing,
        "unreachable_expected": cov.unreachable_expected,
        "extra": cov.extra,
        "too_old": cov.too_old,
        "age_unreadable": cov.age_unreadable,
        "in_future": cov.in_future,
        "attention": cov.attention,
        "reasons": cov.reasons,
        "notes": cov.notes,
    }
