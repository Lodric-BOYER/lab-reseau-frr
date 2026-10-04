"""Dérogations : un défaut connu, documenté et daté, qui ne rend pas l'audit rouge (SPEC_v4, Phase B3).

Une dérogation dit « cette violation précise est connue, voici pourquoi, qui l'a validée et jusqu'à quand
». Elle ne retire jamais une règle : la violation reste affichée, avec le statut DÉROGATION, sa
justification et sa date d'expiration, comptée à part dans la synthèse, sans effet sur le code retour.

Format (YAML chargé par `yaml.safe_load` exclusivement, validé en entier au chargement ; code retour 3
sinon) :

    version: 1
    derogations:
      - id: DER-2026-001               # unique
        rule: ospf6-authentification   # identifiant exact d'une règle des fichiers chargés
        targets:                       # paires (équipement, objet), correspondance EXACTE, sans regex
          - {device: r4, object: eth2}
          - {device: r5, object: eth1}
        justification: "..."           # obligatoire
        validated_by: "..."            # obligatoire, texte libre (non vérifiable : voir ci-dessous)
        validated_on: 2026-10-04       # date ISO, pas dans le futur
        expires: 2027-01-04            # obligatoire, date ISO, au plus 365 jours après validated_on
        references: ["https://..."]    # facultatif

Correspondance : une violation est couverte quand sa règle, son équipement et son OBJET (`Violation.subject` :
le nom de l'interface, l'IP du voisin...) sont ceux d'une paire. Une violation sans objet (`subject` à
None) ne peut pas être couverte. Le nom d'un objet diffère selon le constructeur (eth2, Ethernet2,
ethernet-1/1.0) : un fichier de dérogations par lab, avec les bonnes paires.

Refus au chargement : règle inconnue, règle de gravité « critique » (jamais dérogeable), expiration absente
ou à plus de 365 jours, validation dans le futur, paire en double (règle, équipement, objet) dans le
fichier, clé inconnue, champ vide. Un doublon d'`id` est refusé aussi.

Horloge : le moteur reçoit « aujourd'hui » EN PARAMÈTRE (`today`) et n'appelle jamais l'horloge : les tests
utilisent une date fixe, et une dérogation qui expire ne rend jamais la CI rouge à cause du calendrier. Une
dérogation EXPIRÉE ne couvre plus rien : la violation redevient active et le dit (« dérogation expirée le… »).
Une dérogation qui expire dans moins de 30 jours est signalée en information (sans effet sur le code), pour
que son renouvellement soit un acte conscient. Une dérogation ORPHELINE (aucune violation réelle sur une de
ses paires, sur un équipement audité) est une information aussi.

`validated_by` est du texte libre : netcheck ne peut pas prouver qui a validé quoi. Une signature du
fichier est prévue en phase J. Chaque rapport indique le chemin et l'empreinte SHA-256 du fichier utilisé.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from netcheck.ruletypes import Rule, Violation

SUPPORTED_VERSION = 1
MAX_VALIDITY_DAYS = 365
EXPIRY_WARNING_DAYS = 30
_KEYS = {"id", "rule", "targets", "justification", "validated_by", "validated_on", "expires", "references"}
_REQUIRED = {"id", "rule", "targets", "justification", "validated_by", "validated_on", "expires"}

# Types de note, dans les rapports
NOTE_ORPHAN = "orpheline"
NOTE_EXPIRED = "expirée"
NOTE_EXPIRING = "expire bientôt"


@dataclass(frozen=True)
class Derogation:
    id: str
    rule: str
    targets: tuple[tuple[str, str], ...]     # (équipement, objet)
    justification: str
    validated_by: str
    validated_on: date
    expires: date
    references: tuple[str, ...] = ()

    def is_expired(self, today: date) -> bool:
        return today > self.expires


@dataclass(frozen=True)
class DerogationSet:
    derogations: tuple[Derogation, ...]
    path: str
    sha256: str


@dataclass(frozen=True)
class Derogated:
    """Une violation connue et couverte : elle reste dans le rapport, avec son statut DÉROGATION."""
    violation: Violation
    derogation: Derogation


@dataclass(frozen=True)
class DerogationNote:
    kind: str           # NOTE_ORPHAN | NOTE_EXPIRED | NOTE_EXPIRING
    derogation: str     # identifiant
    text: str


@dataclass
class DerogationOutcome:
    """Ce que l'application d'un fichier de dérogations a produit sur un audit."""
    active: list[Violation] = field(default_factory=list)       # violations restées actives
    derogated: list[Derogated] = field(default_factory=list)
    notes: list[DerogationNote] = field(default_factory=list)
    reactivated: list[Derogated] = field(default_factory=list)  # actives, dont la dérogation a expiré


# ------------------------------------------------------------------------------------------
# Chargement et validation
# ------------------------------------------------------------------------------------------

def _as_date(value: Any, label: str, path: Path) -> date:
    """Une date ISO `AAAA-MM-JJ` (YAML la lit comme une date) : ni une heure, ni un autre format."""
    if isinstance(value, datetime):
        raise ValueError(f"{path} : {label} : une date (AAAA-MM-JJ) est attendue, pas une date et heure")
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise ValueError(f"{path} : {label} : date ISO AAAA-MM-JJ attendue (reçu : {value!r})")


def _text(raw: dict, key: str, label: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} : {label} : « {key} » doit être un texte non vide")
    return value.strip()


def load(path: str | Path, rules: list[Rule], today: date) -> DerogationSet:
    """Charge et valide un fichier de dérogations. `today` est la date du jour, passée par l'appelant."""
    path = Path(path)
    try:
        content = path.read_bytes()
    except OSError as e:
        raise ValueError(f"{path} : fichier de dérogations illisible : {e.strerror or e}") from e
    sha256 = hashlib.sha256(content).hexdigest()
    try:
        data = yaml.safe_load(content.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise ValueError(f"{path} : fichier YAML invalide ou refusé : {e}") from e

    if not isinstance(data, dict) or set(data) - {"version", "derogations"}:
        raise ValueError(f"{path} : attendu un objet avec les seules clés « version » et « derogations »")
    if data.get("version") != SUPPORTED_VERSION:
        raise ValueError(f"{path} : « version » doit valoir {SUPPORTED_VERSION} "
                         f"(reçu : {data.get('version')!r})")
    raw_list = data.get("derogations")
    if not isinstance(raw_list, list):
        raise ValueError(f"{path} : « derogations » doit être une liste")

    severities = {r.id: r.severity for r in rules}
    seen_ids: set[str] = set()
    seen_targets: dict[tuple[str, str, str], str] = {}
    derogations = []
    for index, raw in enumerate(raw_list):
        label = raw.get("id", f"dérogation #{index}") if isinstance(raw, dict) else f"dérogation #{index}"
        if not isinstance(raw, dict):
            raise ValueError(f"{path} : {label} : une dérogation doit être un objet YAML (clé: valeur)")
        missing = _REQUIRED - set(raw)
        if missing:
            raise ValueError(f"{path} : {label} : champ(s) obligatoire(s) manquant(s) : {sorted(missing)}"
                             + (" (l'expiration est obligatoire)" if "expires" in missing else ""))
        unknown = set(raw) - _KEYS
        if unknown:
            raise ValueError(f"{path} : {label} : clé(s) inconnue(s) : {sorted(unknown)}")
        ident = _text(raw, "id", label, path)
        if ident in seen_ids:
            raise ValueError(f"{path} : id de dérogation en double : '{ident}'")
        seen_ids.add(ident)

        rule = _text(raw, "rule", label, path)
        if rule not in severities:
            raise ValueError(f"{path} : {label} : règle inconnue '{rule}' (aucune règle de ce nom dans les "
                             f"fichiers de règles chargés)")
        if severities[rule] == "critique":
            raise ValueError(f"{path} : {label} : la règle '{rule}' est de gravité « critique » : une règle "
                             f"critique ne peut jamais faire l'objet d'une dérogation")

        raw_targets = raw["targets"]
        if not isinstance(raw_targets, list) or not raw_targets:
            raise ValueError(f"{path} : {label} : « targets » doit être une liste non vide de "
                             f"{{device, object}}")
        targets = []
        for target in raw_targets:
            if not isinstance(target, dict) or set(target) != {"device", "object"}:
                raise ValueError(f"{path} : {label} : chaque cible doit être exactement "
                                 f"{{device: ..., object: ...}} (reçu : {target!r})")
            for key in ("device", "object"):
                if not isinstance(target[key], str) or not target[key].strip():
                    raise ValueError(f"{path} : {label} : « {key} » d'une cible doit être un texte non vide "
                                     f"(reçu : {target[key]!r})")
            pair = (target["device"], target["object"])
            key3 = (rule, *pair)
            if key3 in seen_targets:
                raise ValueError(f"{path} : {label} : la cible (règle {rule}, équipement {pair[0]}, objet "
                                 f"{pair[1]}) est déjà couverte par la dérogation {seen_targets[key3]}")
            seen_targets[key3] = ident
            targets.append(pair)

        validated_on = _as_date(raw["validated_on"], f"{label} : validated_on", path)
        expires = _as_date(raw["expires"], f"{label} : expires", path)
        if validated_on > today:
            raise ValueError(f"{path} : {label} : validated_on ({validated_on}) est dans le futur "
                             f"(aujourd'hui : {today})")
        if expires < validated_on:
            raise ValueError(f"{path} : {label} : expires ({expires}) précède validated_on ({validated_on})")
        if expires - validated_on > timedelta(days=MAX_VALIDITY_DAYS):
            raise ValueError(f"{path} : {label} : une dérogation dure au plus {MAX_VALIDITY_DAYS} jours "
                             f"(validated_on {validated_on}, expires {expires})")

        references = raw.get("references", [])
        if not isinstance(references, list) or not all(isinstance(r, str) and r.strip() for r in references):
            raise ValueError(f"{path} : {label} : « references » doit être une liste de textes non vides")

        derogations.append(Derogation(
            id=ident, rule=rule, targets=tuple(targets),
            justification=_text(raw, "justification", label, path),
            validated_by=_text(raw, "validated_by", label, path), validated_on=validated_on, expires=expires,
            references=tuple(r.strip() for r in references)))
    return DerogationSet(tuple(derogations), str(path), sha256)


# ------------------------------------------------------------------------------------------
# Application à un audit
# ------------------------------------------------------------------------------------------

def apply(violations: list[Violation], dset: DerogationSet, today: date,
          audited_devices: set[str]) -> DerogationOutcome:
    """Sépare les violations couvertes (DÉROGATION) de celles qui restent actives, et produit les notes
    (orpheline, expirée, expire bientôt). Une dérogation expirée ne couvre rien. Une cible dont l'équipement
    n'est pas dans cet audit n'est pas jugée (on ne peut pas dire qu'elle ne couvre rien)."""
    by_target = {(d.rule, device, obj): d for d in dset.derogations for device, obj in d.targets}
    outcome = DerogationOutcome()
    matched: set[tuple[str, str, str]] = set()
    expiring_reported: set[str] = set()
    expired_reported: set[str] = set()
    subjectless: dict[tuple[str, str], list[Violation]] = {}

    for v in violations:
        derogation = by_target.get((v.rule.id, v.device, v.subject)) if v.subject is not None else None
        if v.subject is None:
            subjectless.setdefault((v.rule.id, v.device), []).append(v)
        if derogation is None:
            outcome.active.append(v)
            continue
        matched.add((v.rule.id, v.device, v.subject))
        if derogation.is_expired(today):
            outcome.active.append(v)
            outcome.reactivated.append(Derogated(v, derogation))
            if derogation.id not in expired_reported:
                expired_reported.add(derogation.id)
                outcome.notes.append(DerogationNote(NOTE_EXPIRED, derogation.id,
                    f"dérogation {derogation.id} expirée le {derogation.expires} : les violations de la "
                    f"règle {derogation.rule} qu'elle couvrait sont de nouveau actives"))
            continue
        outcome.derogated.append(Derogated(v, derogation))
        days = (derogation.expires - today).days
        if days < EXPIRY_WARNING_DAYS and derogation.id not in expiring_reported:
            expiring_reported.add(derogation.id)
            outcome.notes.append(DerogationNote(NOTE_EXPIRING, derogation.id,
                f"dérogation {derogation.id} : expire dans {days} jour(s) (le {derogation.expires}), "
                f"moins de {EXPIRY_WARNING_DAYS} jours : à renouveler ou à retirer"))

    for d in dset.derogations:
        for device, obj in d.targets:
            if (d.rule, device, obj) in matched or device not in audited_devices:
                continue
            reason = (f"dérogation {d.id} : aucune violation réelle de la règle {d.rule} sur {device} pour "
                      f"l'objet « {obj} »")
            if (d.rule, device) in subjectless:
                reason += (" ; la violation de cette règle sur cet équipement n'a pas d'objet identifiable : "
                           "une dérogation ne peut pas la couvrir")
            outcome.notes.append(DerogationNote(NOTE_ORPHAN, d.id, reason))
    return outcome
