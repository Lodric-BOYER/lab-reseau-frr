"""Changements attendus (`--expect`, Phase D1, SPEC_v3 §7, objectif O3).

Un fichier d'attentes décrit ce qu'une intervention est CENSÉE changer, pour qu'un constat
prévu ne soit plus une alerte et qu'un changement prévu mais absent en devienne une.

Format (yaml.safe_load, au moins une des deux sections non vide) :

  findings:                       # critères sur les constats de diff
    - id: ...                     # obligatoire, unique
      description: ...            # obligatoire
      device: r1                  # obligatoire : un nom précis (jamais "all", jamais une liste)
      category: next_hop          # obligatoire : une catégorie réelle de diff.FINDING_CATEGORIES
      pattern: "10\\.1\\.23\\.0/30"   # optionnel : regex (re.search) sur le message du constat
      severity: attention         # optionnel : info | attention | critique (défaut : attention)
      count: 8                    # optionnel : nombre EXACT de constats attendus pour ce critère
  after:                          # assertions au format intent de la Phase C, évaluées sur
    - id: ...                     #   l'état APRÈS le changement
      ...

Garde-fous anti-masquage (un critère trop large cacherait un vrai problème) :
  - `device` ET `category` obligatoires ; un motif qui accepte tout est refusé ;
  - `severity` est un PLAFOND : sans lui, un critère ne couvre jamais un constat CRITIQUE ;
  - clés inconnues refusées (une faute de frappe ne devient pas un critère inopérant).

Sécurité : yaml.safe_load exclusivement, comme compliance.py et assertions.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from netcheck import assertions
from netcheck.assertions import Assertion, AssertionResult, Status
from netcheck.diff import FINDING_CATEGORIES, Finding, Severity
from netcheck.model import DeviceState
from netcheck.usage import load_yaml

# Catégories synthétiques produites par apply() -- jamais ciblables par un critère.
CATEGORY_MISSING = "expected_change_missing"
CATEGORY_COUNT = "expected_count_mismatch"
CATEGORY_STATE = "expected_state"

_SEVERITIES = {"info": Severity.INFO, "attention": Severity.ATTENTION, "critique": Severity.CRITIQUE}
_TOP_LEVEL_KEYS = {"findings", "after"}
_REQUIRED_FIELDS = {"id", "description", "device", "category"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"pattern", "severity", "count"}

# Chaînes sondes sans rapport entre elles : un motif qui les accepte TOUTES (ou qui accepte la
# chaîne vide) accepterait n'importe quel message -- c'est un critère qui masque tout.
_PROBES = ("a", "0", "-", "zzz")


def is_too_broad(pattern: str) -> bool:
    """Vrai si la regex accepte la chaîne vide ou toutes les chaînes sondes (ex. .*, .+, ., ^,
    [\\s\\S]*, \\S+). Lève re.error si le motif n'est pas une regex valide."""
    regex = re.compile(pattern)
    if regex.search(""):
        return True
    return all(regex.search(probe) for probe in _PROBES)


@dataclass
class Criterion:
    id: str
    description: str
    device: str
    category: str
    pattern: str | None = None
    severity: Severity = Severity.ATTENTION
    count: int | None = None


@dataclass
class Expectation:
    findings: list[Criterion]
    after: list[Assertion]


# ------------------------------------------------------------------------------------------
# Chargement et validation
# ------------------------------------------------------------------------------------------

def load_expect(path: str | Path) -> Expectation:
    """Charge et valide un fichier --expect. Lève ValueError (message qui nomme le critère
    fautif) -- l'appelant renvoie alors le code 3, AVANT toute action sur le réseau."""
    path = Path(path)
    data = load_yaml(path, "fichier d'attentes")

    if not isinstance(data, dict):
        raise ValueError(f"{path} : un fichier --expect est un objet avec 'findings' et/ou 'after'")
    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(f"{path} : clé(s) inconnue(s) au premier niveau : {sorted(unknown)} "
                         f"(attendu : {sorted(_TOP_LEVEL_KEYS)})")

    raw_findings = data.get("findings") or []
    raw_after = data.get("after") or []
    for name, value in (("findings", raw_findings), ("after", raw_after)):
        if not isinstance(value, list):
            raise ValueError(f"{path} : '{name}' doit être une liste")
    if not raw_findings and not raw_after:
        raise ValueError(f"{path} : au moins une des sections 'findings' ou 'after' doit être non vide")

    criteria = [_validate_criterion(raw, i, path) for i, raw in enumerate(raw_findings)]
    after = assertions.validate_assertions(raw_after, path) if raw_after else []

    seen: set[str] = set()
    for item_id in [c.id for c in criteria] + [a.id for a in after]:
        if item_id in seen:
            raise ValueError(f"{path} : id en double (findings et after confondus) : '{item_id}'")
        seen.add(item_id)
    return Expectation(findings=criteria, after=after)


def _validate_criterion(raw: Any, index: int, path: Path) -> Criterion:
    label = raw.get("id", f"critère #{index}") if isinstance(raw, dict) else f"critère #{index}"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} : {label} : un critère doit être un objet YAML (clé: valeur)")

    missing = _REQUIRED_FIELDS - set(raw)
    if missing:
        raise ValueError(f"{path} : {label} : champ(s) obligatoire(s) manquant(s) : {sorted(missing)}")
    unknown = set(raw) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"{path} : {label} : clé(s) inconnue(s) : {sorted(unknown)} "
                         f"(attendu : {sorted(_ALLOWED_FIELDS)})")

    device = raw["device"]
    if not isinstance(device, str) or not device or device == "all":
        raise ValueError(f"{path} : {label} : device doit être un nom d'équipement précis "
                         f"(ni liste, ni 'all') -- reçu : {device!r}")
    if raw["category"] not in FINDING_CATEGORIES:
        raise ValueError(f"{path} : {label} : category '{raw['category']}' inconnue "
                         f"(attendu : {sorted(FINDING_CATEGORIES)})")

    pattern = raw.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise ValueError(f"{path} : {label} : pattern doit être une chaîne")
        try:
            too_broad = is_too_broad(pattern)
        except re.error as e:
            raise ValueError(f"{path} : {label} : pattern n'est pas une regex valide : {e}") from e
        if too_broad:
            raise ValueError(f"{path} : {label} : pattern '{pattern}' trop large (il accepterait "
                             f"n'importe quel message) -- précise ce que le changement doit produire")

    severity_name = raw.get("severity", "attention")
    if severity_name not in _SEVERITIES:
        raise ValueError(f"{path} : {label} : severity '{severity_name}' inconnue "
                         f"(attendu : {sorted(_SEVERITIES)})")

    count = raw.get("count")
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 1):
        raise ValueError(f"{path} : {label} : count doit être un entier >= 1 (reçu : {count!r})")

    return Criterion(id=raw["id"], description=raw["description"], device=device,
                      category=raw["category"], pattern=pattern,
                      severity=_SEVERITIES[severity_name], count=count)


# ------------------------------------------------------------------------------------------
# Application aux constats d'un diff
# ------------------------------------------------------------------------------------------

def _matches(criterion: Criterion, finding: Finding) -> bool:
    if finding.device != criterion.device or finding.category != criterion.category:
        return False
    if finding.severity > criterion.severity:  # plafond : sans severity: critique, jamais un CRITIQUE
        return False
    return criterion.pattern is None or re.search(criterion.pattern, finding.message) is not None


def apply(
    findings: list[Finding],
    expectation: Expectation,
    devices_after: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
    management_vrfs: set[str] | None = None,
) -> tuple[list[Finding], list[AssertionResult]]:
    """Marque PRÉVUS les constats couverts, ajoute les constats synthétiques (changement
    attendu absent, nombre différent, état attendu non respecté), évalue la section `after`.

    Renvoie (constats, résultats des assertions `after`). Un constat couvert par plusieurs
    critères est attribué au premier (expected_by) mais compté pour chacun."""
    matched_count = {c.id: 0 for c in expectation.findings}
    out: list[Finding] = []
    for f in findings:
        owners = [c for c in expectation.findings if _matches(c, f)]
        for c in owners:
            matched_count[c.id] += 1
        out.append(replace(f, expected_by=owners[0].id) if owners else f)

    for c in expectation.findings:
        observed = matched_count[c.id]
        if observed == 0:
            out.append(Finding(Severity.ATTENTION, CATEGORY_MISSING, c.device,
                               f"changement attendu absent : {c.id} ({c.description})"))
        elif c.count is not None and observed != c.count:
            out.append(Finding(Severity.ATTENTION, CATEGORY_COUNT, c.device,
                               f"nombre de constats différent (attendu {c.count}, observé {observed}) "
                               f": {c.id}"))

    results: list[AssertionResult] = []
    if expectation.after:
        results = assertions.evaluate(expectation.after, devices_after, management_interfaces,
                                       management_vrfs)
        for r in results:
            if r.status == Status.ECHEC:
                out.append(Finding(Severity.CRITIQUE, CATEGORY_STATE, r.assertion.device,
                                   f"état attendu non respecté : {r.assertion.id} -- {r.detail}"))
            elif r.status == Status.NON_EVALUABLE:
                out.append(Finding(Severity.ATTENTION, CATEGORY_STATE, r.assertion.device,
                                   f"état attendu non évaluable : {r.assertion.id} -- {r.detail}"))
    return out, results
