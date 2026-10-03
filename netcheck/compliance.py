"""Moteur de conformité : charge des règles YAML et les applique aux équipements (§5.4).

Depuis la Phase A de la v4, ce module est le MOTEUR : chargement et validation des règles, filtrage
par `drivers:`, résolution de l'évaluateur d'un kind chez le driver de l'équipement, trois états
« non applicable », avertissements d'analyse de la configuration, verdict. La syntaxe d'un
constructeur vit dans son driver (`drivers/<nom>_rules.py`, voir `Driver.CONFIG_CHECKS`). Restent ici
les trois kinds neutres : `line_present` et `line_absent` (l'expression régulière est dans la règle
YAML, pas dans le code) et `interface_description_required` (lit le modèle, jamais le texte).

Format d'une règle — voir aussi le commentaire en tête de rules/default.yml :
  id: identifiant court et unique
  description: phrase humaine
  severity: critique | haute | moyenne | basse
  applies_to: "all" ou une liste de noms d'équipements
  kind: un type de règle (voir KNOWN_KINDS : les kinds neutres et ceux des drivers)
  ...  paramètres propres au kind

Sécurité : les fichiers de règles sont chargés avec `yaml.safe_load`, jamais `yaml.load`. Un
fichier de règles n'est pas un canal de confiance (il peut venir d'une revue de code, d'un
partage réseau...) : `yaml.load` avec le loader par défaut peut instancier n'importe quel
objet Python via des tags comme `!!python/object/apply:os.system`, ce qui équivaudrait à de
l'exécution de code arbitraire au chargement d'un simple fichier de config. `safe_load` ne
connaît que les types YAML de base et refuse ces tags.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from netcheck import management
from netcheck.confparse import ParsedConfig
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import (
    CAUSE_DRIVER,
    CAUSE_NOT_IMPLEMENTED,
    Check,
    ConfigWarning,
    NotApplicable,
    Rule,
    Violation,
)

KNOWN_SEVERITIES = {"critique", "haute", "moyenne", "basse"}
KNOWN_DRIVERS = set(DRIVER_REGISTRY)  # Phase D2 : validation du champ optionnel "drivers"
_SEVERITY_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "basse": 1}
REQUIRED_FIELDS = {"id", "description", "severity", "applies_to", "kind"}


# ------------------------------------------------------------------------------------------
# Résolution d'un kind : kinds neutres du moteur, sinon évaluateurs du driver de l'équipement
# ------------------------------------------------------------------------------------------

def resolve_check(kind: str, driver_name: str) -> Check | None:
    """L'évaluateur de ce kind pour ce driver, ou None si le driver ne l'implémente pas."""
    if kind in _UNIVERSAL:
        return _UNIVERSAL[kind]
    driver_cls = DRIVER_REGISTRY.get(driver_name)
    if driver_cls is not None and kind in driver_cls.CONFIG_CHECKS:
        return driver_cls.CONFIG_CHECKS[kind]
    return None


def known_kinds() -> set[str]:
    kinds = set(_UNIVERSAL)
    for driver_cls in DRIVER_REGISTRY.values():
        kinds |= set(driver_cls.CONFIG_CHECKS)
    return kinds


def implementers(kind: str) -> list[str]:
    """Les drivers qui savent évaluer ce kind."""
    return sorted(name for name in DRIVER_REGISTRY if resolve_check(kind, name) is not None)


@dataclass
class ComplianceResult:
    """Ce que produit un audit : violations, règles non applicables, et avertissements d'analyse."""
    violations: list[Violation] = field(default_factory=list)
    not_applicable: list[NotApplicable] = field(default_factory=list)
    config_warnings: list[ConfigWarning] = field(default_factory=list)

    @property
    def unread_lines(self) -> list[ConfigWarning]:
        """Lignes qui empêchent de conclure « conforme » : NON lues, ou à structure incertaine."""
        return [w for w in self.config_warnings if w.blocks_verdict]

    @property
    def notes(self) -> list[ConfigWarning]:
        """Lignes lues mais ambiguës : information, sans effet sur le verdict."""
        return [w for w in self.config_warnings if not w.blocks_verdict]


# ------------------------------------------------------------------------------------------
# Chargement et validation des règles
# ------------------------------------------------------------------------------------------

def load_rules(path: str | Path) -> list[Rule]:
    """Charge et valide rules/default.yml (ou un autre fichier de règles)."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"{path} : fichier YAML invalide ou refusé : {e}") from e

    if not data:
        return []
    raw_rules = data.get("rules") if isinstance(data, dict) else data
    if raw_rules is None:
        raise ValueError(f"{path} : clé 'rules' absente")
    if not isinstance(raw_rules, list):
        raise ValueError(f"{path} : 'rules' doit être une liste")

    rules = [_validate_rule(raw, index=i, path=path) for i, raw in enumerate(raw_rules)]
    _check_unique_ids(rules, path)
    return rules


def _validate_rule(raw: Any, index: int, path: Path) -> Rule:
    label = raw.get("id", f"règle #{index}") if isinstance(raw, dict) else f"règle #{index}"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} : {label} : une règle doit être un objet YAML (clé: valeur)")

    missing = REQUIRED_FIELDS - set(raw)
    if missing:
        raise ValueError(f"{path} : {label} : champ(s) obligatoire(s) manquant(s) : {sorted(missing)}")

    if raw["severity"] not in KNOWN_SEVERITIES:
        raise ValueError(
            f"{path} : {label} : severity '{raw['severity']}' inconnue "
            f"(attendu : {sorted(KNOWN_SEVERITIES)})"
        )
    if raw["kind"] not in known_kinds():
        raise ValueError(
            f"{path} : {label} : kind '{raw['kind']}' inconnu (attendu : {sorted(known_kinds())})"
        )

    applies_to = raw["applies_to"]
    if applies_to != "all" and not isinstance(applies_to, list):
        raise ValueError(f"{path} : {label} : applies_to doit être 'all' ou une liste d'équipements")

    drivers = raw.get("drivers")  # optionnel (Phase D2) : absent = tous les drivers
    if drivers is not None:
        if not isinstance(drivers, list) or not drivers:
            raise ValueError(f"{path} : {label} : drivers doit être une liste non vide de noms de driver")
        # Lu à l'appel : un driver enregistré après l'import compte.
        unknown = set(drivers) - set(DRIVER_REGISTRY)
        if unknown:
            raise ValueError(
                f"{path} : {label} : driver(s) inconnu(s) dans 'drivers' : {sorted(unknown)} "
                f"(disponibles : {sorted(DRIVER_REGISTRY)})"
            )
        # Phase A (v4) : une règle qui cite un driver incapable d'évaluer son kind serait une règle
        # qui ne vérifie rien sur cet équipement : refusée au chargement, jamais « conforme ».
        blind = [d for d in drivers if resolve_check(raw["kind"], d) is None]
        if blind:
            raise ValueError(
                f"{path} : {label} : le kind '{raw['kind']}' n'est pas implémenté par le(s) driver(s) "
                f"{sorted(blind)} cités dans 'drivers' (drivers qui l'implémentent : "
                f"{implementers(raw['kind'])})"
            )

    references = raw.get("references")  # optionnel (Phase A, C14) : absent = aucune référence
    if references is not None:
        if not isinstance(references, list) or not references:
            raise ValueError(f"{path} : {label} : references doit être une liste non vide de {{title, url}}")
        for entry in references:
            if not isinstance(entry, dict) or set(entry) != {"title", "url"}:
                raise ValueError(
                    f"{path} : {label} : chaque référence doit être un objet {{title: ..., url: ...}} "
                    f"exactement (reçu : {entry!r})"
                )
            if not entry["title"] or not entry["url"]:
                raise ValueError(f"{path} : {label} : title et url d'une référence ne peuvent pas être vides")

    category = raw.get("category")  # optionnel : absent = pas de regroupement HTML
    if category is not None and not isinstance(category, str):
        raise ValueError(f"{path} : {label} : category doit être une chaîne")

    meta_fields = REQUIRED_FIELDS | {"drivers", "references", "category"}
    params = {k: v for k, v in raw.items() if k not in meta_fields}
    return Rule(id=raw["id"], description=raw["description"], severity=raw["severity"],
                applies_to=applies_to, kind=raw["kind"], drivers=drivers,
                references=references, category=category, params=params)


def _check_unique_ids(rules: list[Rule], path: Path) -> None:
    seen = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"{path} : id de règle en double : '{r.id}'")
        seen.add(r.id)


# ------------------------------------------------------------------------------------------
# Évaluation
# ------------------------------------------------------------------------------------------

def parse_device_config(state: DeviceState) -> ParsedConfig | None:
    """La configuration de l'équipement analysée par SON driver, ou None si ce driver n'analyse
    pas la configuration (ou n'est pas enregistré)."""
    driver_cls = DRIVER_REGISTRY.get(state.driver)
    return driver_cls().parse_config(state.running_config) if driver_cls is not None else None


def evaluate_config(
    rules: list[Rule],
    devices: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
) -> ComplianceResult:
    """Applique chaque règle à chaque équipement concerné (rule.applies_to).

    Trois états « non applicable », jamais conformes, jamais comptés dans le verdict : la règle ne
    liste pas le driver de l'équipement (`drivers:`, cause « driver »), ou le driver ne sait pas
    évaluer son kind (cause « not_implemented » : un trou de couverture, à ne pas confondre avec une
    règle hors sujet). La configuration de chaque équipement audité est analysée une fois ; toute
    ligne douteuse devient un `ConfigWarning` (voir `verdict()` pour son effet)."""
    mgmt = set(management_interfaces or ())
    result = ComplianceResult()
    parsed: dict[str, ParsedConfig | None] = {}

    def config_of(name: str, state: DeviceState) -> ParsedConfig | None:
        if name not in parsed:
            parsed[name] = parse_device_config(state)
        return parsed[name]

    for rule in rules:
        for name, state in devices.items():
            if not rule.applies(name) or not state.reachable:
                continue
            if rule.drivers is not None and state.driver not in rule.drivers:
                result.not_applicable.append(NotApplicable(rule, name,
                    f"driver '{state.driver}' non couvert par cette règle (drivers: {rule.drivers})",
                    CAUSE_DRIVER))
                continue
            check = resolve_check(rule.kind, state.driver)
            if check is None:
                result.not_applicable.append(NotApplicable(rule, name,
                    f"non implémenté par le driver {state.driver}", CAUSE_NOT_IMPLEMENTED))
                continue
            result.violations += check.fn(rule, management.filtered(state, mgmt), config_of(name, state))

    for name, state in devices.items():
        if state.reachable and any(rule.applies(name) for rule in rules):
            config = config_of(name, state)
            if config is not None:
                result.config_warnings += [ConfigWarning(name, w) for w in config.warnings]
    return result


def evaluate(
    rules: list[Rule],
    devices: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
) -> tuple[list[Violation], list[NotApplicable]]:
    """Forme historique de `evaluate_config` : (violations, non_applicables). Elle ne rend PAS les
    avertissements d'analyse : un appelant qui produit un verdict doit utiliser `evaluate_config`."""
    result = evaluate_config(rules, devices, management_interfaces)
    return result.violations, result.not_applicable


def check_one(rule: Rule, device: DeviceState) -> list[Violation]:
    """Applique UNE règle à UN équipement par le chemin de `evaluate_config` (évaluateur résolu d'après
    `device.driver`, configuration analysée par ce driver), sans filtrage par `applies_to` ni
    `drivers`. Lève ValueError si le driver n'implémente pas le kind (jamais « aucune violation »)."""
    check = resolve_check(rule.kind, device.driver)
    if check is None:
        raise ValueError(f"kind '{rule.kind}' non implémenté par le driver '{device.driver}'")
    return check.fn(rule, device, parse_device_config(device))


STATUS_COMPLIANT = "CONFORME"
STATUS_NON_COMPLIANT = "NON CONFORME"
STATUS_INCOMPLETE = "ANALYSE INCOMPLÈTE"


def status_label(violations: list[Violation], config_warnings: list[ConfigWarning] | tuple = ()) -> str:
    """Le libellé du verdict. NON CONFORME est réservé aux violations RÉELLES : une ligne de
    configuration non lue ne prouve aucune violation, elle dit seulement que l'audit n'a pas tout lu
    (ANALYSE INCOMPLÈTE). Avec les deux, c'est la violation prouvée qui s'affiche."""
    if violations:
        return STATUS_NON_COMPLIANT
    if any(w.blocks_verdict for w in config_warnings):
        return STATUS_INCOMPLETE
    return STATUS_COMPLIANT


def verdict(
    violations: list[Violation], config_warnings: list[ConfigWarning] | tuple = (),
) -> tuple[bool, int]:
    """Codes retour (§5.4) : 0 conforme, 1 moyenne/basse seulement, 2 critique/haute.

    Une ligne de configuration NON lue (ou à structure incertaine) donne au minimum le code 1, même
    si toutes les règles sont satisfaites : un audit ne dit jamais « conforme » sur une configuration
    qu'il n'a pas entièrement lue (le libellé est alors ANALYSE INCOMPLÈTE, voir `status_label`, pas
    NON CONFORME).
    Le code est celui de la plus grave des deux situations. Une ligne lue mais ambiguë
    (`kept=True`) n'a aucun effet sur le code."""
    unread = any(w.blocks_verdict for w in config_warnings)
    if not violations:
        return (not unread), (1 if unread else 0)
    if any(v.rule.severity in ("critique", "haute") for v in violations):
        return False, 2
    return False, 1


# ------------------------------------------------------------------------------------------
# Kinds neutres : lisent une expression régulière de la règle, ou le modèle
# ------------------------------------------------------------------------------------------

def _check_line_present(rule: Rule, device: DeviceState) -> list[Violation]:
    pattern = rule.params.get("pattern")
    if not pattern:
        raise ValueError(f"règle '{rule.id}' (line_present) : paramètre 'pattern' manquant")
    if re.search(pattern, device.running_config, re.MULTILINE):
        return []
    return [Violation(rule, device.name, f"aucune ligne ne correspond à /{pattern}/")]


def _check_line_absent(rule: Rule, device: DeviceState) -> list[Violation]:
    pattern = rule.params.get("pattern")
    if not pattern:
        raise ValueError(f"règle '{rule.id}' (line_absent) : paramètre 'pattern' manquant")
    match = re.search(pattern, device.running_config, re.MULTILINE)
    if not match:
        return []
    # Rapporte la ligne entière contenant le motif, pas seulement le texte capturé par la
    # regex (ex. le motif ne capture parfois que "password", pas "password secret123").
    text = device.running_config
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    line = text[line_start: line_end if line_end != -1 else len(text)].strip()
    return [Violation(rule, device.name, f"ligne interdite trouvée : '{line}'")]


def _is_loopback(iface) -> bool:
    """Utilise Interface.is_loopback quand le driver le connaît (v2, O3) ; sinon (None --
    driver qui n'expose pas l'info, ou snapshot pris avant l'ajout du champ), retombe sur
    l'heuristique de nom : exactement "lo", ou tout nom commençant par "loopback"."""
    if iface.is_loopback is not None:
        return iface.is_loopback
    name = iface.name.lower()
    return name == "lo" or name.startswith("loopback")


def _check_interface_description_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """« Toute interface avec une adresse IP, hors loopback, doit avoir une description » (§5.4).

    `rule.params["exclude"]` retire en plus des interfaces explicitement listées,
    indépendamment des interfaces de management (déjà retirées de `device.interfaces` en
    amont par `evaluate()`).
    """
    exclude = rule.params.get("exclude", [])
    violations = []
    for iface in device.interfaces:
        if not iface.addresses:
            continue
        if _is_loopback(iface):
            continue
        if iface.name in exclude:
            continue
        if not iface.description:
            violations.append(Violation(rule, device.name,
                f"interface {iface.name} ({', '.join(iface.addresses)}) sans description"))
    return violations


# ------------------------------------------------------------------------------------------
# Kinds neutres du moteur et table de résolution
# ------------------------------------------------------------------------------------------

def _two_args(fn, needs=("config",)) -> Check:
    """Adapte un évaluateur (règle, équipement) au contrat des drivers (règle, équipement, config)."""
    return Check(lambda rule, device, config: fn(rule, device), frozenset(needs))


_UNIVERSAL: dict[str, Check] = {
    "line_present": _two_args(_check_line_present),
    "line_absent": _two_args(_check_line_absent),
    # Lit le MODÈLE (adresses, description, is_loopback), jamais le texte de la configuration.
    "interface_description_required": _two_args(_check_interface_description_required, ("interfaces",)),
}

KNOWN_KINDS = known_kinds()
