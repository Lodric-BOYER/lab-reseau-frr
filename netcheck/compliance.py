"""Moteur de conformité : charge des règles YAML et les applique aux équipements (§5.4).

Format d'une règle — voir aussi le commentaire en tête de rules/default.yml :
  id: identifiant court et unique
  description: phrase humaine
  severity: critique | haute | moyenne | basse
  applies_to: "all" ou une liste de noms d'équipements
  kind: un des 6 types ci-dessous
  ...  paramètres propres au kind (voir chaque évaluateur _check_*)

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
from netcheck.model import DeviceState

KNOWN_KINDS = {
    "line_present",
    "line_absent",
    "bgp_neighbor_inbound_policy",
    "bgp_neighbor_outbound_policy",
    "ospf_passive_on_interfaces",
    "interface_description_required",
}
KNOWN_SEVERITIES = {"critique", "haute", "moyenne", "basse"}
_SEVERITY_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "basse": 1}
REQUIRED_FIELDS = {"id", "description", "severity", "applies_to", "kind"}


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    applies_to: list[str] | str  # "all" ou liste explicite de noms d'équipements
    kind: str
    params: dict[str, Any] = field(default_factory=dict)

    def applies(self, device_name: str) -> bool:
        return self.applies_to == "all" or device_name in self.applies_to


@dataclass
class Violation:
    rule: Rule
    device: str
    detail: str


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
    if raw["kind"] not in KNOWN_KINDS:
        raise ValueError(
            f"{path} : {label} : kind '{raw['kind']}' inconnu (attendu : {sorted(KNOWN_KINDS)})"
        )

    applies_to = raw["applies_to"]
    if applies_to != "all" and not isinstance(applies_to, list):
        raise ValueError(f"{path} : {label} : applies_to doit être 'all' ou une liste d'équipements")

    params = {k: v for k, v in raw.items() if k not in REQUIRED_FIELDS}
    return Rule(id=raw["id"], description=raw["description"], severity=raw["severity"],
                applies_to=applies_to, kind=raw["kind"], params=params)


def _check_unique_ids(rules: list[Rule], path: Path) -> None:
    seen = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"{path} : id de règle en double : '{r.id}'")
        seen.add(r.id)


# ------------------------------------------------------------------------------------------
# Évaluation
# ------------------------------------------------------------------------------------------

def evaluate(
    rules: list[Rule],
    devices: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
) -> list[Violation]:
    """Applique chaque règle à chaque équipement concerné (rule.applies_to)."""
    mgmt = set(management_interfaces or ())
    violations: list[Violation] = []
    for rule in rules:
        evaluator = _EVALUATORS[rule.kind]
        for name, state in devices.items():
            if not rule.applies(name) or not state.reachable:
                continue
            violations += evaluator(rule, management.filtered(state, mgmt))
    return violations


def verdict(violations: list[Violation]) -> tuple[bool, int]:
    """Codes retour (§5.4) : 0 conforme, 1 moyenne/basse seulement, 2 critique/haute."""
    if not violations:
        return True, 0
    if any(v.rule.severity in ("critique", "haute") for v in violations):
        return False, 2
    return False, 1


# ------------------------------------------------------------------------------------------
# Aides de parsing de la running-config (texte brut, commun à plusieurs évaluateurs)
# ------------------------------------------------------------------------------------------

def _interface_blocks(running_config: str) -> dict[str, str]:
    """{nom_interface: texte_du_bloc} à partir de blocs 'interface <nom> ... exit'."""
    blocks: dict[str, str] = {}
    name = None
    lines: list[str] = []
    for line in running_config.splitlines():
        if line.startswith("interface "):
            name = line[len("interface "):].strip()
            lines = [line]
        elif name is not None:
            lines.append(line)
            if line.strip() == "exit":
                blocks[name] = "\n".join(lines)
                name = None
    return blocks


def _bgp_block(running_config: str) -> tuple[str, str] | None:
    """(AS_local, texte_du_bloc 'router bgp ... exit') ou None si pas de BGP configuré."""
    lines = running_config.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("router bgp ")), None)
    if start is None:
        return None
    local_as = lines[start].split()[2]
    end = start + 1
    while end < len(lines) and lines[end].strip() != "exit":
        end += 1
    return local_as, "\n".join(lines[start:end + 1])


# ------------------------------------------------------------------------------------------
# Un évaluateur par type de règle (kind)
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


def _has_bgp_policy(block: str, neighbor: str, direction: str) -> bool:
    pattern = rf"^\s*neighbor {re.escape(neighbor)} (?:route-map|prefix-list) \S+ {direction}\s*$"
    return re.search(pattern, block, re.MULTILINE) is not None


def _check_bgp_policy(rule: Rule, device: DeviceState, direction: str) -> list[Violation]:
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []  # pas de BGP configuré sur cet équipement : rien à vérifier
    local_as, block = bgp
    neighbors = re.findall(r"^\s*neighbor (\S+) remote-as (\d+)", block, re.MULTILINE)
    violations = []
    for ip, remote_as in neighbors:
        if remote_as == local_as:
            continue  # iBGP : hors périmètre de cette règle (politique eBGP)
        if not _has_bgp_policy(block, ip, direction):
            mot = "entrée" if direction == "in" else "sortie"
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {ip} sans route-map/prefix-list en {mot}"))
    return violations


def _check_bgp_neighbor_inbound_policy(rule: Rule, device: DeviceState) -> list[Violation]:
    return _check_bgp_policy(rule, device, "in")


def _check_bgp_neighbor_outbound_policy(rule: Rule, device: DeviceState) -> list[Violation]:
    return _check_bgp_policy(rule, device, "out")


def _check_ospf_passive_on_interfaces(rule: Rule, device: DeviceState) -> list[Violation]:
    pattern = rule.params.get("pattern")
    if not pattern:
        raise ValueError(f"règle '{rule.id}' (ospf_passive_on_interfaces) : paramètre 'pattern' manquant")
    regex = re.compile(pattern)
    blocks = _interface_blocks(device.running_config)
    violations = []
    for iface in device.interfaces:
        if not iface.description or not regex.search(iface.description):
            continue
        if "ip ospf passive" not in blocks.get(iface.name, ""):
            violations.append(Violation(rule, device.name,
                f"interface {iface.name} (description '{iface.description}') "
                f"n'est pas en ip ospf passive"))
    return violations


def _check_interface_description_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """« Toute interface avec une adresse IP, hors loopback, doit avoir une description » (§5.4).

    Le loopback est reconnu par son nom (pas par un champ dédié du modèle, qui n'en a pas) :
    exactement "lo", ou tout nom commençant par "loopback" (insensible à la casse, pour
    rester valable au-delà du seul driver FRR). `rule.params["exclude"]` retire en plus des
    interfaces explicitement listées, indépendamment des interfaces de management (déjà
    retirées de `device.interfaces` en amont par `evaluate()`).
    """
    exclude = rule.params.get("exclude", [])
    violations = []
    for iface in device.interfaces:
        if not iface.addresses:
            continue
        name = iface.name.lower()
        if name == "lo" or name.startswith("loopback"):
            continue
        if iface.name in exclude:
            continue
        if not iface.description:
            violations.append(Violation(rule, device.name,
                f"interface {iface.name} ({', '.join(iface.addresses)}) sans description"))
    return violations


_EVALUATORS = {
    "line_present": _check_line_present,
    "line_absent": _check_line_absent,
    "bgp_neighbor_inbound_policy": _check_bgp_neighbor_inbound_policy,
    "bgp_neighbor_outbound_policy": _check_bgp_neighbor_outbound_policy,
    "ospf_passive_on_interfaces": _check_ospf_passive_on_interfaces,
    "interface_description_required": _check_interface_description_required,
}
