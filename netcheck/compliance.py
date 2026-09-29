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
from netcheck.collector import DRIVER_REGISTRY
from netcheck.model import DeviceState

KNOWN_KINDS = {
    "line_present",
    "line_absent",
    "bgp_neighbor_inbound_policy",
    "bgp_neighbor_outbound_policy",
    "ospf_passive_on_interfaces",
    "interface_description_required",
    "srlinux_interface_mtu_margin",
    "srlinux_ospf_interface_type_point_to_point",
    # -- Phase A (sécurité, O1) --------------------------------------------------------------
    "ospf_authentication_required",
    "bgp_neighbor_password_required",
    "bgp_neighbor_maximum_prefix_required",
    "bgp_neighbor_ttl_security_required",
    "bgp_neighbor_no_default_route_policy",
    "bgp_neighbor_no_own_prefixes_policy",
    "srlinux_ospf_authentication_required",
}
KNOWN_SEVERITIES = {"critique", "haute", "moyenne", "basse"}
KNOWN_DRIVERS = set(DRIVER_REGISTRY)  # Phase D2 : validation du champ optionnel "drivers"
_SEVERITY_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "basse": 1}
REQUIRED_FIELDS = {"id", "description", "severity", "applies_to", "kind"}


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    applies_to: list[str] | str  # "all" ou liste explicite de noms d'équipements
    kind: str
    # None = tous les drivers (Phase D2). Une liste restreint la règle aux équipements dont
    # DeviceState.driver y figure ; les autres deviennent "non applicable" (evaluate()), pas
    # "conformes" et jamais une violation.
    drivers: list[str] | None = None
    # Phase A (sécurité, O1, C14) : références vérifiables (ANSSI, CIS, RFC, doc constructeur).
    # None = aucune référence. Chaque entrée est {"title": str, "url": str} -- un champ vide
    # plutôt qu'inventé si aucune source fiable n'a été trouvée pour la règle (C14).
    references: list[dict[str, str]] | None = None
    # Regroupement du rapport HTML par thème (ex. "acces", "journalisation", "bgp", "ospf").
    # None = pas de catégorie (règles antérieures à la Phase A).
    category: str | None = None
    params: dict[str, Any] = field(default_factory=dict)

    def applies(self, device_name: str) -> bool:
        return self.applies_to == "all" or device_name in self.applies_to


@dataclass
class Violation:
    rule: Rule
    device: str
    detail: str


@dataclass
class NotApplicable:
    """Une règle qui ne concerne pas le driver de cet équipement (Phase D2) : ni conforme, ni
    violation, un troisième état à part entière -- voir evaluate() et verdict()."""
    rule: Rule
    device: str
    reason: str


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

    drivers = raw.get("drivers")  # optionnel (Phase D2) : absent = tous les drivers
    if drivers is not None:
        if not isinstance(drivers, list) or not drivers:
            raise ValueError(f"{path} : {label} : drivers doit être une liste non vide de noms de driver")
        unknown = set(drivers) - KNOWN_DRIVERS
        if unknown:
            raise ValueError(
                f"{path} : {label} : driver(s) inconnu(s) dans 'drivers' : {sorted(unknown)} "
                f"(disponibles : {sorted(KNOWN_DRIVERS)})"
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

def evaluate(
    rules: list[Rule],
    devices: dict[str, DeviceState],
    management_interfaces: set[str] | None = None,
) -> tuple[list[Violation], list[NotApplicable]]:
    """Applique chaque règle à chaque équipement concerné (rule.applies_to).

    Renvoie (violations, non_applicables). Phase D2 : une règle dont `rule.drivers` ne couvre
    pas le driver de l'équipement (DeviceState.driver) ne produit ni conformité ni violation --
    "non applicable" est un troisième état à part entière (jamais "conforme", jamais compté
    dans `verdict()`, qui ne prend que `violations`)."""
    mgmt = set(management_interfaces or ())
    violations: list[Violation] = []
    not_applicable: list[NotApplicable] = []
    for rule in rules:
        evaluator = _EVALUATORS[rule.kind]
        for name, state in devices.items():
            if not rule.applies(name) or not state.reachable:
                continue
            if rule.drivers is not None and state.driver not in rule.drivers:
                not_applicable.append(NotApplicable(rule, name,
                    f"driver '{state.driver}' non couvert par cette règle (drivers: {rule.drivers})"))
                continue
            violations += evaluator(rule, management.filtered(state, mgmt))
    return violations, not_applicable


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
    start = next((i for i, line in enumerate(lines) if line.startswith("router bgp ")), None)
    if start is None:
        return None
    local_as = lines[start].split()[2]
    end = start + 1
    while end < len(lines) and lines[end].strip() != "exit":
        end += 1
    return local_as, "\n".join(lines[start:end + 1])


# ------------------------------------------------------------------------------------------
# Aides de parsing de la running-config SR Linux (accolades imbriquées, Phase D2)
# ------------------------------------------------------------------------------------------

def _srlinux_section(running_config: str, marker: str) -> str:
    """Isole la section qui suit '# --- <marker> ---' jusqu'au marqueur suivant (ou la fin).

    drivers/srlinux.py concatène deux commandes distinctes (config des interfaces, config
    OSPF) séparées par ces marqueurs plutôt que bout à bout : les deux réutilisent la même
    syntaxe de bloc "interface <nom> { ... }" avec un sens différent (interface physique d'un
    côté, sous-interface dans une zone OSPF de l'autre) -- sans cette séparation explicite, un
    évaluateur pourrait confondre les deux. Renvoie "" si le marqueur est absent (ex. un
    running_config FRR, qui n'a jamais ce format) : rien à trouver, pas une erreur.
    """
    start = running_config.find(f"# --- {marker} ---")
    if start == -1:
        return ""
    start = running_config.find("\n", start) + 1
    next_marker = running_config.find("# --- ", start)
    return running_config[start:] if next_marker == -1 else running_config[start:next_marker]


def _srlinux_brace_blocks(text: str, header_prefix: str) -> dict[str, str]:
    """{nom: texte_du_bloc} pour des blocs '<header_prefix><nom> { ... }' à accolades
    imbriquées (syntaxe SR Linux "info from running"). Suit la profondeur d'accolades pour
    capturer le bloc complet, contrairement à une simple recherche ligne à ligne (nécessaire
    ici : une zone OSPF contient elle-même des sous-blocs "interface <nom> { ... }")."""
    blocks: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith(header_prefix) and stripped.endswith("{"):
            name = stripped[len(header_prefix):-1].strip()
            depth = 1
            block_lines = [lines[i]]
            i += 1
            while i < len(lines) and depth > 0:
                block_lines.append(lines[i])
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            blocks[name] = "\n".join(block_lines)
        else:
            i += 1
    return blocks


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


def _check_ospf_authentication_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit porter une authentification message-
    digest (Phase A, O1). Vérifié en direct (FRR 10.2.1) : accepté sans casser l'adjacence
    quand appliqué symétriquement des deux côtés d'un lien -- mais `service password-
    encryption` ne chiffre PAS la clé dans running-config (vérifié en direct également) : elle
    reste en clair dans la config et dans les snapshots, d'où la portée du champ `references`
    de cette règle et le rappel dans le README (snapshots exclus de Git, valeurs de lab)."""
    blocks = _interface_blocks(device.running_config)
    violations = []
    for name, block in blocks.items():
        if "ip ospf area" not in block or "ip ospf passive" in block:
            continue  # pas de l'OSPF actif sur cette interface : pas d'adjacence, rien à protéger
        if "ip ospf authentication message-digest" not in block:
            violations.append(Violation(rule, device.name,
                f"interface {name} : adjacence OSPF active sans authentification "
                f"message-digest"))
    return violations


def _eligible_ebgp_neighbors(device: DeviceState) -> list[str]:
    """IP des voisins eBGP (remote-as différent de l'AS local) de cet équipement, ou liste vide
    s'il n'a pas de BGP configuré -- factorisé pour les règles de sécurité par voisin."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    local_as, block = bgp
    return [ip for ip, remote_as in re.findall(r"^\s*neighbor (\S+) remote-as (\d+)", block, re.MULTILINE)
            if remote_as != local_as]


def _check_bgp_neighbor_password_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """Chaque voisin eBGP doit avoir un mot de passe TCP-MD5 (Phase A, O1). Vérifié en direct :
    accepté par FRR 10.2.1 (kernel WSL2 : CONFIG_TCP_MD5SIG=y). TCP-AO (RFC 5925), plus récent,
    est hors de portée ici : ni le kernel WSL2 (CONFIG_TCP_AO absent) ni bgpd (feature request
    FRRouting#7240, jamais mergée) ne le supportent dans ce lab -- TCP-MD5 est donc la seule
    option réaliste, malgré ses faiblesses cryptographiques connues face à TCP-AO."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    _, block = bgp
    violations = []
    for ip in _eligible_ebgp_neighbors(device):
        if not re.search(rf"^\s*neighbor {re.escape(ip)} password \S+\s*$", block, re.MULTILINE):
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {ip} sans authentification TCP-MD5 (mot de passe)"))
    return violations


def _check_bgp_neighbor_maximum_prefix_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """Chaque voisin eBGP doit avoir une limite `maximum-prefix` (Phase A, O1) : protège contre
    une fuite de routes massive côté voisin. Vérifié en direct : accepté par FRR 10.2.1, mais
    la modification force un reset de la session (FSM repassé par Active quelques secondes,
    NOTIFICATION Cease envoyée) -- un `clear bgp` explicite a été nécessaire pour un retour
    immédiat à Established pendant ce test ; à surveiller en Phase B (test_lab.sh/
    integration.sh doivent rester verts malgré ce reset)."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    _, block = bgp
    violations = []
    for ip in _eligible_ebgp_neighbors(device):
        if not re.search(rf"^\s*neighbor {re.escape(ip)} maximum-prefix \d+\s*$", block, re.MULTILINE):
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {ip} sans limite maximum-prefix"))
    return violations


def _check_bgp_neighbor_ttl_security_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """Chaque voisin eBGP doit avoir le GTSM (`ttl-security hops`, RFC 5082) activé (Phase A,
    O1) : rejette les paquets dont le TTL indique qu'ils viennent de plus loin que le voisin
    direct attendu, sans les coûts cryptographiques d'une authentification. Vérifié en direct :
    accepté par FRR 10.2.1 sur ce lien directement connecté (hops 1) ; même remarque que
    `bgp_neighbor_maximum_prefix_required` sur le reset de session observé au moment du
    changement."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    _, block = bgp
    violations = []
    for ip in _eligible_ebgp_neighbors(device):
        if not re.search(rf"^\s*neighbor {re.escape(ip)} ttl-security hops \d+\s*$", block, re.MULTILINE):
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {ip} sans GTSM (ttl-security hops)"))
    return violations


def _route_map_in_name(block: str, neighbor: str) -> str | None:
    """Nom du route-map appliqué en entrée ('in') à ce voisin, ou None si aucun (dans ce cas,
    la règle ebgp-politique-entrante existante signale déjà le problème -- pas le rôle des
    règles de politique ci-dessous, qui supposent qu'un route-map en entrée existe)."""
    m = re.search(rf"^\s*neighbor {re.escape(neighbor)} route-map (\S+) in\s*$", block, re.MULTILINE)
    return m.group(1) if m else None


def _route_map_prefix_lists(running_config: str, route_map_name: str) -> list[str]:
    """Noms des prefix-lists référencées par 'match ip address prefix-list' dans un route-map
    (toutes ses séquences, pas seulement la première)."""
    names = []
    in_block = False
    for line in running_config.splitlines():
        if line.startswith(f"route-map {route_map_name} "):
            in_block = True
            continue
        if in_block:
            if line.strip() == "exit":
                in_block = False
                continue
            m = re.match(r"\s*match ip address prefix-list (\S+)", line)
            if m:
                names.append(m.group(1))
    return names


def _prefix_list_networks(running_config: str, name: str) -> list[str]:
    """Réseau (sans le 'le'/'ge' éventuel) de chaque entrée 'permit'/'deny' d'une prefix-list."""
    pattern = rf"^ip prefix-list {re.escape(name)} seq \d+ (?:permit|deny) (\S+)"
    return re.findall(pattern, running_config, re.MULTILINE)


def _check_bgp_neighbor_no_default_route_policy(rule: Rule, device: DeviceState) -> list[Violation]:
    """La prefix-list appliquée en entrée à chaque voisin eBGP ne doit autoriser 0.0.0.0/0 sous
    aucune forme (Phase A, O1 -- politique déclarée, pas la table de routage : un voisin qui
    n'annonce pas encore de route par défaut aujourd'hui ne prouve rien sur le filtrage lui-
    même). Toute entrée dont le réseau de base est 0.0.0.0/0 couvre la route par défaut exacte,
    qu'elle porte ou non une clause `le`/`ge` -- 'permit 0.0.0.0/0' et 'permit 0.0.0.0/0 le 32'
    sont donc tous deux détectés par la même vérification sur le réseau de base."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    _, block = bgp
    violations = []
    for ip in _eligible_ebgp_neighbors(device):
        pl_name = _route_map_in_name(block, ip)
        if pl_name is None:
            continue
        for pl in _route_map_prefix_lists(device.running_config, pl_name):
            for network in _prefix_list_networks(device.running_config, pl):
                if network == "0.0.0.0/0":
                    violations.append(Violation(rule, device.name,
                        f"prefix-list '{pl}' (politique d'entrée du voisin eBGP {ip}) "
                        f"autorise 0.0.0.0/0 : route par défaut acceptable depuis l'extérieur"))
    return violations


def _check_bgp_neighbor_no_own_prefixes_policy(rule: Rule, device: DeviceState) -> list[Violation]:
    """La prefix-list appliquée en entrée à chaque voisin eBGP ne doit pas autoriser un préfixe
    que ce routeur annonce lui-même (Phase A, O1 -- politique déclarée) : sans ce filtre, un
    voisin pourrait réannoncer nos propres préfixes, créant une boucle ou un détournement de
    trafic. Vérifié sur la config réelle : r3 annonce 10.1.0.0/16 et 192.168.1.0/24, sa
    PL-EBGP-IN n'autorise que 10.2.0.0/16 et 192.168.2.0/24 -- déjà conforme aujourd'hui."""
    bgp = _bgp_block(device.running_config)
    if bgp is None:
        return []
    local_as, block = bgp
    own_networks = set(re.findall(r"^\s*network (\S+)", block, re.MULTILINE))
    violations = []
    for ip in _eligible_ebgp_neighbors(device):
        pl_name = _route_map_in_name(block, ip)
        if pl_name is None:
            continue
        for pl in _route_map_prefix_lists(device.running_config, pl_name):
            for network in _prefix_list_networks(device.running_config, pl):
                if network in own_networks:
                    violations.append(Violation(rule, device.name,
                        f"prefix-list '{pl}' (politique d'entrée du voisin eBGP {ip}) "
                        f"autorise {network}, que ce routeur annonce déjà lui-même : "
                        f"risque de réinjection"))
    return violations


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


# -- Règles propres à SR Linux (Phase D2) --------------------------------------------------

def _check_srlinux_interface_mtu_margin(rule: Rule, device: DeviceState) -> list[Violation]:
    """SR Linux exige que l'ip-mtu d'une sous-interface reste strictement inférieur au mtu L2
    de l'interface porteuse -- constaté et corrigé en direct sur ce lab (Phase C) : sans une
    marge d'au moins 14 octets (la taille d'un en-tête Ethernet), la sous-interface reste
    "down, reason ip-mtu-too-large" et une adjacence OSPF ne peut jamais s'y établir. Bonne
    pratique de conformité pour éviter de reproduire cette panne après une future
    reconfiguration de MTU. `rule.params["margin"]` (défaut 14) est la marge minimale exigée.

    Ne vérifie que les interfaces où mtu ET ip-mtu sont *explicitement* positionnés dans la
    config : une valeur absente prend le défaut de la plateforme, qu'on ne devine pas ici.
    """
    margin = rule.params.get("margin", 14)
    section = _srlinux_section(device.running_config, "interface")
    violations = []
    for name, block in _srlinux_brace_blocks(section, "interface ").items():
        mtu_match = re.search(r"^\s*mtu (\d+)\s*$", block, re.MULTILINE)
        if not mtu_match:
            continue
        mtu = int(mtu_match.group(1))
        for ip_mtu_match in re.finditer(r"^\s*ip-mtu (\d+)\s*$", block, re.MULTILINE):
            ip_mtu = int(ip_mtu_match.group(1))
            if mtu - ip_mtu < margin:
                violations.append(Violation(rule, device.name,
                    f"interface {name} : mtu {mtu} - ip-mtu {ip_mtu} = {mtu - ip_mtu} "
                    f"< marge minimale {margin} (cf. Phase C : ip-mtu-too-large)"))
    return violations


def _check_srlinux_ospf_interface_type_point_to_point(rule: Rule, device: DeviceState) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit être en interface-type point-to-point.

    Bonne pratique réseau standard sur un lien qui n'a jamais qu'un seul voisin possible :
    évite une élection DR/BDR inutile (temps de convergence et trafic de contrôle superflus),
    et le comportement par défaut de SR Linux sur Ethernet est justement l'inverse
    ("broadcast"), d'où l'intérêt de le vérifier explicitement plutôt que de compter sur la
    valeur par défaut. Les interfaces passives (LAN, loopback) sont hors de propos : sans
    adjacence, DR/BDR ne s'y applique jamais.
    """
    section = _srlinux_section(device.running_config, "network-instance default protocols ospf")
    violations = []
    for name, block in _srlinux_brace_blocks(section, "interface ").items():
        if re.search(r"^\s*passive true\s*$", block, re.MULTILINE):
            continue
        if not re.search(r"^\s*interface-type point-to-point\s*$", block, re.MULTILINE):
            violations.append(Violation(rule, device.name,
                f"interface OSPF {name} active (non passive) sans interface-type "
                f"point-to-point : risque d'élection DR/BDR inutile"))
    return violations


def _check_srlinux_ospf_authentication_required(rule: Rule, device: DeviceState) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit référencer une keychain d'authentification
    existante et de type ospf (Phase A, O1). SR Linux n'a pas de mot de passe inline sur
    l'interface (contrairement à FRR) : l'authentification est une keychain nommée, définie à
    part sous /system authentication (schéma YANG vérifié en direct par sondage : seuls
    'cleartext' et 'md5' sont des algorithmes valides pour un type 'ospf' -- 'hmac-md5' est
    réservé à isis, refusé au commit pour ospf/tcp-md5). Vérifié en interopérabilité réelle
    avec FRR (message-digest-key md5) sur le lien r4<->r5 : MD5 classique s'établit en Full des
    deux côtés ; c'est le seul algorithme commun aux deux constructeurs pour OSPF (FRR
    n'implémente que le MD5 classique RFC 2328 Appendix D, aucune variante HMAC-SHA)."""
    ospf_section = _srlinux_section(device.running_config, "network-instance default protocols ospf")
    auth_section = _srlinux_section(device.running_config, "system authentication")
    keychains = _srlinux_brace_blocks(auth_section, "keychain ")
    violations = []
    for name, block in _srlinux_brace_blocks(ospf_section, "interface ").items():
        if re.search(r"^\s*passive true\s*$", block, re.MULTILINE):
            continue  # pas d'adjacence sur une interface passive : rien à authentifier
        match = re.search(r"^\s*keychain (\S+)\s*$", block, re.MULTILINE)
        if not match:
            violations.append(Violation(rule, device.name,
                f"interface OSPF {name} active (non passive) sans authentification "
                f"(aucune keychain référencée)"))
            continue
        keychain_block = keychains.get(match.group(1))
        if keychain_block is None:
            violations.append(Violation(rule, device.name,
                f"interface OSPF {name} référence la keychain '{match.group(1)}', "
                f"introuvable sous /system authentication"))
        elif not re.search(r"^\s*type ospf\s*$", keychain_block, re.MULTILINE):
            violations.append(Violation(rule, device.name,
                f"interface OSPF {name} référence la keychain '{match.group(1)}', "
                f"qui n'est pas de type ospf"))
    return violations


_EVALUATORS = {
    "line_present": _check_line_present,
    "line_absent": _check_line_absent,
    "bgp_neighbor_inbound_policy": _check_bgp_neighbor_inbound_policy,
    "bgp_neighbor_outbound_policy": _check_bgp_neighbor_outbound_policy,
    "ospf_passive_on_interfaces": _check_ospf_passive_on_interfaces,
    "interface_description_required": _check_interface_description_required,
    "srlinux_interface_mtu_margin": _check_srlinux_interface_mtu_margin,
    "srlinux_ospf_interface_type_point_to_point": _check_srlinux_ospf_interface_type_point_to_point,
    # -- Phase A (sécurité, O1) ---------------------------------------------------------------
    "ospf_authentication_required": _check_ospf_authentication_required,
    "bgp_neighbor_password_required": _check_bgp_neighbor_password_required,
    "bgp_neighbor_maximum_prefix_required": _check_bgp_neighbor_maximum_prefix_required,
    "bgp_neighbor_ttl_security_required": _check_bgp_neighbor_ttl_security_required,
    "bgp_neighbor_no_default_route_policy": _check_bgp_neighbor_no_default_route_policy,
    "bgp_neighbor_no_own_prefixes_policy": _check_bgp_neighbor_no_own_prefixes_policy,
    "srlinux_ospf_authentication_required": _check_srlinux_ospf_authentication_required,
}
