"""Règles de configuration Arista EOS (SPEC_v4, Phase A3) : ce qui lit la syntaxe d'EOS vit ici, plus dans
`compliance.py`. Les évaluateurs lisent l'arbre de `confparse.parse_indented`.

Syntaxes vérifiées sur cEOS 4.34.8M (tests/fixtures/ceos/) : `ip ospf authentication message-digest`,
`ip ospf message-digest-key 1 md5 7 <hash>` (EOS écrit la clé en « type 7 »), `neighbor X password 7
<hash>`, `neighbor X ttl maximum-hops 1`, `neighbor X maximum-routes 10`, `passive-interface <if>` sous
`router ospf`.

EOS, comme FRR, lit un fichier de configuration selon le CONTEXTE (le mode ouvert) et non selon
l'indentation. Vérifié en chargeant de vrais fichiers dans une session de configuration abandonnée :
`neighbor X remote-as N` en colonne 0 juste après `router bgp 65002` est appliqué à `router bgp`, y
compris après un `!` en colonne 0 (un `!` est un commentaire, il ne ferme aucun bloc) ; la même ligne
après `exit` est rejetée (« Invalid input »). Une sous-commande non indentée serait donc lue au premier
niveau par l'arbre et son bloc paraîtrait incomplet, sans alerte : `flag_misplaced_subcommands` la signale
(ligne NON conservée). Conséquence sur l'ancien code (v0.3.0), qui terminait un bloc au premier `!` : il
ignorait les lignes indentées qui suivent un `!` alors qu'EOS les applique au bloc ouvert.

Les messages sont ceux de la v0.3.0, mot pour mot (le gel de référence les compare), sauf pour un voisin
membre d'un peer group, que le constat nomme avec son groupe (étape A4 : `bgp_neighbors`).
"""
from __future__ import annotations

import re

from netcheck.confparse import ConfigNode, ParsedConfig
from netcheck.drivers.bgp_neighbors import EOS_SYNTAX, BgpView
from netcheck.model import DeviceState
from netcheck.ruletypes import Check, Rule, Violation

# Une bannière EOS est du texte libre multi-lignes, terminé par `EOF` (vérifié, `login` et `motd`) : ses
# lignes peuvent contenir « ! », « { » ou une indentation, sans être de la configuration.
RAW_BLOCKS = ((r"banner (?:login|motd)", r"EOF"),)


def _config(cfg: ParsedConfig | None) -> ParsedConfig:
    if cfg is None:
        raise ValueError("configuration EOS non analysée")
    return cfg


def _below(block: ConfigNode) -> list[ConfigNode]:
    return [n for n in block.walk() if n is not block]


def _has(node: ConfigNode, *words: str) -> bool:
    return any(child.words == words for child in node.children)


def _bgp(cfg: ParsedConfig) -> BgpView | None:
    """Le premier bloc `router bgp <AS>`. Les voisins sont lus avec leurs réglages effectifs : un membre
    d'un peer group hérite de son groupe et peut le surcharger (voir `bgp_neighbors`, relevé sur cEOS
    4.34.8M dans tests/fixtures/peergroups/). EOS refuse `remote-as external|internal` (`% Invalid input`,
    sur un voisin comme sur un groupe) : seuls des numéros d'AS désignent un voisin."""
    nodes = cfg.top("router", "bgp", "*")
    return BgpView(nodes[0], EOS_SYNTAX) if nodes else None


def _check_eos_ospf_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface OSPF EOS active (non passive) doit porter `ip ospf authentication message-
    digest` ET au moins une clé `ip ospf message-digest-key N md5 ...` : le mode seul, sans clé,
    ne peut jamais former d'adjacence. Interopérabilité vérifiée en direct avec FRR (MD5 classique,
    RFC 2328 Annexe D) : adjacence Full des deux côtés, et perdue avec une mauvaise clé. Une
    interface est passive par `passive-interface <if>` sous `router ospf`, ou par `passive-
    interface default` sans `no passive-interface <if>`."""
    config = _config(cfg)
    routers = config.top("router", "ospf", "*")
    if not routers:
        return []
    below = [n for router in routers for n in _below(router)]
    passive_default = any(n.words == ("passive-interface", "default") for n in below)
    passive = {n.words[1] for n in below if n.words[0] == "passive-interface" and len(n.words) >= 2
               and not re.match(r"default\b", n.words[1])}
    active = {n.words[2] for n in below if n.words[:2] == ("no", "passive-interface") and len(n.words) >= 3}
    interfaces = {" ".join(n.words[1:]): n for n in config.top("interface", "*")}
    violations = []
    for name, block in interfaces.items():
        if not any(len(c.words) == 4 and c.words[:3] == ("ip", "ospf", "area") for c in block.children):
            continue
        if name in passive or (passive_default and name not in active):
            continue   # pas d'adjacence sur une interface passive : rien à authentifier
        if not _has(block, "ip", "ospf", "authentication", "message-digest"):
            violations.append(Violation(rule, device.name,
                f"interface {name} : adjacence OSPF active sans authentification message-digest", name))
        elif not any(len(c.words) >= 6 and c.words[:3] == ("ip", "ospf", "message-digest-key")
                     and c.words[3].isdigit() and c.words[4] == "md5" for c in block.children):
            violations.append(Violation(rule, device.name,
                f"interface {name} : message-digest activé mais aucune clé md5 configurée", name))
    return violations


def _check_eos_ospf6_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface OSPFv3 EOS active doit porter une authentification (Phase B3, O2). Sur cEOS 4.34.8M, la
    seule forme acceptée est IPsec : `ospfv3 authentication ipsec spi N (sha1|md5) [passphrase] <clé>` (EOS
    écrit la clé en « type 7 » dans la configuration). Vérifié dans des sessions de configuration
    abandonnées : `ospfv3 authentication disabled`, `null` et la forme `encryption ipsec` essayée sont
    refusées (« Invalid input »). Seule la présence compte, jamais la valeur de la clé. Une interface est
    active quand elle a `ospfv3 ipv6 area N` et pas `ospfv3 passive` (ou `passive-interface`)."""
    violations = []
    for name, block in {" ".join(n.words[1:]): n for n in _config(cfg).top("interface", "*")}.items():
        if not any(c.words[:3] == ("ospfv3", "ipv6", "area") for c in block.children):
            continue
        # EOS écrit `ospfv3 passive` dans un fichier de démarrage et `ospfv3 passive-interface` dans la
        # running-config (relevé sur cEOS 4.34.8M) : les deux désignent une interface passive.
        if _has(block, "ospfv3", "passive") or _has(block, "ospfv3", "passive-interface"):
            continue   # pas d'adjacence sur une interface passive : rien à authentifier
        if not any(len(c.words) >= 7 and c.words[:4] == ("ospfv3", "authentication", "ipsec", "spi")
                   and c.words[4].isdigit() and c.words[5] in ("sha1", "md5") for c in block.children):
            violations.append(Violation(rule, device.name,
                f"interface {name} : adjacence OSPFv3 active sans authentification "
                f"(ospfv3 authentication ipsec)", name))
    return violations


def _check_eos_bgp_neighbor_password_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP EOS doit avoir un mot de passe TCP-MD5 (`neighbor X password [type] ...`,
    EOS l'écrit en « type 7 »). Interopérabilité vérifiée en direct avec FRR : session Established
    des deux côtés, et en Connect avec un mot de passe différent après réinitialisation (une
    session déjà établie garde son socket tant qu'elle n'est pas réinitialisée)."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []

    def has_password(ip: str) -> bool:
        for n in bgp.lines(ip, lambda rest: rest[:1] == ("password",)):
            rest = n.words[3:]
            if len(rest) == 1 or (len(rest) == 2 and rest[0].isdigit()):
                return True
        return False

    return [Violation(rule, device.name,
                      f"voisin eBGP {bgp.label(ip)} sans authentification TCP-MD5 (mot de passe)", ip)
            for ip in bgp.ebgp if not has_password(ip)]


def _check_eos_bgp_neighbor_ttl_security_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP EOS doit avoir le GTSM (`neighbor X ttl maximum-hops N`, RFC 5082) :
    EOS envoie alors un TTL de 255 et rejette un TTL inférieur à 255-N. Vérifié en direct : sans
    cette commande EOS envoie un TTL de 1 et un voisin FRR en `ttl-security` ne monte jamais."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []
    return [Violation(rule, device.name, f"voisin eBGP {bgp.label(ip)} sans GTSM (ttl maximum-hops)", ip)
            for ip in bgp.ebgp
            if not any(len(n.words) == 5 and n.words[4].isdigit()
                       for n in bgp.lines(ip, lambda rest: rest[:2] == ("ttl", "maximum-hops")))]


def _check_eos_bgp_neighbor_maximum_routes_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP EOS doit avoir `neighbor X maximum-routes N` avec N > 0 (0 = illimité).
    ATTENTION : `maximum-routes` (EOS) n'est PAS strictement équivalent au `maximum-prefix` de
    FRR -- voir la description de la règle dans security.yml."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []
    violations = []
    for ip in bgp.ebgp:
        limit = next((int(m.group())
                      for n in bgp.lines(ip, lambda rest: rest[:1] == ("maximum-routes",))
                      if len(n.words) >= 4 and (m := re.match(r"\d+\b", n.words[3]))), None)
        if limit is None:
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {bgp.label(ip)} sans limite maximum-routes", ip))
        elif limit == 0:
            violations.append(Violation(rule, device.name,
                f"voisin eBGP {bgp.label(ip)} : maximum-routes 0 (illimité) n'est pas une limite", ip))
    return violations


def _check_eos_management_api_disabled(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Aucune API de gestion EOS ne doit être active : eAPI, gNMI, NETCONF. Seul SSH est utilisé
    par netcheck, et un lab de sécurité n'expose pas d'API inutiles (chacune est un service réseau
    de plus, avec sa propre authentification et sa propre surface d'attaque). Formes observées
    sur cEOS 4.34.8M : eAPI active = `management api http-commands` + `no shutdown` ; gNMI ou
    NETCONF actifs = `management api gnmi|netconf` + une ligne `transport ...` ; section absente =
    API désactivée. Le mécanisme de désactivation par `shutdown` d'un transport n'a pas été
    observé : une section présente avec `transport` est donc toujours signalée."""
    blocks = {n.words[2]: n for n in _config(cfg).top("management", "api", "*")}
    violations = []
    http = blocks.get("http-commands")
    if http is not None and any(n.words == ("no", "shutdown") for n in _below(http)):
        violations.append(Violation(rule, device.name,
            "API de gestion eAPI (management api http-commands) active (no shutdown)", "http-commands"))
    for api, label in (("gnmi", "gNMI"), ("netconf", "NETCONF")):
        block = blocks.get(api)
        if block is not None and any(n.words[0] == "transport" and len(n.words) >= 2 for n in _below(block)):
            violations.append(Violation(rule, device.name,
                f"API de gestion {label} (management api {api}) active (transport configuré)", api))
    return violations


# Sous-commandes de bloc : (premiers mots, bloc parent attendu). Chaque entrée a été testée sur cEOS
# 4.34.8M en chargeant la ligne SEULE, au niveau racine, dans une session de configuration abandonnée :
# toutes sont rejetées (« Invalid input »). 22 motifs observés dans les configurations réelles et 30
# sous-commandes courantes non observées ; aucune n'a été acceptée à la racine.
_BLOCK_SUBCOMMANDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("description",), "interface"), (("ip", "address"), "interface"), (("ipv6", "address"), "interface"),
    (("ip", "ospf"), "interface"), (("no", "switchport"), "interface"), (("switchport",), "interface"),
    (("shutdown",), "interface"), (("mtu",), "interface"),
    (("neighbor",), "router bgp"), (("address-family",), "router bgp"), (("maximum-paths",), "router bgp"),
    (("passive-interface",), "router ospf"), (("max-lsa",), "router ospf"),
    (("router-id",), "router bgp ou router ospf"), (("network",), "router bgp ou router ospf"),
    (("redistribute",), "router bgp ou router ospf"),
    (("match",), "route-map"), (("set",), "route-map"), (("continue",), "route-map"),
    (("transport",), "management api"), (("no", "shutdown"), "management api ou interface"),
)


def flag_misplaced_subcommands(cfg: ParsedConfig) -> None:
    """Signale (ligne NON conservée) toute sous-commande de bloc connue trouvée au premier niveau.
    Les sorties relevées en direct sont toujours indentées : elles n'en produisent aucune."""
    for node in list(cfg.root.children):
        for prefix, parent in _BLOCK_SUBCOMMANDS:
            if node.words[:len(prefix)] == prefix:
                cfg.reject(node, f"sous-commande de « {parent} » au premier niveau : EOS l'applique au bloc "
                                 f"ouvert quelle que soit l'indentation, l'analyse ne sait pas lequel")
                break


CHECKS: dict[str, Check] = {
    "eos_ospf_authentication_required": Check(_check_eos_ospf_authentication_required),
    "eos_ospf6_authentication_required": Check(_check_eos_ospf6_authentication_required, ipv6=True),
    "eos_bgp_neighbor_password_required": Check(_check_eos_bgp_neighbor_password_required),
    "eos_bgp_neighbor_ttl_security_required": Check(_check_eos_bgp_neighbor_ttl_security_required),
    "eos_bgp_neighbor_maximum_routes_required": Check(_check_eos_bgp_neighbor_maximum_routes_required),
    "eos_management_api_disabled": Check(_check_eos_management_api_disabled),
}
