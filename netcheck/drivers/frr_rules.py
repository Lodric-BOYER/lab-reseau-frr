"""Règles de configuration FRR (SPEC_v4, Phase A3) : ce qui lit la syntaxe de FRR vit ici, plus dans
`compliance.py`. Les évaluateurs lisent l'arbre produit par `confparse.parse_indented` (blocs par
indentation, `exit` et `!` n'ont aucun rôle structurel) au lieu de chercher des lignes par regex.

Différences voulues avec les évaluateurs textuels de la v0.3.0, toutes à l'avantage de la précision :
- une ligne est reconnue en entier (mots exacts), plus par sous-chaîne : `no ip ospf passive` n'est
  plus lu comme « ip ospf passive » ;
- un bloc se termine à la fin de son indentation : supprimer un `exit` ne fait plus perdre ni fusionner
  le bloc qui précède (la v0.3.0 ne retrouvait un bloc d'interface que s'il se terminait par `exit`).
Les messages sont inchangés mot pour mot (le gel de référence les compare), sauf pour un voisin membre d'un
peer group, que le constat nomme avec son groupe.

Vérifié en direct sur FRR 10.2.1 (les commentaires de chaque règle disent quoi). Les peer groups sont lus
par `bgp_neighbors` (étape A4) : un membre est évalué avec les réglages de son groupe, qu'il peut surcharger ;
`remote-as external|internal` désigne un voisin eBGP / iBGP.

ATTENTION, FRR ne lit pas l'indentation : il lit selon le CONTEXTE (le bloc ouvert). Vérifié avec
`vtysh -C` (contrôle de syntaxe, rien n'est appliqué) : `ip ospf area 0` ou `neighbor X remote-as N` en
colonne 0 juste après `interface eth1` ou `router bgp 65001` sont acceptés et s'appliquent au bloc ;
les mêmes lignes après `exit` sont rejetées (« Unknown command »). Or l'arbre de `confparse` rattache
une ligne à un bloc par son indentation : dans un fichier écrit à la main, une sous-commande non
indentée serait lue au premier niveau et son interface paraîtrait sans authentification, sans alerte.
`flag_misplaced_subcommands` la signale donc comme ligne NON conservée (avertissement).
"""
from __future__ import annotations

import re

from netcheck.confparse import ConfigNode, ParsedConfig
from netcheck.drivers.bgp_neighbors import FRR_SYNTAX, BgpView
from netcheck.drivers.ebgp_filters import (
    DEFAULT_ROUTE,
    default_route_violation,
    inbound_prefix_lists,
    reinjection_violation,
    same_network,
)
from netcheck.model import DeviceState
from netcheck.ruletypes import Check, Rule, Violation


def _config(cfg: ParsedConfig | None) -> ParsedConfig:
    if cfg is None:
        raise ValueError("configuration FRR non analysée")
    return cfg


def _interfaces(cfg: ParsedConfig) -> dict[str, ConfigNode]:
    """{nom: bloc 'interface <nom>'} ; un nom défini deux fois garde le dernier bloc."""
    return {" ".join(n.words[1:]): n for n in cfg.top("interface", "*")}


def _has(node: ConfigNode, *words: str) -> bool:
    """Le bloc contient une ligne EXACTEMENT égale à ces mots."""
    return any(child.words == words for child in node.children)


def _has_prefix(node: ConfigNode, *pattern: str) -> bool:
    return bool(node.children_matching(*pattern))


# Sous-commandes de bloc : (premiers mots, bloc parent attendu). Chaque entrée a été testée avec
# `vtysh -C` sur FRR 10.2.1 et REJETÉE au niveau racine (donc ne peut être qu'une sous-commande) :
# les 23 motifs observés dans les configurations réelles du dépôt et des labs, et 38 sous-commandes
# courantes non observées. Des préfixes précis, jamais un mot générique : `bgp community-list` est une
# commande valide à la racine, alors `bgp` seul ne figure pas ici (mais `bgp router-id` oui).
_BLOCK_SUBCOMMANDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ip", "address"), "interface"), (("ipv6", "address"), "interface"), (("ip", "ospf"), "interface"),
    (("ipv6", "ospf6"), "interface"),
    (("description",), "interface"), (("shutdown",), "interface"), (("mtu",), "interface"),
    (("bandwidth",), "interface"), (("link-detect",), "interface"),
    (("neighbor",), "router bgp"), (("address-family",), "router bgp"),
    (("exit-address-family",), "router bgp"), (("bgp", "router-id"), "router bgp"),
    (("bgp", "log-neighbor-changes"), "router bgp"), (("no", "bgp", "ebgp-requires-policy"), "router bgp"),
    (("maximum-paths",), "router bgp"),
    (("ospf", "router-id"), "router ospf"), (("ospf6", "router-id"), "router ospf6"),
    (("passive-interface",), "router ospf"),
    (("area",), "router ospf"), (("default-information", "originate"), "router ospf"),
    (("log-adjacency-changes",), "router ospf"),
    (("network",), "router bgp ou router ospf"), (("redistribute",), "router bgp ou router ospf"),
    (("match",), "route-map"), (("set",), "route-map"), (("on-match",), "route-map"),
    (("call",), "route-map"),
)


def flag_misplaced_subcommands(cfg: ParsedConfig) -> None:
    """Signale (ligne NON conservée) toute sous-commande de bloc connue trouvée au premier niveau.
    Les sorties relevées en direct sont toujours indentées : elles n'en produisent aucune."""
    for node in list(cfg.root.children):
        for prefix, parent in _BLOCK_SUBCOMMANDS:
            if node.words[:len(prefix)] == prefix:
                cfg.reject(node, f"sous-commande de « {parent} » au premier niveau : FRR l'applique au bloc "
                                 f"ouvert quelle que soit l'indentation, l'analyse ne sait pas lequel")
                break


def _bgp(cfg: ParsedConfig) -> BgpView | None:
    """Le premier bloc `router bgp <AS>`, ou None s'il n'y a pas de BGP configuré. Les voisins sont lus
    avec leurs réglages effectifs (peer groups : voir `bgp_neighbors`)."""
    nodes = cfg.top("router", "bgp", "*")
    return BgpView(nodes[0], FRR_SYNTAX) if nodes else None


# ------------------------------------------------------------------------------------------
# Politiques d'entrée et de sortie des voisins eBGP
# ------------------------------------------------------------------------------------------

def _policy_lines(bgp: BgpView, ip: str, kind: str, direction: str) -> list[ConfigNode]:
    return bgp.lines(ip, lambda rest: len(rest) == 3 and rest[0] == kind and rest[2] == direction)


def _has_policy(bgp: BgpView, ip: str, direction: str) -> bool:
    return any(_policy_lines(bgp, ip, kind, direction) for kind in ("route-map", "prefix-list"))


def _check_bgp_policy(rule: Rule, device: DeviceState, cfg, direction: str) -> list[Violation]:
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []  # pas de BGP configuré sur cet équipement : rien à vérifier
    mot = "entrée" if direction == "in" else "sortie"
    return [Violation(rule, device.name,
                      f"voisin eBGP {bgp.label(ip)} sans route-map/prefix-list en {mot}", ip)
            for ip in bgp.ebgp if not _has_policy(bgp, ip, direction)]


def _check_bgp_neighbor_inbound_policy(rule, device, cfg):
    return _check_bgp_policy(rule, device, cfg, "in")


def _check_bgp_neighbor_outbound_policy(rule, device, cfg):
    return _check_bgp_policy(rule, device, cfg, "out")


# ------------------------------------------------------------------------------------------
# OSPF
# ------------------------------------------------------------------------------------------

def _check_ospf_passive_on_interfaces(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    pattern = rule.params.get("pattern")
    if not pattern:
        raise ValueError(f"règle '{rule.id}' (ospf_passive_on_interfaces) : paramètre 'pattern' manquant")
    regex = re.compile(pattern)
    blocks = _interfaces(_config(cfg))
    violations = []
    for iface in device.interfaces:
        if not iface.description or not regex.search(iface.description):
            continue
        block = blocks.get(iface.name)
        if block is None or not _has(block, "ip", "ospf", "passive"):
            violations.append(Violation(rule, device.name,
                f"interface {iface.name} (description '{iface.description}') "
                f"n'est pas en ip ospf passive", iface.name))
    return violations


def _check_ospf_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit porter une authentification message-
    digest (Phase A, O1). Vérifié en direct (FRR 10.2.1) : accepté sans casser l'adjacence
    quand appliqué symétriquement des deux côtés d'un lien -- mais `service password-
    encryption` ne chiffre PAS la clé dans running-config (vérifié en direct également) : elle
    reste en clair dans la config et dans les snapshots, d'où la portée du champ `references` de
    cette règle et le rappel dans le README (snapshots exclus de Git, valeurs de lab)."""
    violations = []
    for name, block in _interfaces(_config(cfg)).items():
        if not _has_prefix(block, "ip", "ospf", "area") or _has(block, "ip", "ospf", "passive"):
            continue  # pas de l'OSPF actif sur cette interface : pas d'adjacence, rien à protéger
        if not _has_prefix(block, "ip", "ospf", "authentication", "message-digest"):
            violations.append(Violation(rule, device.name,
                f"interface {name} : adjacence OSPF active sans authentification "
                f"message-digest", name))
    return violations


def _check_ospf6_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface OSPFv3 active (non passive) doit porter une authentification (Phase B3, O2). FRR 10.2.1
    n'a que l'en-tête d'authentification de la RFC 7166 : `ipv6 ospf6 authentication key-id N hash-algo A
    key K` ou `ipv6 ospf6 authentication keychain NOM`. Vérifié par `vtysh -C` : `authentication null` et
    la forme `ipsec spi ...` sont REFUSÉES par cette version, elles ne peuvent donc pas figurer dans une
    configuration. Seules la présence de la clé (ou la référence de la keychain) compte, jamais sa valeur.
    Une interface est active quand elle a `ipv6 ospf6 area N` et pas `ipv6 ospf6 passive`."""
    violations = []
    for name, block in _interfaces(_config(cfg)).items():
        if not _has_prefix(block, "ipv6", "ospf6", "area") or _has(block, "ipv6", "ospf6", "passive"):
            continue  # pas d'OSPFv3 actif sur cette interface : pas d'adjacence, rien à protéger
        authenticated = any(
            c.words[:3] == ("ipv6", "ospf6", "authentication") and (
                (len(c.words) >= 4 and c.words[3] == "key-id" and "key" in c.words[4:-1])
                or (len(c.words) == 5 and c.words[3] == "keychain"))
            for c in block.children)
        if not authenticated:
            violations.append(Violation(rule, device.name,
                f"interface {name} : adjacence OSPFv3 active sans authentification "
                f"(ipv6 ospf6 authentication)", name))
    return violations


# ------------------------------------------------------------------------------------------
# Sécurité des sessions eBGP
# ------------------------------------------------------------------------------------------

def _check_bgp_neighbor_password_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP doit avoir un mot de passe TCP-MD5 (Phase A, O1). Vérifié en direct :
    accepté par FRR 10.2.1 (kernel WSL2 : CONFIG_TCP_MD5SIG=y). TCP-AO (RFC 5925), plus récent,
    est hors de portée ici : ni le kernel WSL2 (CONFIG_TCP_AO absent) ni bgpd (feature request
    FRRouting#7240, jamais mergée) ne le supportent dans ce lab -- TCP-MD5 est donc la seule
    option réaliste, malgré ses faiblesses cryptographiques connues face à TCP-AO."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []
    return [Violation(rule, device.name,
                      f"voisin eBGP {bgp.label(ip)} sans authentification TCP-MD5 (mot de passe)", ip)
            for ip in bgp.ebgp
            if not any(len(n.words) == 4 for n in bgp.lines(ip, lambda rest: rest[:1] == ("password",)))]


def _check_bgp_neighbor_maximum_prefix_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP doit avoir une limite `maximum-prefix` (Phase A, O1) : protège contre
    une fuite de routes massive côté voisin. Vérifié en direct : accepté par FRR 10.2.1, mais
    la modification force un reset de la session (FSM repassé par Active quelques secondes,
    NOTIFICATION Cease envoyée) -- un `clear bgp` explicite a été nécessaire pour un retour
    immédiat à Established pendant ce test ; à surveiller en Phase B (test_lab.sh/
    integration.sh doivent rester verts malgré ce reset)."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []
    return [Violation(rule, device.name, f"voisin eBGP {bgp.label(ip)} sans limite maximum-prefix", ip)
            for ip in bgp.ebgp
            if not any(len(n.words) == 4 and n.words[3].isdigit()
                       for n in bgp.lines(ip, lambda rest: rest[:1] == ("maximum-prefix",)))]


def _check_bgp_neighbor_ttl_security_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Chaque voisin eBGP doit avoir le GTSM (`ttl-security hops`, RFC 5082) activé (Phase A,
    O1) : rejette les paquets dont le TTL indique qu'ils viennent de plus loin que le voisin
    direct attendu, sans les coûts cryptographiques d'une authentification. Vérifié en direct :
    accepté par FRR 10.2.1 sur ce lien directement connecté (hops 1) ; même remarque que
    `bgp_neighbor_maximum_prefix_required` sur le reset de session observé au moment du
    changement."""
    bgp = _bgp(_config(cfg))
    if bgp is None:
        return []
    return [Violation(rule, device.name, f"voisin eBGP {bgp.label(ip)} sans GTSM (ttl-security hops)", ip)
            for ip in bgp.ebgp
            if not any(len(n.words) == 5 and n.words[4].isdigit()
                       for n in bgp.lines(ip, lambda rest: rest[:2] == ("ttl-security", "hops")))]


# ------------------------------------------------------------------------------------------
# Politiques d'entrée : ce que la prefix-list autorise réellement
# ------------------------------------------------------------------------------------------

# Les route-maps d'entrée d'un voisin (TOUS, par famille d'adresses, séquences `deny` ignorées) sont lus par
# `ebgp_filters.inbound_prefix_lists`, comme pour EOS (Phase B4). Un voisin sans route-map en entrée n'a
# rien à lire ici : la règle ebgp-politique-entrante existante signale déjà le problème.


def _prefix_list_networks(cfg: ParsedConfig, name: str, family: str = "ip") -> list[str]:
    """Réseau (sans le 'le'/'ge' éventuel) de chaque entrée 'permit' d'une prefix-list, IPv4 (`ip
    prefix-list`) ou IPv6 (`ipv6 prefix-list`). Seules les entrées 'permit' AUTORISENT un préfixe : un
    'deny' est un filtre, pas une faute (Phase B4 : l'IPv4 est alignée sur l'IPv6 ; la v0.3.0 comptait
    aussi les 'deny' IPv4 et signalait donc à tort `deny 0.0.0.0/0` ou `deny <notre préfixe>`, qui sont
    précisément les bons filtres). L'ordre des entrées n'est pas simulé (premier correspondant) : un
    'permit' est signalé même précédé d'un 'deny' plus large."""
    return [n.words[6] for n in cfg.top(family, "prefix-list", name)
            if len(n.words) >= 7 and n.words[3] == "seq" and n.words[4].isdigit() and n.words[5] == "permit"]


def _check_bgp_neighbor_no_default_route_policy(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """La prefix-list appliquée en entrée à chaque voisin eBGP ne doit autoriser la route par défaut
    (0.0.0.0/0, et ::/0 depuis la phase B3) sous aucune forme (Phase A, O1 -- politique déclarée, pas la
    table de routage : un voisin qui n'annonce pas encore de route par défaut aujourd'hui ne prouve rien
    sur le filtrage lui-même). Toute entrée dont le réseau de base est la route par défaut la couvre,
    qu'elle porte ou non une clause `le`/`ge` -- 'permit 0.0.0.0/0' et 'permit 0.0.0.0/0 le 32' sont donc
    tous deux détectés par la même vérification sur le réseau de base. Les prefix-lists IPv4 et IPv6 d'un
    route-map sont lues chacune pour sa famille (`match ip address` et `match ipv6 address`). Phase B4 :
    tous les route-maps d'entrée du voisin sont lus (par famille d'adresses), les séquences `deny` d'un
    route-map sont ignorées."""
    config = _config(cfg)
    bgp = _bgp(config)
    if bgp is None:
        return []
    violations = []
    for ip in bgp.ebgp:
        for family, pl in inbound_prefix_lists(config, bgp, ip):
            for network in _prefix_list_networks(config, pl, family):
                if same_network(family, network, DEFAULT_ROUTE[family]):
                    violations.append(
                        default_route_violation(rule, device.name, bgp.label(ip), ip, family, pl))
    return violations


def _check_bgp_neighbor_no_own_prefixes_policy(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """La prefix-list appliquée en entrée à chaque voisin eBGP ne doit pas autoriser un préfixe
    que ce routeur annonce lui-même (Phase A, O1 -- politique déclarée ; IPv6 depuis la phase B3, où les
    `network` se déclarent sous `address-family ipv6 unicast`) : sans ce filtre, un voisin pourrait réannoncer
    nos propres préfixes, créant une boucle ou un détournement de trafic. Vérifié sur la config réelle : r3
    annonce 10.1.0.0/16 et 192.168.1.0/24, sa PL-EBGP-IN n'autorise que 10.2.0.0/16 et 192.168.2.0/24 -- déjà
    conforme aujourd'hui."""
    config = _config(cfg)
    bgp = _bgp(config)
    if bgp is None:
        return []
    own_networks = [n.words[1] for n in bgp.below if len(n.words) >= 2 and n.words[0] == "network"]
    violations = []
    for ip in bgp.ebgp:
        for family, pl in inbound_prefix_lists(config, bgp, ip):
            for network in _prefix_list_networks(config, pl, family):
                if any(same_network(family, network, own) for own in own_networks):
                    violations.append(
                        reinjection_violation(rule, device.name, bgp.label(ip), ip, pl, network))
    return violations


CHECKS: dict[str, Check] = {
    "bgp_neighbor_inbound_policy": Check(_check_bgp_neighbor_inbound_policy),
    "bgp_neighbor_outbound_policy": Check(_check_bgp_neighbor_outbound_policy),
    # Lit les descriptions d'interface du MODÈLE collecté, en plus de la configuration.
    "ospf_passive_on_interfaces":
        Check(_check_ospf_passive_on_interfaces, frozenset({"config", "interfaces"})),
    "ospf_authentication_required": Check(_check_ospf_authentication_required),
    "ospf6_authentication_required": Check(_check_ospf6_authentication_required, ipv6=True),
    "bgp_neighbor_password_required": Check(_check_bgp_neighbor_password_required),
    "bgp_neighbor_maximum_prefix_required": Check(_check_bgp_neighbor_maximum_prefix_required),
    "bgp_neighbor_ttl_security_required": Check(_check_bgp_neighbor_ttl_security_required),
    "bgp_neighbor_no_default_route_policy": Check(_check_bgp_neighbor_no_default_route_policy),
    "bgp_neighbor_no_own_prefixes_policy": Check(_check_bgp_neighbor_no_own_prefixes_policy),
}
