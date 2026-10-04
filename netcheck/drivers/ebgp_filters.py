"""Ce que les règles « pas de route par défaut en entrée » et « pas de réinjection de nos préfixes en entrée »
ont de commun pour FRR et EOS (SPEC_v4, Phase B4) : la route par défaut de chaque famille, la comparaison de
deux réseaux et le texte des constats. La syntaxe propre à chaque équipement (où se trouvent les route-maps et
les prefix-lists) reste dans son driver ; un seul texte de constat, donc, quel que soit le constructeur.

Seules les entrées `permit` d'une prefix-list AUTORISENT un préfixe : un `deny` est un filtre, jamais une
faute. L'ordre des entrées n'est pas simulé (« premier correspondant ») : un `permit` est signalé même
précédé d'un `deny` plus large.
"""
from __future__ import annotations

import ipaddress

from netcheck.confparse import ParsedConfig
from netcheck.drivers.bgp_neighbors import BgpView
from netcheck.ruletypes import Rule, Violation

# Famille des listes de préfixes : « ip » (IPv4) ou « ipv6 », comme le premier mot de leur commande.
DEFAULT_ROUTE = {"ip": "0.0.0.0/0", "ipv6": "::/0"}


def same_network(family: str, a: str, b: str) -> bool:
    """IPv4 : comparaison de texte, comme la v0.3.0. IPv6 : comparaison des réseaux (la compression de
    l'écriture ne compte pas : `2001:db8:1:0::/48` est `2001:db8:1::/48`)."""
    if family == "ip":
        return a == b
    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b


def route_map_prefix_lists(cfg: ParsedConfig, route_map: str) -> list[tuple[str, str]]:
    """(famille, nom) des prefix-lists que les séquences `permit` d'un route-map font correspondre :
    `match ip address prefix-list` (famille « ip ») et `match ipv6 address prefix-list` (« ipv6 »). Une
    séquence `deny` est ignorée : elle REFUSE ce qu'elle reconnaît, c'est la manière classique d'écarter la
    route par défaut (`route-map X deny 5` + `match ip address prefix-list DEFAUT`), pas une faute. Sans
    action, le route-map est un `permit` (FRR comme EOS)."""
    found: list[tuple[str, str]] = []
    for block in cfg.top("route-map", route_map):
        if block.words[2:3] == ("deny",):
            continue
        for line in block.children:
            w = line.words
            is_match = len(w) >= 5 and w[0] == "match" and w[1] in ("ip", "ipv6")
            if is_match and w[2:4] == ("address", "prefix-list"):
                found.append((w[1], w[4]))
    return found


def inbound_prefix_lists(cfg: ParsedConfig, bgp: BgpView, neighbor: str) -> list[tuple[str, str]]:
    """(famille, nom) de chaque prefix-list des route-maps appliqués en ENTRÉE à ce voisin : TOUS les
    route-maps d'entrée, avec les réglages effectifs PAR FAMILLE d'adresses (le membre d'un peer group
    masque son groupe famille par famille). Un voisin sans route-map en entrée n'a rien à lire ici : la
    règle de politique d'entrée le dit déjà. Chaque (famille, liste) n'est donnée qu'une fois."""
    seen: list[tuple[str, str]] = []
    for line in bgp.lines_by_family(
            neighbor, lambda rest: len(rest) == 3 and rest[0] == "route-map" and rest[2] == "in"):
        for key in route_map_prefix_lists(cfg, line.words[3]):
            if key not in seen:
                seen.append(key)
    return seen


def default_route_violation(rule: Rule, device: str, neighbor_label: str, neighbor: str, family: str,
                            prefix_list: str) -> Violation:
    default = DEFAULT_ROUTE[family]
    return Violation(rule, device,
                     f"prefix-list '{prefix_list}' (politique d'entrée du voisin eBGP {neighbor_label}) "
                     f"autorise {default} : route par défaut acceptable depuis l'extérieur", neighbor)


def reinjection_violation(rule: Rule, device: str, neighbor_label: str, neighbor: str, prefix_list: str,
                          network: str) -> Violation:
    return Violation(rule, device,
                     f"prefix-list '{prefix_list}' (politique d'entrée du voisin eBGP {neighbor_label}) "
                     f"autorise {network}, que ce routeur annonce déjà lui-même : risque de réinjection",
                     neighbor)
