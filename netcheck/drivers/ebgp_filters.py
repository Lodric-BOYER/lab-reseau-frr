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
