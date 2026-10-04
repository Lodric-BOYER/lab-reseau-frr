"""Règles de configuration SR Linux (SPEC_v4, Phase A3) : ce qui lit la syntaxe de SR Linux vit ici,
plus dans `compliance.py`. Les évaluateurs lisent la VUE PLATE de `confparse` : un chemin de mots par
ligne feuille (`interface ethernet-1/1 subinterface 0 ip-mtu 1500`). Ce n'est pas un détail : SR Linux
a DEUX syntaxes pour la même configuration, les accolades de « info from running » (relevées sur
l'équipement) et les lignes `set / ...` du fichier de démarrage. Les deux donnent les mêmes chemins
(vérifié sur le r5 réel : 27 lignes sur 31 du `config.cli` se retrouvent à l'identique), donc chaque
règle ne s'écrit qu'une fois.

Ces règles vérifient la PRÉSENCE et la RÉFÉRENCE d'une clé (une keychain qui existe, de type ospf,
référencée par l'interface), jamais sa FORME : la clé est en clair dans `config.cli` et en `$aes1$` sur
l'équipement (la plateforme l'obscurcit), et le verdict doit être le même. Elles ne vérifient pas non
plus qu'une clé existe DANS la keychain (comportement de la v0.3.0, conservé ; amélioration prévue).

Les messages sont ceux de la v0.3.0, mot pour mot (le gel de référence les compare).
"""
from __future__ import annotations

from netcheck.confparse import FlatLine, ParsedConfig
from netcheck.model import DeviceState
from netcheck.ruletypes import Check, Rule, Violation

_OSPF = ("network-instance", "default", "protocols", "ospf")


def _config(cfg: ParsedConfig | None) -> ParsedConfig:
    if cfg is None:
        raise ValueError("configuration SR Linux non analysée")
    return cfg


def _ospf_versions(cfg: ParsedConfig) -> dict[str, str]:
    """{instance: version} d'après `instance <nom> version ospf-v2|ospf-v3`. Une instance sans ligne `version`
    est lue comme OSPFv2 (le comportement de la v0.3.0, qui ne connaissait pas l'OSPFv3)."""
    versions: dict[str, str] = {}
    for line in cfg.select(*_OSPF):
        tail = line.path[len(_OSPF):]
        if len(tail) == 4 and tail[0] == "instance" and tail[2] == "version":
            versions[tail[1]] = tail[3]
    return versions


def _ospf_interfaces(cfg: ParsedConfig, version: str = "ospf-v2") -> dict[str, list[tuple[str, ...]]]:
    """{interface: [chemin restant, ...]} pour les interfaces OSPF des instances de cette VERSION (phase B3 :
    une instance `ospf-v3` ne donne plus ses interfaces aux règles OSPFv2, qui lui reprochaient une
    keychain que la plateforme refuse), dans l'ordre. L'interface se repère au mot `interface` sous le
    chemin OSPF, où qu'il soit (instance et zone n'ont pas à être là : comme la v0.3.0, qui cherchait les
    blocs `interface <nom>` à toute profondeur). Une interface OSPF sans aucune ligne (bloc vide) est
    présente avec une liste vide."""
    versions = _ospf_versions(cfg)
    interfaces: dict[str, list[tuple[str, ...]]] = {}
    for line in cfg.select(*_OSPF):
        tail = line.path[len(_OSPF):]
        instance = tail[1] if len(tail) > 1 and tail[0] == "instance" else None
        if (versions.get(instance, "ospf-v2") if instance is not None else "ospf-v2") != version:
            continue
        if "interface" not in tail:
            continue
        i = tail.index("interface")
        if i + 1 >= len(tail):
            continue
        rest = interfaces.setdefault(tail[i + 1], [])
        if len(tail) > i + 2:
            rest.append(tail[i + 2:])
    return interfaces


def _is_passive(rest: list[tuple[str, ...]]) -> bool:
    return ("passive", "true") in rest


def _check_srlinux_interface_mtu_margin(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
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
    by_interface: dict[str, list[FlatLine]] = {}
    for line in _config(cfg).select("interface", "*"):
        by_interface.setdefault(line.path[1], []).append(line)
    violations = []
    for name, lines in by_interface.items():
        mtu = next((int(line.path[3]) for line in lines
                    if len(line.path) == 4 and line.path[2] == "mtu" and line.path[3].isdigit()), None)
        if mtu is None:
            continue
        for line in lines:
            if line.path[-2] == "ip-mtu" and line.path[-1].isdigit():
                ip_mtu = int(line.path[-1])
                if mtu - ip_mtu < margin:
                    violations.append(Violation(rule, device.name,
                        f"interface {name} : mtu {mtu} - ip-mtu {ip_mtu} = {mtu - ip_mtu} "
                        f"< marge minimale {margin} (cf. Phase C : ip-mtu-too-large)", name))
    return violations


def _check_srlinux_ospf_interface_type_point_to_point(
        rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit être en interface-type point-to-point.

    Bonne pratique réseau standard sur un lien qui n'a jamais qu'un seul voisin possible :
    évite une élection DR/BDR inutile (temps de convergence et trafic de contrôle superflus),
    et le comportement par défaut de SR Linux sur Ethernet est justement l'inverse
    ("broadcast"), d'où l'intérêt de le vérifier explicitement plutôt que de compter sur la
    valeur par défaut. Les interfaces passives (LAN, loopback) sont hors de propos : sans
    adjacence, DR/BDR ne s'y applique jamais.
    """
    violations = []
    for name, rest in _ospf_interfaces(_config(cfg)).items():
        if _is_passive(rest):
            continue
        if ("interface-type", "point-to-point") not in rest:
            violations.append(Violation(rule, device.name,
                f"interface OSPF {name} active (non passive) sans interface-type "
                f"point-to-point : risque d'élection DR/BDR inutile", name))
    return violations


def _check_srlinux_ospf_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    return _keychain_violations(rule, device, cfg, "ospf-v2", "OSPF")


def _check_srlinux_ospf6_authentication_required(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Toute interface des instances OSPFv3 (`version ospf-v3`) doit référencer une keychain
    d'authentification (Phase B3, O2), comme en OSPFv2. Vérifié sur 26.7.2 : le schéma de l'interface OSPF
    n'a qu'UN mécanisme, `authentication keychain` (`tree` : ni ipsec ni autre), et la plateforme le REFUSE
    pour une instance ospf-v3 (« Authentication keychain not supported on ospf-v3 », constaté par `commit
    validate`). Cette règle signale donc, sur cette version, toute adjacence OSPFv3 : c'est le fait, et
    c'est ce que la dérogation du lab documente (justification, date d'expiration). Elle cessera de
    signaler quand une version de SR Linux acceptera l'authentification d'une instance OSPFv3."""
    return _keychain_violations(rule, device, cfg, "ospf-v3", "OSPFv3")


def _keychain_violations(rule: Rule, device: DeviceState, cfg, version: str, label: str) -> list[Violation]:
    """Toute interface OSPF active (non passive) doit référencer une keychain d'authentification
    existante et de type ospf (Phase A, O1). SR Linux n'a pas de mot de passe inline sur
    l'interface (contrairement à FRR) : l'authentification est une keychain nommée, définie à
    part sous /system authentication (schéma YANG vérifié en direct par sondage : seuls
    'cleartext' et 'md5' sont des algorithmes valides pour un type 'ospf' -- 'hmac-md5' est
    réservé à isis, refusé au commit pour ospf/tcp-md5). Vérifié en interopérabilité réelle
    avec FRR (message-digest-key md5) sur le lien r4<->r5 : MD5 classique s'établit en Full des
    deux côtés ; c'est le seul algorithme commun aux deux constructeurs pour OSPF (FRR
    n'implémente que le MD5 classique RFC 2328 Appendix D, aucune variante HMAC-SHA).

    Seules la présence et la référence comptent : la forme de la clé (en clair dans le fichier de
    démarrage, `$aes1$` sur l'équipement) n'est jamais lue."""
    config = _config(cfg)
    keychains: dict[str, list[tuple[str, ...]]] = {}
    for line in config.select("system", "authentication", "keychain", "*"):
        keychains.setdefault(line.path[3], []).append(line.path[4:])
    violations = []
    for name, rest in _ospf_interfaces(config, version).items():
        if _is_passive(rest):
            continue  # pas d'adjacence sur une interface passive : rien à authentifier
        reference = next((r[2] for r in rest if r[:2] == ("authentication", "keychain") and len(r) == 3),
                         None)
        if reference is None:
            violations.append(Violation(rule, device.name,
                f"interface {label} {name} active (non passive) sans authentification "
                f"(aucune keychain référencée)", name))
        elif reference not in keychains:
            violations.append(Violation(rule, device.name,
                f"interface {label} {name} référence la keychain '{reference}', "
                f"introuvable sous /system authentication", name))
        elif ("type", "ospf") not in keychains[reference]:
            violations.append(Violation(rule, device.name,
                f"interface {label} {name} référence la keychain '{reference}', "
                f"qui n'est pas de type ospf", name))
    return violations


def _check_srlinux_login_banner_present(rule: Rule, device: DeviceState, cfg) -> list[Violation]:
    """Une bannière de connexion doit être configurée. Elle se lit sur le CHEMIN : le mot-clé `login-banner`
    suivi de son texte, identique dans les deux syntaxes (accolades de « info from running » et ligne
    `set / system banner login-banner "..."` du fichier de démarrage) : aucune expression régulière sur le
    texte, donc aucune forme à reconstruire pour que `check --config-dir` donne le verdict du direct (A5).
    Le préfixe `system banner` n'est volontairement pas exigé : la v0.3.0 voyait la bannière même quand le
    marqueur de section de la collecte manquait, et le gel le compare (une configuration ainsi abîmée est de
    toute façon signalée par l'analyse). Le message de la v0.3.0 citait l'expression régulière de la règle ;
    il dit maintenant ce qui manque (le verdict et le code ne changent pas)."""
    if any("login-banner" in line.path[:-1] for line in _config(cfg).flat):
        return []
    return [Violation(rule, device.name, "aucune bannière de connexion (login-banner) configurée",
                      "login-banner")]


CHECKS: dict[str, Check] = {
    "srlinux_login_banner_present": Check(_check_srlinux_login_banner_present),
    "srlinux_interface_mtu_margin": Check(_check_srlinux_interface_mtu_margin),
    "srlinux_ospf_interface_type_point_to_point": Check(_check_srlinux_ospf_interface_type_point_to_point),
    "srlinux_ospf_authentication_required": Check(_check_srlinux_ospf_authentication_required),
    "srlinux_ospf6_authentication_required": Check(_check_srlinux_ospf6_authentication_required),
}
