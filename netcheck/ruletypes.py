"""Types partagés par le moteur de conformité et par les drivers (SPEC_v4, Phase A3).

Ils vivent ici, et non dans `compliance.py`, pour que les drivers puissent fournir leurs propres
évaluateurs de configuration sans importer le moteur (qui importe les drivers : un cycle sinon).
`compliance.py` les ré-exporte, donc `compliance.Rule`, `compliance.Violation`... continuent de
fonctionner pour tout l'existant.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from netcheck.confparse import ParsedConfig, ParseWarning
from netcheck.model import DeviceState


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
    # Phase B3 : l'OBJET du constat (interface, voisin BGP, API de gestion...), sous une forme exacte et
    # stable que les dérogations visent (`targets: [{device, object}]`). None = pas d'objet identifiable :
    # une dérogation ne peut pas couvrir cette violation. Jamais un texte libre : le nom de l'interface,
    # l'IP du voisin.
    subject: str | None = None


# Pourquoi une règle est « non applicable » à un équipement. Les deux causes ne sont JAMAIS
# confondues dans les rapports : l'une est un choix (la règle ne concerne pas ce driver), l'autre
# est un trou de couverture (la règle concerne ce driver, mais il ne sait pas l'évaluer).
CAUSE_DRIVER = "driver"                    # `drivers:` de la règle ne liste pas ce driver
CAUSE_NOT_IMPLEMENTED = "not_implemented"  # le driver n'implémente pas le kind de la règle
# Hors ligne (`check --config-dir`), seule la configuration existe : une règle qui lit le MODÈLE collecté
# (interfaces...) ne peut pas être évaluée. Ce n'est ni un choix ni un trou du driver : un manque de données.
CAUSE_NO_MODEL = "no_model"


@dataclass
class NotApplicable:
    """Une règle qui ne concerne pas cet équipement : ni conforme, ni violation, un troisième
    état à part entière -- voir compliance.evaluate_config() et verdict()."""
    rule: Rule
    device: str
    reason: str
    cause: str = CAUSE_DRIVER


@dataclass(frozen=True)
class ConfigWarning:
    """Une ligne de configuration que l'analyse n'a pas pu classer proprement (SPEC_v4, A3) :
    `kept=False` = ligne NON lue (l'audit ne peut plus dire « conforme ») ; `kept=True` = ligne lue mais
    ambiguë (information), sauf si `blocks_verdict` (structure incertaine : lue, mais l'audit ne peut pas
    pour autant conclure « conforme »). Le texte est déjà masqué (confparse)."""
    device: str
    warning: ParseWarning

    @property
    def kept(self) -> bool:
        return self.warning.kept

    @property
    def blocks_verdict(self) -> bool:
        """Vrai si l'audit ne peut pas conclure « conforme » : ligne non lue, ou structure incertaine."""
        return self.warning.blocks_verdict


# Évaluateur de configuration fourni par un driver : (règle, équipement, configuration analysée).
# `config` est le résultat de `Driver.parse_config` (None si le driver n'analyse pas la configuration).
CheckFn = Callable[[Rule, DeviceState, ParsedConfig | None], list[Violation]]


@dataclass(frozen=True)
class Check:
    """Un évaluateur et ce qu'il lit : `needs` vaut {"config"} (la configuration seule) ou y ajoute
    "interfaces" (le modèle collecté). Hors ligne (`check --config-dir`), seule la configuration
    existe : une règle qui lit le modèle y est « non applicable » (Phase A5).

    `ipv6` (Phase B4) : l'évaluateur juge un objet PROPRE à l'IPv6 (ex. l'authentification OSPFv3). `check`
    s'en sert pour dire qu'aucune règle IPv6 ne s'applique à un équipement qui utilise l'IPv6."""
    fn: CheckFn
    needs: frozenset[str] = frozenset({"config"})
    ipv6: bool = False
