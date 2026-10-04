"""Interface commune que doit implémenter un driver constructeur.

Pour ajouter un nouveau driver (ex. Cisco IOS, FortiGate) :

1. Créer `drivers/<constructeur>.py` avec une classe héritant de `Driver`.
2. Définir `REQUIRED_COMMANDS` : les commandes "logiques" de la liste blanche
   (`netcheck.collector.ALLOWED_COMMANDS`) que ce driver sait produire. Toutes ne sont pas
   obligatoires (ex. un pare-feu n'a pas d'OSPF) : `parse()` doit alors renvoyer des listes vides
   pour les données qu'il ne collecte pas.
3. Implémenter `translate(commande_logique) -> commande_cli_réelle` : par exemple, FRR préfixe
   chaque commande par `vtysh -c`.
4. Implémenter `parse(raw, name, host) -> DeviceState` (netcheck/model.py), en gérant les
   variations de format entre versions du même OS (voir FrrDriver.parse pour un exemple avec
   les clés `nbrState`/`state`).
5. Optionnel : surcharger `clean_output()` pour retirer un bruit propre au constructeur avant
   analyse (avertissements non bloquants, bannières, etc.).
6. Phase A de la v4 : fournir ses règles de configuration. `parse_config()` analyse le texte de la
   running-config avec `netcheck/confparse.py` (la syntaxe du constructeur : indentation,
   accolades, lignes `set`), et `CONFIG_CHECKS` associe chaque `kind` de règle YAML que ce driver
   sait évaluer à son évaluateur (voir `drivers/frr_rules.py`). Un `kind` absent de
   `CONFIG_CHECKS` rend la règle « non implémentée par ce driver » dans les rapports, jamais
   « conforme ».

Rien en dehors de `drivers/` ne doit connaître la syntaxe d'un constructeur particulier :
`collector.py`, `diff.py`, `compliance.py` et `report.py` ne travaillent que sur le modèle
normalisé (`netcheck/model.py`) et sur les évaluateurs que les drivers fournissent.
"""
from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import ClassVar

from netcheck.confparse import ParsedConfig
from netcheck.model import DeviceState
from netcheck.ruletypes import Check

_IPV6_TOKEN = re.compile(r"[0-9A-Fa-f:.]{2,}(?:/[0-9]{1,3})?")


def has_ipv6_literal(text: str) -> bool:
    """Vrai si le texte contient une adresse ou un préfixe IPv6 (`2001:db8::1/64`, `::/0`). Un candidat doit
    être une vraie adresse IPv6 (module `ipaddress`) : une adresse MAC, une heure, une communauté BGP
    (`65001:100`) ne comptent pas."""
    for match in _IPV6_TOKEN.finditer(text):
        try:
            ipaddress.IPv6Interface(match.group(0))
        except ValueError:
            continue
        return True
    return False


class Driver(ABC):
    """Contrat commun à tous les drivers."""

    #: Commandes logiques nécessaires à ce driver, prises dans la liste blanche du collecteur.
    REQUIRED_COMMANDS: list[str] = []

    #: Phase F (3e constructeur) : l'équipement ouvre la session en mode utilisateur et exige
    #: `enable` pour lire la configuration (Arista EOS : `show running-config` répond « %
    #: Invalid input (privileged mode required) » sinon). Le collecteur appelle alors la
    #: méthode `enable()` de Netmiko, jamais `send_command("enable")`.
    NEEDS_ENABLE: bool = False

    #: Phase F : liste blanche des commandes CLI RÉELLES, en correspondance EXACTE de la chaîne
    #: complète (None = pas de contrôle supplémentaire : FRR et SR Linux, historique). La liste
    #: blanche des commandes LOGIQUES du collecteur ne voit pas ce que `translate()` fabrique ;
    #: ce second contrôle, lui, porte sur ce qui part réellement vers l'équipement.
    ALLOWED_CLI: frozenset[str] | None = None

    #: Phase A (v4) : évaluateurs de configuration de ce driver, {kind de règle: Check}. Vide par
    #: défaut : le driver n'implémente alors aucun kind propre à un constructeur (les kinds neutres,
    #: `line_present`, `line_absent` et `interface_description_required`, sont dans le moteur).
    CONFIG_CHECKS: ClassVar[dict[str, Check]] = {}

    #: Phase A5 : noms de fichier de configuration que ce driver reconnaît dans un dossier d'équipement
    #: (`check --config-dir dossier/<équipement>/<fichier>`), quand le dossier en contient plusieurs.
    CONFIG_FILENAMES: ClassVar[tuple[str, ...]] = ()

    #: Phase A5 : premiers mots des lignes de PREMIER niveau d'une vraie configuration de cet équipement
    #: (`hostname`, `interface`, `router`...). `check --config-dir` ne l'audite que si au moins la moitié de
    #: ses lignes de premier niveau en commencent par l'un d'eux (sinon : un fichier de notes lu avec
    #: `--driver` serait « conforme ») et signale en information les autres. None = pas de contrôle (à
    #: éviter : un driver sans liste accepte n'importe quel texte).
    ROOT_KEYWORDS: ClassVar[frozenset[str] | None] = None

    #: Phase B4 : débuts de ligne (indentation retirée) qui montrent que l'IPv6 est configuré même sans
    # qu'aucune adresse IPv6 n'apparaisse (`router ospf6`, `address-family ipv6`...). Les adresses, elles,
    # sont reconnues quel que soit le constructeur (`has_ipv6_literal`).
    IPV6_CONFIG_PREFIXES: ClassVar[tuple[str, ...]] = ()

    def config_uses_ipv6(self, running_config: str) -> bool:
        """La configuration utilise-t-elle l'IPv6 ? (adresse ou préfixe IPv6, ou ligne de
        IPV6_CONFIG_PREFIXES). Sert à dire, en information, qu'aucune règle IPv6 ne couvre un équipement
        qui en a (`check`)."""
        if has_ipv6_literal(running_config):
            return True
        prefixes = self.IPV6_CONFIG_PREFIXES
        lines = (line.lstrip() for line in running_config.splitlines())
        return bool(prefixes) and any(line.startswith(prefixes) for line in lines)

    def parse_config(self, running_config: str) -> ParsedConfig | None:
        """Analyse structurée de la running-config (voir `netcheck/confparse.py`), ou None si ce
        driver n'analyse pas la configuration. Ne lève jamais : une ligne douteuse devient un
        avertissement, repris dans le rapport de conformité."""
        return None

    def translate(self, command: str) -> str:
        """Traduit une commande logique (ex. 'show ip route json') en commande CLI réelle."""
        return command

    def check_cli(self, cli: str) -> None:
        """Refuse (PermissionError) toute commande CLI réelle hors de ALLOWED_CLI quand ce
        driver en déclare une. Appelé par le collecteur avant la connexion, puis avant chaque
        envoi."""
        if self.ALLOWED_CLI is not None and cli not in self.ALLOWED_CLI:
            raise PermissionError(f"commande CLI hors liste blanche exacte du driver : {cli!r}")

    def clean_output(self, raw: str) -> str:
        """Retire un bruit propre au constructeur avant analyse (par défaut : rien à faire)."""
        return raw

    @abstractmethod
    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        """Transforme les sorties brutes {commande_logique: texte} en DeviceState."""

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
