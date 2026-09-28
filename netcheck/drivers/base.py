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

Rien en dehors de `drivers/` ne doit connaître la syntaxe d'un constructeur particulier :
`collector.py`, `diff.py`, `compliance.py` et `report.py` ne travaillent que sur le modèle
normalisé (`netcheck/model.py`).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from netcheck.model import DeviceState


class Driver(ABC):
    """Contrat commun à tous les drivers."""

    #: Commandes logiques nécessaires à ce driver, prises dans la liste blanche du collecteur.
    REQUIRED_COMMANDS: list[str] = []

    def translate(self, command: str) -> str:
        """Traduit une commande logique (ex. 'show ip route json') en commande CLI réelle."""
        return command

    def clean_output(self, raw: str) -> str:
        """Retire un bruit propre au constructeur avant analyse (par défaut : rien à faire)."""
        return raw

    @abstractmethod
    def parse(self, raw: dict[str, str], name: str, host: str) -> DeviceState:
        """Transforme les sorties brutes {commande_logique: texte} en DeviceState."""

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
