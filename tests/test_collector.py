"""Vérifie la contrainte C1 (lecture seule) : une commande hors liste blanche est refusée."""
from unittest.mock import MagicMock

import pytest

from netcheck import collector
from netcheck.drivers.base import Driver
from netcheck.model import DeviceState


class _RogueDriver(Driver):
    """Driver fictif qui tente une commande de configuration : ne doit jamais s'exécuter."""
    REQUIRED_COMMANDS = ["show running-config", "configure terminal"]

    def parse(self, raw, name, host) -> DeviceState:
        raise AssertionError("parse() ne doit jamais être appelé : le refus doit être plus tôt")


def _router() -> dict:
    return {"device_type": "linux", "host": "203.0.113.1", "username": "u", "password": "p", "name": "r1"}


def test_collect_refuses_command_outside_whitelist_without_connecting(monkeypatch):
    """Le refus doit intervenir avant toute connexion SSH (pas seulement avant l'envoi)."""
    connect = MagicMock(side_effect=AssertionError("ConnectHandler ne doit jamais être appelé"))
    monkeypatch.setattr(collector, "ConnectHandler", connect)

    with pytest.raises(PermissionError):
        collector.collect(_router(), _RogueDriver())

    connect.assert_not_called()


def test_ensure_allowed_accepts_known_commands():
    collector._ensure_allowed(["show ip route json", "show running-config"])  # ne lève rien


def test_ensure_allowed_rejects_unknown_command():
    with pytest.raises(PermissionError, match="configure terminal"):
        collector._ensure_allowed(["configure terminal"])
