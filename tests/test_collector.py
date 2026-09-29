"""Vérifie la contrainte C1 (lecture seule) : une commande hors liste blanche est refusée.
Vérifie aussi l'attente de convergence utilisée par `guard --wait` (§5.5)."""
from unittest.mock import MagicMock

import pytest

from netcheck import collector
from netcheck.drivers.base import Driver
from netcheck.drivers.frr import FrrDriver
from netcheck.drivers.srlinux import SrlinuxDriver
from netcheck.model import BgpPeer, DeviceState, OspfNeighbor


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


class _FakeDriver(Driver):
    """Driver minimal pour vérifier ce que collect() fait de state.driver (Phase D2), sans
    ouvrir de vraie connexion SSH."""
    REQUIRED_COMMANDS = ["show running-config"]

    def parse(self, raw, name, host) -> DeviceState:
        return DeviceState(name=name, host=host, timestamp="t", reachable=True)


def test_collect_sets_state_driver_from_router_inventory_field(monkeypatch):
    """Phase D2 : compliance.py filtre les règles par DeviceState.driver -- collect() doit le
    renseigner d'après le champ "driver" de l'inventaire, pas d'après le type de l'instance
    driver reçue (utile quand un appelant impose un driver explicite, ex. les tests)."""
    fake_conn = MagicMock()
    fake_conn.send_command.return_value = "{}"
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=fake_conn))

    router = {**_router(), "driver": "srlinux"}
    state = collector.collect(router, _FakeDriver())
    assert state.driver == "srlinux"


def test_collect_defaults_state_driver_to_frr_when_field_absent(monkeypatch):
    fake_conn = MagicMock()
    fake_conn.send_command.return_value = "{}"
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=fake_conn))

    state = collector.collect(_router(), _FakeDriver())  # pas de champ "driver"
    assert state.driver == "frr"


def test_ensure_allowed_accepts_known_commands():
    collector._ensure_allowed(["show ip route json", "show running-config"])  # ne lève rien


def test_ensure_allowed_rejects_unknown_command():
    with pytest.raises(PermissionError, match="configure terminal"):
        collector._ensure_allowed(["configure terminal"])


# -- Registre de drivers (Phase D1) ----------------------------------------------------------

@pytest.mark.parametrize("driver_cls", [FrrDriver, SrlinuxDriver])
def test_whitelist_covers_every_registered_driver(driver_cls):
    """Liste blanche vérifiée pour CHAQUE driver du registre, pas seulement FRR : un driver
    mal écrit qui demanderait une commande hors liste doit être détectable statiquement."""
    assert set(driver_cls().REQUIRED_COMMANDS) <= collector.ALLOWED_COMMANDS


def test_resolve_driver_defaults_to_frr_when_field_absent():
    router = {"name": "r1"}  # pas de champ "driver" : comportement historique inchangé
    assert isinstance(collector._resolve_driver(router), FrrDriver)


def test_resolve_driver_uses_srlinux_when_specified():
    router = {"name": "r5", "driver": "srlinux"}
    assert isinstance(collector._resolve_driver(router), SrlinuxDriver)


def test_resolve_driver_raises_clear_error_on_unknown_driver():
    router = {"name": "r9", "driver": "cisco_ios"}
    with pytest.raises(ValueError, match="r9.*cisco_ios"):
        collector._resolve_driver(router)


def test_collect_resolves_driver_automatically_per_router(monkeypatch):
    """collect() sans driver explicite : résout via le registre, applique quand même la liste
    blanche avant toute connexion (même garantie que pour un driver passé explicitement)."""
    connect = MagicMock(side_effect=AssertionError("ConnectHandler ne doit jamais être appelé"))
    monkeypatch.setattr(collector, "ConnectHandler", connect)
    monkeypatch.setattr(collector, "DRIVER_REGISTRY", {"rogue": _RogueDriver})

    with pytest.raises(PermissionError):
        collector.collect({**_router(), "driver": "rogue"})
    connect.assert_not_called()


# -- Convergence (guard --wait) -------------------------------------------------------------

def _state(ospf_full=2, bgp=None) -> DeviceState:
    neighbors = [OspfNeighbor(f"10.0.0.{i}", "Full/-", "eth1") for i in range(ospf_full)]
    peers = [BgpPeer(ip, 65000, state, pfx, pfx) for ip, (state, pfx) in (bgp or {}).items()]
    return DeviceState(name="r1", host="10.0.0.1", timestamp="t", reachable=True,
                        ospf_neighbors=neighbors, bgp_peers=peers)


_ROUTERS = {"r3": {"name": "r3", "ospf_neighbors": 2, "bgp_peers": {"172.16.34.2": 2}}}


def test_converged_true_when_ospf_full_and_bgp_established_with_enough_prefixes():
    results = {"r3": (True, _state(ospf_full=2, bgp={"172.16.34.2": ("Established", 2)}))}
    assert collector._converged(results, _ROUTERS) is True


def test_converged_false_when_ospf_neighbor_missing():
    results = {"r3": (True, _state(ospf_full=1, bgp={"172.16.34.2": ("Established", 2)}))}
    assert collector._converged(results, _ROUTERS) is False


def test_converged_false_when_bgp_not_established():
    results = {"r3": (True, _state(ospf_full=2, bgp={"172.16.34.2": ("Active", 0)}))}
    assert collector._converged(results, _ROUTERS) is False


def test_converged_false_when_device_unreachable():
    results = {"r3": (False, "TimeoutError: ...")}
    assert collector._converged(results, _ROUTERS) is False


def test_wait_for_convergence_returns_true_immediately_when_already_converged(monkeypatch):
    monkeypatch.setattr(collector, "collect_all",
        lambda routers, driver, workers=5: {"r3": (True, _state(bgp={"172.16.34.2": ("Established", 2)}))})
    sleeps = []
    monkeypatch.setattr(collector.time, "sleep", lambda s: sleeps.append(s))

    assert collector.wait_for_convergence(_ROUTERS, driver=object(), timeout=10) is True
    assert sleeps == []  # convergé dès le premier essai : jamais entré dans l'attente


def test_wait_for_convergence_returns_false_after_timeout_without_fixed_sleep(monkeypatch):
    # Toujours pas convergé : jamais de pause fixe unique, on repasse par la boucle de sondage.
    monkeypatch.setattr(collector, "collect_all",
        lambda routers, driver, workers=5: {"r3": (True, _state(ospf_full=0))})
    ticks = iter([0, 1, 2, 3, 11])  # dépasse timeout=10 au 5e relevé de l'horloge
    monkeypatch.setattr(collector.time, "monotonic", lambda: next(ticks))
    sleeps = []
    monkeypatch.setattr(collector.time, "sleep", lambda s: sleeps.append(s))

    assert collector.wait_for_convergence(_ROUTERS, driver=object(), timeout=10, interval=2) is False
    assert sleeps and all(s == 2 for s in sleeps)  # attente par petits pas, pas un unique sleep(10)
