"""Résolution des identifiants de l'inventaire (netcheck/inventory.py).

Sur un inventaire mixte (Phase D1), NETCHECK_USER/PASS ne doit PAS écraser aveuglément tous les
routeurs quel que soit leur driver : un opérateur qui positionne NETCHECK_USER/PASS pour cibler
les routeurs FRR ne doit pas casser les identifiants SR Linux de r5, et inversement. Vérifié ici
avec un vrai fichier YAML (tmp_path), pas des dicts construits à la main, pour exercer le vrai
chemin de code de `load()` (fusion defaults + attrs, filtrage `only`, tout).
"""
from netcheck import inventory

YAML_MIXTE = """
defaults:
  device_type: linux
  username: netops
  password: netops
routers:
  r1: {host: 172.20.21.11}
  r5: {host: 172.20.21.15, driver: srlinux, username: admin, password: NokiaSrl1!}
"""


def _clear_credential_env(monkeypatch):
    for var in ("NETCHECK_USER", "NETCHECK_PASS", "LAB_USER", "LAB_PASS",
                "NETCHECK_SRLINUX_USER", "NETCHECK_SRLINUX_PASS",
                "NETCHECK_FRR_USER", "NETCHECK_FRR_PASS"):
        monkeypatch.delenv(var, raising=False)


def _write_inventory(tmp_path):
    path = tmp_path / "inventory-mixte.yml"
    path.write_text(YAML_MIXTE, encoding="utf-8")
    return path


def test_no_env_var_keeps_inventory_credentials_per_router(tmp_path, monkeypatch):
    _clear_credential_env(monkeypatch)
    inv = inventory.load(path=_write_inventory(tmp_path))
    assert inv.routers["r1"]["username"] == "netops"
    assert inv.routers["r5"]["username"] == "admin"
    assert inv.routers["r5"]["password"] == "NokiaSrl1!"


def test_generic_netcheck_env_overrides_every_router_regardless_of_driver(tmp_path, monkeypatch):
    # Comportement historique conservé : NETCHECK_USER/PASS reste une bascule globale quand
    # aucune variable plus spécifique n'est positionnée.
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("NETCHECK_USER", "generic-user")
    monkeypatch.setenv("NETCHECK_PASS", "generic-pass")
    inv = inventory.load(path=_write_inventory(tmp_path))
    assert inv.routers["r1"]["username"] == "generic-user"
    assert inv.routers["r5"]["username"] == "generic-user"
    assert inv.routers["r5"]["password"] == "generic-pass"


def test_per_driver_env_var_does_not_leak_to_other_drivers(tmp_path, monkeypatch):
    # Le bug signalé : sans variable par driver, NETCHECK_USER/PASS écraserait aussi r5. Ici,
    # NETCHECK_SRLINUX_USER/PASS protège r5 tout en laissant r1 recevoir le générique.
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("NETCHECK_USER", "frr-user")
    monkeypatch.setenv("NETCHECK_PASS", "frr-pass")
    monkeypatch.setenv("NETCHECK_SRLINUX_USER", "srl-user")
    monkeypatch.setenv("NETCHECK_SRLINUX_PASS", "srl-pass")
    inv = inventory.load(path=_write_inventory(tmp_path))

    assert inv.routers["r1"]["username"] == "frr-user"
    assert inv.routers["r1"]["password"] == "frr-pass"
    assert inv.routers["r5"]["username"] == "srl-user"
    assert inv.routers["r5"]["password"] == "srl-pass"


def test_lab_user_pass_still_works_as_legacy_fallback(tmp_path, monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("LAB_USER", "legacy-user")
    monkeypatch.setenv("LAB_PASS", "legacy-pass")
    inv = inventory.load(path=_write_inventory(tmp_path))
    assert inv.routers["r1"]["username"] == "legacy-user"
    assert inv.routers["r5"]["username"] == "legacy-user"  # pas de var srlinux : generique s'applique


def test_priority_order_most_specific_wins(tmp_path, monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("LAB_USER", "legacy-user")
    monkeypatch.setenv("NETCHECK_USER", "generic-user")
    monkeypatch.setenv("NETCHECK_SRLINUX_USER", "srl-user")
    inv = inventory.load(path=_write_inventory(tmp_path))
    assert inv.routers["r5"]["username"] == "srl-user"    # le plus specifique
    assert inv.routers["r1"]["username"] == "generic-user"  # pas de var frr : generique
