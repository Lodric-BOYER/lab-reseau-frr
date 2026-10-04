"""Test sentinelle (phase C2) : une valeur de mot de passe connue ne doit apparaître NULLE PART.

Une valeur sentinelle sert de mot de passe, tour à tour par variable d'environnement, par fichier 0600 et
par l'inventaire. Toutes les commandes qui collectent (snapshot, check, assert, guard, monitor) tournent de
bout en bout, en mode « tout réussit » puis en mode « tout échoue avec une exception qui recopie le mot de
passe » (ce que ferait une bibliothèque maladroite). Rien ne doit contenir la sentinelle : sortie standard
et d'erreur, journaux, fichiers écrits (snapshots, rapports JSON et HTML, état et rapports de monitor,
journal de guard), message d'alerte envoyé au webhook. Le test prouve aussi que la sentinelle a bien été
fournie à la connexion (sinon il serait vide de sens) et que la source de l'identifiant est dite.

Limite : seule la valeur EXACTE est cherchée (pas une forme encodée en base64 ou en pourcentage).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netcheck import cli, collector, credentials, inventory, secrets, snapshot, webhook
from netcheck.drivers.frr import FrrDriver
from netcheck.model import DeviceState
from netcheck.secrets import SecretStr

SENTINEL = "SENTINEL-PASSWORD-5f3a9c1e7b"
WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/SENTINELWEBHOOK0123456789"
INTENT = inventory.REPO_ROOT / "intents" / "lab.yml"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="droits POSIX")


class _FakeDriver(FrrDriver):
    """Le vrai driver FRR (ses règles, ses vérifications de commande) mais une seule commande et aucun
    analyseur : la collecte ne dépend d'aucune sortie d'équipement."""
    REQUIRED_COMMANDS = ["show running-config"]

    def parse(self, raw, name, host) -> DeviceState:
        return DeviceState(name=name, host=host, timestamp="2026-10-05T00:00:00", reachable=True)


class _Network:
    """ConnectHandler factice : réussit, ou échoue avec une exception qui recopie le mot de passe."""

    def __init__(self):
        self.mode = "ok"
        self.passwords: list[str] = []

    def __call__(self, **kwargs):
        self.passwords.append(kwargs["password"])
        if self.mode == "fail":
            raise RuntimeError(f"authentification refusée pour {kwargs['username']} "
                               f"avec le mot de passe {kwargs['password']} (device {kwargs['host']})")
        conn = MagicMock()
        conn.send_command.return_value = "{}"
        return conn


class World:
    def __init__(self, tmp_path: Path, monkeypatch, capsys, caplog):
        self.tmp, self.capsys, self.caplog = tmp_path, capsys, caplog
        self.net = _Network()
        self.alerts: list[tuple[str, dict]] = []
        self.outputs: list[str] = []
        (tmp_path / "snapshots").mkdir()
        (tmp_path / "reports").mkdir()
        monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)   # cmd_snapshot affiche un chemin relatif
        monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
        monkeypatch.setattr(collector, "ConnectHandler", self.net)
        monkeypatch.setitem(collector.DRIVER_REGISTRY, "frr", _FakeDriver)
        monkeypatch.setattr(webhook, "post", self._post)
        monkeypatch.setenv("NETCHECK_WEBHOOK_URL", WEBHOOK)
        monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "known_hosts"))
        for var in list(os.environ):
            if var.startswith(("NETCHECK_USER", "NETCHECK_PASS", "NETCHECK_FRR", "LAB_")):
                monkeypatch.delenv(var, raising=False)
        caplog.set_level(logging.DEBUG)

    def _post(self, url, payload, **_):
        self.alerts.append((url, payload))
        return webhook.SendResult(ok=True, attempts=1)

    def inventory(self, password: str | None) -> str:
        pw = f", password: {password}" if password else ""
        path = self.tmp / "inv.yml"
        path.write_text(f"lab: true\ndefaults: {{device_type: linux, username: netops{pw}}}\n"
                        "routers:\n  r1: {host: 192.0.2.1}\n  r2: {host: 192.0.2.2}\n", encoding="utf-8")
        return str(path)

    def run(self, *argv) -> int:
        code = cli.main(list(argv))
        out = self.capsys.readouterr()
        self.outputs += [out.out, out.err]
        return code

    def everything(self) -> str:
        """Tout ce qui a été produit : sorties, journaux, alertes, et chaque fichier écrit."""
        chunks = list(self.outputs) + [r.getMessage() for r in self.caplog.records]
        chunks += [json.dumps(a, default=repr) for a in self.alerts]
        for path in sorted(self.tmp.rglob("*")):
            if path.is_file() and path.name != "secret-file" and path.name != "inv.yml":
                text = path.read_text(encoding="utf-8", errors="replace")
                chunks.append(f"== {path.relative_to(self.tmp)}\n{text}")
        return "\n".join(chunks)


@pytest.fixture
def world(tmp_path, monkeypatch, capsys, caplog):
    return World(tmp_path, monkeypatch, capsys, caplog)


def _provide(world: World, monkeypatch, how: str) -> tuple[str, str]:
    """Fournit la sentinelle par `how` ; renvoie (fichier d'inventaire, source attendue)."""
    if how == "variable":
        monkeypatch.setenv("NETCHECK_PASS", SENTINEL)
        return world.inventory("mot-de-passe-de-l-inventaire"), "variable NETCHECK_PASS"
    if how == "fichier":
        f = world.tmp / "secret-file"
        f.write_text(SENTINEL + "\n", encoding="utf-8")
        f.chmod(0o600)
        monkeypatch.setenv("NETCHECK_PASS_FILE", str(f))
        return world.inventory("mot-de-passe-de-l-inventaire"), f"fichier {f}"
    return world.inventory(SENTINEL), "inventaire"


def _script(world: World) -> str:
    path = world.tmp / "change.sh"
    path.write_text("true\n", encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("how", ["variable", "fichier", "inventaire"])
@pytest.mark.parametrize("mode", ["ok", "fail"])
def test_the_password_appears_nowhere(how, mode, world, monkeypatch):
    inv, expected_source = _provide(world, monkeypatch, how)
    world.net.mode = "ok"
    # La référence de monitor est prise quand tout fonctionne ; le mode choisi s'applique ensuite.
    assert world.run("snapshot", "base", "-i", inv) == 0
    world.net.mode = mode

    world.run("snapshot", "s1", "-i", inv, "--force")
    world.run("check", "-i", inv, "--json", str(world.tmp / "check.json"),
              "--html", str(world.tmp / "check.html"))
    world.run("assert", "--intent", str(INTENT), "-i", inv, "--json", str(world.tmp / "assert.json"),
              "--html", str(world.tmp / "assert.html"))
    world.run("monitor", "--baseline", "base", "-i", inv, "--state-file", str(world.tmp / "state.json"))
    world.run("guard", "--change", _script(world), "--yes", "--wait", "1", "-i", inv)

    # La sentinelle a bien servi à ouvrir les connexions : sans cela, le test serait vide de sens.
    assert world.net.passwords and set(world.net.passwords) == {SENTINEL}

    everything = world.everything()
    assert SENTINEL not in everything
    # La source de l'identifiant est dite (terminal, JSON), sans la valeur.
    assert f"mot de passe : {expected_source}" in everything
    if mode == "ok":
        assert (world.tmp / "check.json").exists(), world.outputs      # sinon la commande a échoué
        data = json.loads((world.tmp / "check.json").read_text(encoding="utf-8"))
        assert data["credential_sources"]["mot de passe"] == {expected_source: ["r1", "r2"]}
        adata = json.loads((world.tmp / "assert.json").read_text(encoding="utf-8"))
        assert adata["credential_sources"]["mot de passe"] == {expected_source: ["r1", "r2"]}
        meta = json.loads((world.tmp / "snapshots" / "s1" / "meta.json").read_text(encoding="utf-8"))
        assert meta["credential_sources"]["mot de passe"] == {expected_source: ["r1", "r2"]}
        assert expected_source in (world.tmp / "check.html").read_text(encoding="utf-8")
        assert expected_source in (world.tmp / "assert.html").read_text(encoding="utf-8")
    else:
        assert "****" in everything     # l'exception recopiée a été expurgée, pas supprimée en silence
        assert world.alerts, "monitor aurait dû alerter (équipements injoignables)"


def test_monitor_summary_and_alert_carry_no_secret(world, monkeypatch):
    inv, expected_source = _provide(world, monkeypatch, "variable")
    assert world.run("snapshot", "base", "-i", inv) == 0
    world.net.mode = "fail"
    state = str(world.tmp / "st.json")
    assert world.run("monitor", "--baseline", "base", "-i", inv, "--state-file", state) == 2
    summaries = sorted((world.tmp / "reports").rglob("summary.json"))
    assert summaries
    for path in summaries:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["credential_sources"]["mot de passe"] == {expected_source: ["r1", "r2"]}
        assert SENTINEL not in path.read_text(encoding="utf-8")
    assert len(world.alerts) == 1 and SENTINEL not in json.dumps(world.alerts)


def test_collect_all_redacts_an_exception_that_echoes_the_password(world, monkeypatch):
    inv, _ = _provide(world, monkeypatch, "variable")
    world.net.mode = "fail"
    results = collector.collect_all(inventory.load(path=inv).routers)
    assert set(results) == {"r1", "r2"}
    for ok, message in results.values():
        assert ok is False and SENTINEL not in message and "****" in message
        assert "avec le mot de passe ****" in message


def test_router_and_inventory_objects_never_print_the_password(world, monkeypatch):
    inv, _ = _provide(world, monkeypatch, "variable")
    loaded = inventory.load(path=inv)
    router = loaded.routers["r1"]
    assert isinstance(router["password"], SecretStr)
    for text in (repr(loaded), str(loaded), repr(router), str(router), f"{router}", f"{loaded.routers}",
                 json.dumps(router, default=str), json.dumps(router, default=repr)):
        assert SENTINEL not in text, text


def test_report_masking_also_removes_the_registered_password(world, monkeypatch):
    _provide(world, monkeypatch, "variable")
    inventory.load(path=world.inventory(None))
    leaked = f"ligne de configuration {SENTINEL} copiée par erreur"
    assert SENTINEL in leaked
    assert SENTINEL not in secrets.mask_secrets(leaked)          # tout texte publié passe par mask_secrets
    assert SENTINEL not in secrets.redact_known(leaked)


def test_offline_commands_resolve_and_print_no_credentials(world, monkeypatch, capsys):
    inv, _ = _provide(world, monkeypatch, "variable")
    world.net.mode = "ok"
    assert world.run("snapshot", "s", "-i", inv) == 0
    assert world.run("assert", "--intent", str(INTENT), "-i", inv, "--snapshot", "s") in (0, 1, 2)
    out = world.outputs[-2] + world.outputs[-1]
    assert "Identifiants" not in out and SENTINEL not in out      # hors ligne : aucun identifiant résolu
    assert credentials.describe_sources(inventory.load(path=inv, resolve_credentials=False).routers) is None
