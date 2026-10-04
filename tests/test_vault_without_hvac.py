"""Chemin « hvac absent » : `hvac` est un extra optionnel, et la CI installe `.[dev]` (donc `hvac` y est).
Ces tests BLOQUENT l'import de `hvac` (et de `requests`) pour prouver, sans dépendre de ce qui est installé :

- Vault configuré mais `hvac` absent : code 3, UN message clair (`pip install 'netcheck[vault]'`),
  aucune connexion, aucun repli sur `LAB_PASS` ni sur l'inventaire ;
- Vault non configuré : `hvac` n'est jamais importé, netcheck marche sans lui ;
- aucun module de netcheck n'importe `hvac` ou `requests` au niveau du module.

Pas de `pytest.importorskip` : ce fichier doit tourner partout.
"""

from __future__ import annotations

import ast
import os
import socket
import subprocess
import sys

import pytest

from netcheck import cli, collector, credentials, inventory, snapshot, vault

REAL_INTENT = str(inventory.REPO_ROOT / "intents" / "lab.yml")  # avant tout patch de REPO_ROOT
LAB_PASSWORD = "lab-pass-from-LAB_PASS"
INVENTORY_PASSWORD = "inventory-password-xyz"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")):
            monkeypatch.delenv(var, raising=False)


@pytest.fixture
def no_hvac(monkeypatch):
    """`import hvac` et `import requests` lèvent ImportError, comme sur une installation sans l'extra."""
    for name in list(sys.modules):
        if name == "hvac" or name.startswith("hvac.") or name == "requests" or name.startswith("requests."):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "hvac", None)
    monkeypatch.setitem(sys.modules, "requests", None)
    with pytest.raises(ImportError):
        import hvac  # noqa: F401


@pytest.fixture
def listener():
    """Un port qui écoute : toute connexion de netcheck y serait vue."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    sock.setblocking(False)
    yield sock
    sock.close()


def _connections(listener) -> int:
    count = 0
    while True:
        try:
            listener.accept()[0].close()
            count += 1
        except BlockingIOError:
            return count


def _secret_id(tmp_path):
    path = tmp_path / "secret_id"
    path.write_text("secret-id-SENTINEL-0123\n", encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def _vault_env(tmp_path, listener):
    return {
        vault.ENV_ADDR: f"http://127.0.0.1:{listener.getsockname()[1]}",
        vault.ENV_ROLE_ID: "role",
        vault.ENV_SECRET_ID_FILE: _secret_id(tmp_path),
        vault.ENV_PATH: "netcheck/lab",
    }


def test_lookup_without_hvac_is_a_clear_error_and_connects_nowhere(no_hvac, tmp_path, listener):
    env = {**_vault_env(tmp_path, listener), "LAB_PASS": LAB_PASSWORD}
    with pytest.raises(vault.VaultError, match=r"netcheck\[vault\]"):
        credentials.resolve("PASS", "frr", INVENTORY_PASSWORD, "r1", environ=env)
    assert _connections(listener) == 0


def test_the_error_is_a_credential_error_so_the_cli_exits_3(no_hvac):
    assert issubclass(vault.VaultError, credentials.CredentialError)


def _inventory(tmp_path):
    path = tmp_path / "inv.yml"
    path.write_text(
        "lab: true\n"
        f"defaults: {{device_type: linux, username: u, password: {INVENTORY_PASSWORD}}}\n"
        "routers:\n  r1: {host: 192.0.2.1}\n",
        encoding="utf-8",
    )
    return str(path)


@pytest.mark.parametrize("command", ["snapshot", "check", "assert", "monitor"])
def test_cli_without_hvac_exits_3_with_one_clear_line_and_no_collection(
    command, no_hvac, monkeypatch, tmp_path, listener, capsys
):
    for name, value in _vault_env(tmp_path, listener).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("LAB_PASS", LAB_PASSWORD)
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)

    def never(*_a, **_k):
        raise AssertionError("aucune collecte ne doit avoir lieu")

    monkeypatch.setattr(collector, "collect_all", never)
    inv = _inventory(tmp_path)
    if command == "monitor":
        snapshot.save("base", {})
    argv = {
        "snapshot": ["snapshot", "s", "-i", inv],
        "check": ["check", "-i", inv],
        "assert": ["assert", "--intent", REAL_INTENT, "-i", inv],
        "monitor": ["monitor", "--baseline", "base", "-i", inv],
    }[command]
    assert cli.main(argv) == 3
    captured = capsys.readouterr()
    lines = [ln for ln in captured.err.splitlines() if ln.strip()]
    assert len(lines) == 1 and "netcheck[vault]" in lines[0] and "Traceback" not in captured.err
    assert (
        LAB_PASSWORD not in captured.out + captured.err
        and INVENTORY_PASSWORD not in captured.out + captured.err
    )
    assert _connections(listener) == 0  # ni Vault, ni routeur


def test_offline_commands_and_unconfigured_vault_never_import_hvac(no_hvac, tmp_path, monkeypatch, capsys):
    # Vault non configuré : le niveau Vault ne touche jamais hvac.
    assert credentials.resolve("PASS", "frr", INVENTORY_PASSWORD, "r1", environ={})[0] == INVENTORY_PASSWORD
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    snapshot.save("base", {})
    assert cli.main(["list"]) == 0
    capsys.readouterr()


def test_hvac_is_never_imported_at_module_level():
    root = inventory.REPO_ROOT / "netcheck"
    offenders = []
    for path in root.rglob("*.py"):
        if ".venv" in path.parts:
            continue
        for node in ast.parse(path.read_text(encoding="utf-8")).body:  # niveau module seulement
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n.split(".")[0] in ("hvac", "requests") for n in names):
                offenders.append(str(path.relative_to(root)))
    assert offenders == []


def test_real_process_without_hvac_exits_3(tmp_path, listener):
    """Processus réel, import de hvac bloqué par un finder (comme une installation sans l'extra)."""
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in ('hvac', 'requests'):\n"
        "            raise ModuleNotFoundError(name)\n"
        "sys.meta_path.insert(0, Block())\n"
        "from netcheck import cli\n"
        f"sys.exit(cli.main(['snapshot', 'zz-no-hvac', '-i', {_inventory(tmp_path)!r}]))\n"
    )
    environ = {k: v for k, v in os.environ.items() if not k.startswith(("NETCHECK_", "LAB_"))}
    environ.update(_vault_env(tmp_path, listener))
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        cwd=inventory.REPO_ROOT,
        env=environ,
    )
    assert result.returncode == 3, result.stderr
    lines = [ln for ln in result.stderr.splitlines() if ln.strip()]
    assert len(lines) == 1 and "netcheck[vault]" in lines[0]
    assert _connections(listener) == 0
    assert not (inventory.REPO_ROOT / "snapshots" / "zz-no-hvac").exists()


def test_hvac_is_checked_before_the_secret_id_file_is_even_read(no_hvac, tmp_path, listener):
    # Un secret_id mal protégé aurait donné « droits 644 » : le message hvac passe donc en premier.
    env = _vault_env(tmp_path, listener)
    (tmp_path / "secret_id").chmod(0o644)
    with pytest.raises(vault.VaultError, match=r"netcheck\[vault\]"):
        vault.lookup("PASS", "frr", env)
    assert _connections(listener) == 0
