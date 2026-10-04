"""Vérification des clés d'hôte SSH (phase C1, netcheck/hostkeys.py).

Un faux serveur SSH local (Paramiko, hôte 127.0.0.1, port aléatoire) présente une clé d'hôte puis
refuse tout mot de passe : le refus d'authentification prouve que l'étape « clé d'hôte » a réussi,
le refus de clé prouve qu'elle a échoué. Aucun équipement, aucun lab.
"""
from __future__ import annotations

import ast
import os
import socket
import threading
from contextlib import contextmanager
from pathlib import Path

import paramiko
import pytest
from netmiko.exceptions import NetmikoAuthenticationException

from netcheck import cli, collector, hostkeys, inventory

PACKAGE = Path(hostkeys.__file__).resolve().parent


class _RefuseAuth(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED


@contextmanager
def ssh_server(key: paramiko.PKey, port: int = 0):
    """Faux serveur SSH sur 127.0.0.1 qui présente `key` et refuse toute authentification."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.2)
    stop = threading.Event()
    transports: list[paramiko.Transport] = []

    def loop():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            transport = paramiko.Transport(conn)
            transport.add_server_key(key)
            transports.append(transport)
            try:
                transport.start_server(server=_RefuseAuth())
            except (paramiko.SSHException, EOFError, OSError):
                pass

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        for t in transports:
            t.close()
        listener.close()


def _key() -> paramiko.PKey:
    return paramiko.ECDSAKey.generate()


def _router(port: int) -> dict:
    return {"device_type": "linux", "host": "127.0.0.1", "port": port, "username": "u", "password": "p",
            "name": "r1"}


def _policy(tmp_path, mode="strict", lab=False) -> hostkeys.HostKeyPolicy:
    return hostkeys.HostKeyPolicy(mode=mode, known_hosts=tmp_path / "kh" / "known_hosts", lab=lab)


@pytest.fixture(autouse=True)
def _reset_policy(monkeypatch):
    hostkeys.set_policy(None)
    monkeypatch.delenv(hostkeys.ENV_MODE, raising=False)
    monkeypatch.delenv(hostkeys.ENV_KNOWN_HOSTS, raising=False)
    yield
    hostkeys.set_policy(None)


def _write_entry(path: Path, host: str, key: paramiko.PKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{host} {key.get_name()} {key.get_base64()}\n")


# -- Résolution de la politique ---------------------------------------------------------------

def test_default_policy_is_strict_with_a_dedicated_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    policy = hostkeys.configure(None, None, lab=False)
    assert policy.mode == "strict"
    assert policy.path == tmp_path / ".netcheck" / "known_hosts"
    assert ".ssh" not in str(policy.path)


def test_cli_option_beats_environment():
    env = {hostkeys.ENV_MODE: "accept-new", hostkeys.ENV_KNOWN_HOSTS: "/tmp/from-env"}
    policy = hostkeys.configure("strict", "/tmp/from-cli", lab=True, environ=env)
    assert policy.mode == "strict"
    assert policy.known_hosts == Path("/tmp/from-cli")


def test_environment_applies_when_no_option():
    env = {hostkeys.ENV_MODE: "accept-new", hostkeys.ENV_KNOWN_HOSTS: "/tmp/from-env"}
    policy = hostkeys.configure(None, None, lab=True, environ=env)
    assert (policy.mode, policy.known_hosts) == ("accept-new", Path("/tmp/from-env"))


def test_unknown_mode_is_refused():
    with pytest.raises(hostkeys.HostKeyError, match="inconnu"):
        hostkeys.configure("ignore", None, lab=True)
    with pytest.raises(hostkeys.HostKeyError, match="inconnu"):
        hostkeys.configure(None, None, lab=True, environ={hostkeys.ENV_MODE: "off"})


def test_there_is_no_ignore_mode():
    assert hostkeys.MODES == ("strict", "accept-new")


def test_accept_new_is_refused_on_a_non_lab_inventory():
    with pytest.raises(hostkeys.HostKeyError, match=r"lab: true"):
        hostkeys.configure("accept-new", None, lab=False)
    with pytest.raises(hostkeys.HostKeyError, match=r"lab: true"):
        hostkeys.configure(None, None, lab=False, environ={hostkeys.ENV_MODE: "accept-new"})


def test_current_without_configuration_is_strict_and_env_cannot_grant_lab(monkeypatch, tmp_path):
    assert hostkeys.current().mode == "strict"
    # Sans la CLI (qui seule connaît `lab`), la variable d'environnement ne suffit pas à apprendre une clé.
    monkeypatch.setenv(hostkeys.ENV_MODE, "accept-new")
    policy = hostkeys.current()
    assert policy.mode == "accept-new" and policy.lab is False
    with pytest.raises(hostkeys.HostKeyError, match="lab"):
        hostkeys.learn("127.0.0.1", 22, policy)


def test_entry_name_follows_openssh():
    assert hostkeys.entry_name("172.20.20.11") == "172.20.20.11"
    assert hostkeys.entry_name("172.20.20.11", 2222) == "[172.20.20.11]:2222"


def test_fingerprint_is_sha256_of_the_key(tmp_path):
    key = _key()
    fp = hostkeys.fingerprint(key)
    assert fp.startswith("SHA256:") and "=" not in fp and len(fp) == 7 + 43


@pytest.mark.skipif(os.name == "nt", reason="droits POSIX")
def test_known_hosts_writable_by_others_is_refused(tmp_path):
    path = tmp_path / "known_hosts"
    path.write_text("", encoding="utf-8")
    path.chmod(0o666)
    with pytest.raises(hostkeys.HostKeyError, match="chmod 600"):
        hostkeys.check_file(path)
    path.chmod(0o660)
    with pytest.raises(hostkeys.HostKeyError):
        hostkeys.check_file(path)   # modifiable par le groupe : refusé
    path.chmod(0o644)
    hostkeys.check_file(path)       # lisible par tous mais modifiable par le seul propriétaire : accepté
    path.chmod(0o600)
    hostkeys.check_file(path)
    hostkeys.check_file(tmp_path / "absent")   # un fichier absent n'est pas une erreur de droits


# -- learn() : premier contact ---------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="droits POSIX")
def test_learn_writes_the_entry_with_private_permissions(tmp_path):
    key = _key()
    policy = _policy(tmp_path, "accept-new", lab=True)
    with ssh_server(key) as port:
        assert hostkeys.learn("127.0.0.1", port, policy) is True
    kh = policy.path
    assert kh.stat().st_mode & 0o777 == 0o600
    assert kh.parent.stat().st_mode & 0o777 == 0o700
    stored = paramiko.HostKeys(str(kh)).lookup(hostkeys.entry_name("127.0.0.1", port))
    assert stored.get(key.get_name()) == key


def test_learn_does_not_touch_a_known_host_and_does_not_recontact_it(tmp_path):
    key = _key()
    policy = _policy(tmp_path, "accept-new", lab=True)
    _write_entry(policy.path, "127.0.0.1", key)
    before = policy.path.read_text(encoding="utf-8")
    # Aucun serveur n'écoute : un contact serait une erreur. Un hôte connu n'est jamais recontacté ici.
    assert hostkeys.learn("127.0.0.1", 22, policy) is False
    assert policy.path.read_text(encoding="utf-8") == before


def test_learn_never_overwrites_a_different_key(tmp_path):
    old, new = _key(), _key()
    policy = _policy(tmp_path, "accept-new", lab=True)
    with ssh_server(new) as port:
        _write_entry(policy.path, hostkeys.entry_name("127.0.0.1", port), old)
        before = policy.path.read_text(encoding="utf-8")
        assert hostkeys.learn("127.0.0.1", port, policy) is False
    assert policy.path.read_text(encoding="utf-8") == before


def test_learn_is_a_no_op_in_strict_mode(tmp_path):
    policy = _policy(tmp_path, "strict", lab=True)
    assert hostkeys.learn("127.0.0.1", 9, policy) is False
    assert not policy.path.exists()


def test_learn_refuses_without_lab(tmp_path):
    policy = _policy(tmp_path, "accept-new", lab=False)
    with pytest.raises(hostkeys.HostKeyError, match="lab"):
        hostkeys.learn("127.0.0.1", 9, policy)
    assert not policy.path.exists()


def test_learn_reports_an_unreachable_host(tmp_path):
    with socket.socket() as s:     # un port libre, sans serveur
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    policy = _policy(tmp_path, "accept-new", lab=True)
    with pytest.raises(hostkeys.HostKeyError, match="injoignable"):
        hostkeys.learn("127.0.0.1", free, policy)
    assert not policy.path.exists()


def test_learn_keeps_a_last_line_without_newline(tmp_path):
    key = _key()
    policy = _policy(tmp_path, "accept-new", lab=True)
    other = _key()
    policy.path.parent.mkdir(parents=True)
    policy.path.write_text(f"10.9.9.9 {other.get_name()} {other.get_base64()}", encoding="utf-8")  # pas de \n
    with ssh_server(key) as port:
        assert hostkeys.learn("127.0.0.1", port, policy) is True
    hk = paramiko.HostKeys(str(policy.path))
    assert hk.lookup("10.9.9.9") is not None
    assert hk.lookup(hostkeys.entry_name("127.0.0.1", port)) is not None


def test_parallel_first_contacts_write_each_host_once(tmp_path):
    policy = _policy(tmp_path, "accept-new", lab=True)
    with ssh_server(_key()) as p0, ssh_server(_key()) as p1, ssh_server(_key()) as p2, \
            ssh_server(_key()) as p3:
        ports = [p0, p1, p2, p3]
        threads = [threading.Thread(target=hostkeys.learn, args=("127.0.0.1", p, policy)) for p in ports * 2]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    lines = policy.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4 and len(set(line.split()[0] for line in lines)) == 4


# -- collect() : la clé d'hôte est vérifiée AVANT l'authentification --------------------------

def test_collect_asks_netmiko_for_strict_checking_against_the_dedicated_file(monkeypatch, tmp_path):
    seen = {}

    def fake_connect(**kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop")

    monkeypatch.setattr(collector, "ConnectHandler", fake_connect)
    policy = _policy(tmp_path)
    hostkeys.set_policy(policy)
    with pytest.raises(RuntimeError, match="stop"):
        collector._connect(_router(2222))
    assert seen["ssh_strict"] is True
    assert seen["system_host_keys"] is False
    assert seen["alt_host_keys"] is True
    assert seen["alt_key_file"] == str(policy.path)
    assert seen["port"] == 2222


def test_collect_refuses_an_unknown_host_key(tmp_path):
    hostkeys.set_policy(_policy(tmp_path))
    with ssh_server(_key()) as port, pytest.raises(hostkeys.HostKeyError) as err:
        collector._connect(_router(port))
    assert "inconnue" in str(err.value) and "Migration" in str(err.value)


def test_collect_accepts_a_pinned_key_then_fails_only_on_authentication(tmp_path):
    key = _key()
    policy = _policy(tmp_path)
    hostkeys.set_policy(policy)
    with ssh_server(key) as port:
        _write_entry(policy.path, hostkeys.entry_name("127.0.0.1", port), key)
        policy.path.chmod(0o600)
        with pytest.raises(NetmikoAuthenticationException):
            collector._connect(_router(port))


def test_collect_refuses_a_changed_key_and_shows_both_fingerprints(tmp_path):
    pinned, presented = _key(), _key()
    policy = _policy(tmp_path)
    hostkeys.set_policy(policy)
    with ssh_server(presented) as port:
        _write_entry(policy.path, hostkeys.entry_name("127.0.0.1", port), pinned)
        policy.path.chmod(0o600)
        with pytest.raises(hostkeys.HostKeyError) as err:
            collector._connect(_router(port))
    message = str(err.value)
    assert "CHANGÉE" in message
    assert hostkeys.fingerprint(presented) in message and hostkeys.fingerprint(pinned) in message


def test_accept_new_learns_then_connects_strictly_and_still_refuses_a_change(tmp_path):
    first, second = _key(), _key()
    policy = _policy(tmp_path, "accept-new", lab=True)
    hostkeys.set_policy(policy)
    with ssh_server(first) as port:
        with pytest.raises(NetmikoAuthenticationException):    # clé apprise, puis authentification refusée
            collector._connect(_router(port))
    assert hostkeys.entry_name("127.0.0.1", port) in policy.path.read_text(encoding="utf-8")
    with ssh_server(second, port=port):                        # même adresse, autre clé
        with pytest.raises(hostkeys.HostKeyError, match="CHANGÉE"):
            collector._connect(_router(port))


def test_the_users_own_known_hosts_is_never_read(monkeypatch, tmp_path):
    key = _key()
    monkeypatch.setenv("HOME", str(tmp_path))
    with ssh_server(key) as port:
        _write_entry(tmp_path / ".ssh" / "known_hosts", hostkeys.entry_name("127.0.0.1", port), key)
        hostkeys.set_policy(_policy(tmp_path))                 # fichier dédié : vide
        with pytest.raises(hostkeys.HostKeyError, match="inconnue"):
            collector._connect(_router(port))


def test_world_writable_known_hosts_stops_before_any_connection(monkeypatch, tmp_path):
    policy = _policy(tmp_path)
    policy.path.parent.mkdir(parents=True)
    policy.path.write_text("", encoding="utf-8")
    policy.path.chmod(0o666)
    hostkeys.set_policy(policy)
    monkeypatch.setattr(collector, "ConnectHandler", lambda **_: pytest.fail("connexion ouverte"))
    with pytest.raises(hostkeys.HostKeyError, match="modifiable"):
        collector._connect(_router(22))


# -- Aucun chemin ne contourne la vérification -----------------------------------------------

def _code_nodes():
    for path in sorted(PACKAGE.rglob("*.py")):
        if ".venv" in path.parts:   # l'environnement virtuel vit dans netcheck/.venv : pas du code du projet
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def test_no_code_path_accepts_unverified_keys():
    forbidden_names = {"AutoAddPolicy", "WarningPolicy"}
    offenders = []
    for path, tree in _code_nodes():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute | ast.Name):
                name = node.attr if isinstance(node, ast.Attribute) else node.id
                if name in forbidden_names or name == "set_missing_host_key_policy":
                    offenders.append(f"{path.name}:{node.lineno} {name}")
            if isinstance(node, ast.keyword) and isinstance(node.value, ast.Constant):
                if (node.arg, node.value.value) in {("ssh_strict", False), ("system_host_keys", True)}:
                    offenders.append(f"{path.name}:{node.value.lineno} {node.arg}={node.value.value}")
    assert not offenders, offenders


def test_every_connect_handler_call_is_strict():
    calls = []
    for path, tree in _code_nodes():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ConnectHandler":
                calls.append((path.name, {k.arg: k.value for k in node.keywords}))
    assert calls, "ConnectHandler n'est plus appelé : ce test doit suivre le code"
    for name, kwargs in calls:
        assert isinstance(kwargs.get("ssh_strict"), ast.Constant) and kwargs["ssh_strict"].value is True, name
        assert "alt_key_file" in kwargs, name


# -- Inventaire et CLI -------------------------------------------------------------------------

def _inventory_file(tmp_path, lab=None) -> str:
    lines = []
    if lab is not None:
        lines.append(f"lab: {lab}")
    lines += ["defaults: {device_type: linux, username: u, password: p}",
              "routers:", "  r1: {host: 127.0.0.1}"]
    path = tmp_path / "inv.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_inventory_lab_flag(tmp_path):
    assert inventory.load(path=_inventory_file(tmp_path)).lab is False
    assert inventory.load(path=_inventory_file(tmp_path, "true")).lab is True
    with pytest.raises(SystemExit, match="lab"):
        inventory.load(path=_inventory_file(tmp_path, '"oui"'))


def test_lab_inventories_of_the_repository_are_marked_lab():
    for name in ("inventory.yml", "inventory-multivendor.yml", "inventory-ceos.yml"):
        assert inventory.load(path=inventory.REPO_ROOT / "automation" / name).lab is True, name


def test_ignore_is_not_an_accepted_value(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args(["snapshot", "x", "--host-keys", "ignore"])
    assert exit_info.value.code == 3   # erreur d'usage de netcheck (2 = ÉCHEC)
    assert "ignore" in capsys.readouterr().err


def _never_collect(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("aucune collecte ne doit avoir lieu")
    monkeypatch.setattr(collector, "collect_all", boom)
    monkeypatch.setattr(collector, "wait_for_convergence", boom)


def _script(tmp_path) -> str:
    path = tmp_path / "change.sh"
    path.write_text("true\n", encoding="utf-8")
    return str(path)


def _commands(tmp_path, inv):
    return {
        "snapshot": ["snapshot", "s", "-i", inv],
        "check": ["check", "-i", inv],
        "assert": ["assert", "--intent", str(inventory.REPO_ROOT / "intents" / "lab.yml"), "-i", inv],
        "guard": ["guard", "--change", _script(tmp_path), "--yes", "-i", inv],
        "monitor": ["monitor", "--baseline", "b", "-i", inv],
    }


@pytest.mark.parametrize("command", ["snapshot", "check", "assert", "guard", "monitor"])
def test_accept_new_on_a_non_lab_inventory_is_refused_before_any_collection(
        command, monkeypatch, tmp_path, capsys):
    if command == "monitor":
        from netcheck import snapshot
        monkeypatch.setattr(snapshot, "load", lambda name: {})
    _never_collect(monkeypatch)
    inv = _inventory_file(tmp_path)   # pas de `lab: true`
    code = cli.main(_commands(tmp_path, inv)[command] + ["--host-keys", "accept-new"])
    assert code == 3
    assert "lab: true" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["snapshot", "check", "assert", "guard", "monitor"])
def test_environment_cannot_bypass_the_lab_requirement(command, monkeypatch, tmp_path, capsys):
    if command == "monitor":
        from netcheck import snapshot
        monkeypatch.setattr(snapshot, "load", lambda name: {})
    _never_collect(monkeypatch)
    monkeypatch.setenv(hostkeys.ENV_MODE, "accept-new")
    code = cli.main(_commands(tmp_path, _inventory_file(tmp_path))[command])
    assert code == 3
    assert "lab: true" in capsys.readouterr().err


def test_invalid_mode_in_environment_is_refused(monkeypatch, tmp_path, capsys):
    _never_collect(monkeypatch)
    monkeypatch.setenv(hostkeys.ENV_MODE, "off")
    assert cli.main(["snapshot", "s", "-i", _inventory_file(tmp_path, "true")]) == 3
    assert "inconnu" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["snapshot", "check", "assert"])
def test_accept_new_on_a_lab_inventory_warns_every_time_and_sets_the_policy(
        command, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(collector, "collect_all", lambda routers, *a, **k: {})
    from netcheck import snapshot
    monkeypatch.setattr(snapshot, "save", lambda *a, **k: inventory.REPO_ROOT / "snapshots" / "x")
    inv = _inventory_file(tmp_path, "true")
    for _ in range(2):
        cli.main(_commands(tmp_path, inv)[command] + ["--host-keys", "accept-new",
                                                      "--known-hosts", str(tmp_path / "kh")])
        err = capsys.readouterr().err
        assert "Avertissement" in err and "accept-new" in err
    policy = hostkeys.current()
    assert (policy.mode, policy.lab, policy.known_hosts) == ("accept-new", True, tmp_path / "kh")


def test_strict_is_the_default_and_prints_no_warning(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(collector, "collect_all", lambda routers, *a, **k: {})
    from netcheck import snapshot
    monkeypatch.setattr(snapshot, "save", lambda *a, **k: inventory.REPO_ROOT / "snapshots" / "x")
    cli.main(["snapshot", "s", "-i", _inventory_file(tmp_path, "true")])
    assert "Avertissement" not in capsys.readouterr().err
    assert hostkeys.current().mode == "strict"
