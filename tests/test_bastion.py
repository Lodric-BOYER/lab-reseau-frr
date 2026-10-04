"""Bastion SSH (phase C4) contre un VRAI serveur SSH de test (paramiko, 127.0.0.1) : clé d'hôte du bastion
vérifiée en strict dans le même known_hosts, authentification par clé seulement, rebond `direct-tcpip`
limité à une liste, aucun repli direct, aucune session, aucun agent, aucun X11.
"""

from __future__ import annotations

import ast
import socket

import paramiko
import pytest
from sshd_fake import EchoServer, FakeSshd, make_key

from netcheck import bastion, collector, hostkeys, inventory
from netcheck.credentials import CredentialError
from netcheck.secrets import SecretStr
from netcheck.sshkeys import Bastion, KeySpec

ROUTER = ("172.20.20.11", 22)
PASSPHRASE = "Passphrase-Sentinel-31415"


@pytest.fixture
def env(tmp_path):
    client_key_path = tmp_path / "id_bastion"
    client_key = make_key(client_key_path)
    echo = EchoServer()
    server = FakeSshd(paramiko.ECDSAKey.generate(), authorized=[client_key], targets={ROUTER: echo.address})
    known_hosts = tmp_path / "known_hosts"
    server.known_hosts_line(known_hosts)
    spec = Bastion("127.0.0.1", server.port, "jump", KeySpec(str(client_key_path), None))
    policy = hostkeys.HostKeyPolicy("strict", known_hosts, False)

    class Env:
        pass

    e = Env()
    e.tmp, e.server, e.echo, e.spec, e.policy, e.known_hosts = (
        tmp_path,
        server,
        echo,
        spec,
        policy,
        known_hosts,
    )
    e.client_key_path = client_key_path
    yield e
    server.stop()
    echo.stop()


# --- Le tunnel ----------------------------------------------------------------------------------------


def test_the_channel_to_a_permitted_target_carries_real_bytes(env):
    link = bastion.BastionLink.open(env.spec, env.policy)
    try:
        channel = link.open_channel(*ROUTER)
        channel.sendall(b"bonjour routeur")
        channel.settimeout(5)
        assert channel.recv(100) == b"bonjour routeur"
    finally:
        link.close()
    assert env.server.forward_requests == [ROUTER]
    assert env.server.auth_attempts == [("jump", "ssh-ed25519", True)]


def test_only_a_direct_tcpip_channel_is_ever_requested(env):
    link = bastion.BastionLink.open(env.spec, env.policy)
    try:
        link.open_channel(*ROUTER).close()
    finally:
        link.close()
    assert env.server.session_requests == []  # ni shell, ni exec, ni agent, ni X11
    assert env.server.password_attempts == 0  # jamais de mot de passe


def test_a_target_outside_the_permit_list_is_refused_by_the_bastion(env):
    link = bastion.BastionLink.open(env.spec, env.policy)
    try:
        for destination in (("192.0.2.1", 22), (ROUTER[0], 179), ("127.0.0.1", 22)):
            with pytest.raises(bastion.BastionError, match="refusé le rebond"):
                link.open_channel(*destination)
    finally:
        link.close()
    assert env.echo.connections == 0  # rien n'a atteint le « routeur »


def test_close_ends_the_session(env):
    link = bastion.BastionLink.open(env.spec, env.policy)
    transport = link.client.get_transport()
    link.close()
    assert not transport.is_active()
    with pytest.raises(bastion.BastionError, match="fermée"):
        link.open_channel(*ROUTER)


# --- Clé d'hôte du bastion ----------------------------------------------------------------------------


def test_an_unknown_bastion_host_key_is_refused_in_strict_mode(env):
    env.known_hosts.write_text("", encoding="utf-8")
    env.known_hosts.chmod(0o600)
    with pytest.raises(hostkeys.HostKeyError, match="inconnue"):
        bastion.BastionLink.open(env.spec, env.policy)
    assert env.server.auth_attempts == []  # refusé avant toute authentification


def test_a_changed_bastion_host_key_is_refused(env):
    other = FakeSshd(paramiko.ECDSAKey.generate())
    try:
        other.known_hosts_line(env.known_hosts, "127.0.0.1")  # la clé de l'autre, sous le port de l'autre
        # on réécrit le known_hosts : la ligne de CE bastion porte la clé de l'autre serveur
        keys = paramiko.HostKeys()
        keys.add(hostkeys.entry_name("127.0.0.1", env.server.port), other.host_key.get_name(), other.host_key)
        keys.save(str(env.known_hosts))
        env.known_hosts.chmod(0o600)
        with pytest.raises(hostkeys.HostKeyError, match="CHANGÉE"):
            bastion.BastionLink.open(env.spec, env.policy)
    finally:
        other.stop()
    assert env.server.auth_attempts == []


def test_accept_new_learns_the_bastion_key_only_in_a_lab_inventory(env):
    env.known_hosts.unlink()
    lab = hostkeys.HostKeyPolicy("accept-new", env.known_hosts, True)
    link = bastion.BastionLink.open(env.spec, lab)
    link.close()
    line = env.known_hosts.read_text(encoding="utf-8")
    assert (
        hostkeys.entry_name("127.0.0.1", env.server.port) in line and env.server.host_key.get_name() in line
    )
    assert (env.known_hosts.stat().st_mode & 0o777) == 0o600
    env.known_hosts.unlink()
    with pytest.raises(hostkeys.HostKeyError, match="lab"):
        bastion.BastionLink.open(env.spec, hostkeys.HostKeyPolicy("accept-new", env.known_hosts, False))


def test_the_router_key_learned_in_accept_new_comes_through_the_bastion(env):
    router_sshd = FakeSshd(paramiko.ECDSAKey.generate())
    env.server.targets[ROUTER] = ("127.0.0.1", router_sshd.port)
    lab = hostkeys.HostKeyPolicy("accept-new", env.tmp / "learned", True)
    link = bastion.BastionLink.open(env.spec, hostkeys.HostKeyPolicy("strict", env.known_hosts, False))
    try:
        assert hostkeys.learn(ROUTER[0], ROUTER[1], lab, opener=link.open_channel) is True
    finally:
        link.close()
        router_sshd.stop()
    learned = (env.tmp / "learned").read_text(encoding="utf-8")
    assert learned.startswith(
        f"{ROUTER[0]} {router_sshd.host_key.get_name()} {router_sshd.host_key.get_base64()}"
    )
    assert env.server.forward_requests == [ROUTER]  # le premier contact est passé par le bastion


# --- Authentification : clé seulement -------------------------------------------------------------------


def test_a_key_the_bastion_does_not_know_is_refused_without_trying_anything_else(env):
    other_path = env.tmp / "other"
    make_key(other_path)
    spec = Bastion("127.0.0.1", env.server.port, "jump", KeySpec(str(other_path), None))
    with pytest.raises(bastion.BastionError, match="refusé la clé"):
        bastion.BastionLink.open(spec, env.policy)
    assert env.server.password_attempts == 0
    assert [a[2] for a in env.server.auth_attempts] == [False]


def test_the_wrong_username_is_refused(env):
    spec = Bastion("127.0.0.1", env.server.port, "root", env.spec.key)
    with pytest.raises(bastion.BastionError, match="refusé la clé"):
        bastion.BastionLink.open(spec, env.policy)


def test_an_unreachable_bastion_is_an_explicit_error(env):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    spec = Bastion("127.0.0.1", port, "jump", env.spec.key)
    known = hostkeys.HostKeyPolicy("strict", env.known_hosts, False)
    with pytest.raises(bastion.BastionError, match="injoignable"):
        bastion.BastionLink.open(spec, known)


def test_a_passphrase_protected_key_works_and_a_wrong_one_stops_before_connecting(env):
    protected = env.tmp / "protected"
    key = make_key(protected, PASSPHRASE)
    env.server.authorized.add(key.get_base64())
    good = Bastion(
        "127.0.0.1", env.server.port, "jump", KeySpec(str(protected), SecretStr(PASSPHRASE, "test"))
    )
    bastion.BastionLink.open(good, env.policy).close()
    bad = Bastion(
        "127.0.0.1", env.server.port, "jump", KeySpec(str(protected), SecretStr("faux-faux-faux", "t"))
    )
    before = len(env.server.auth_attempts)
    with pytest.raises(CredentialError, match="phrase secrète incorrecte") as raised:
        bastion.BastionLink.open(bad, env.policy)
    assert PASSPHRASE not in str(raised.value) and "faux-faux-faux" not in str(raised.value)
    assert len(env.server.auth_attempts) == before  # la clé n'a même pas été présentée


# --- Collecteur : tout passe par le bastion, jamais de repli direct --------------------------------------


class _Link:
    def __init__(self, fail_channel=False):
        self.opened, self.closed, self.fail_channel = [], False, fail_channel

    def open_channel(self, host, port):
        if self.fail_channel:
            raise bastion.BastionError("rebond refusé")
        self.opened.append((host, port))
        return f"canal-{host}:{port}"

    def close(self):
        self.closed = True


class _Conn:
    def disconnect(self):
        pass


def _router(**extra):
    return {
        "name": "r1",
        "host": "172.20.20.11",
        "device_type": "linux",
        "username": "netops",
        "password": SecretStr("pw-long-enough-1", "test"),
        **extra,
    }


@pytest.fixture
def traps(monkeypatch, env):
    """Le routeur ne doit JAMAIS être contacté en direct ; ConnectHandler enregistre ses arguments."""
    calls = []

    class Conn:
        def disconnect(self):
            calls.append("disconnect")

    def connect(**kwargs):
        calls.append(kwargs)
        return Conn()

    def no_direct(*_a, **_k):
        raise AssertionError("connexion directe interdite : tout passe par le bastion")

    monkeypatch.setattr(collector, "ConnectHandler", connect)
    monkeypatch.setattr(socket, "create_connection", no_direct)
    monkeypatch.setattr(hostkeys, "set_policy", hostkeys.set_policy)
    hostkeys.set_policy(env.policy)
    yield calls
    hostkeys.set_policy(None)


def test_collector_goes_through_the_bastion_with_the_channel_as_socket(monkeypatch, traps, env):
    link = _Link()
    monkeypatch.setattr(collector.BastionLink, "open", classmethod(lambda cls, spec, policy: link))
    conn = collector._connect(_router(bastion=env.spec))
    kwargs = traps[0]
    assert kwargs["sock"] == "canal-172.20.20.11:22" and link.opened == [("172.20.20.11", 22)]
    assert kwargs["ssh_strict"] is True and kwargs["allow_agent"] is False
    assert "use_keys" not in kwargs and "key_file" not in kwargs  # jamais les clés de ~/.ssh
    collector._disconnect(conn)
    assert link.closed is True and traps[-1] == "disconnect"


def test_no_fallback_to_a_direct_connection_when_the_bastion_fails(monkeypatch, traps, env):
    def boom(cls, spec, policy):
        raise bastion.BastionError("bastion injoignable")

    monkeypatch.setattr(collector.BastionLink, "open", classmethod(boom))
    with pytest.raises(bastion.BastionError):
        collector._connect(_router(bastion=env.spec))
    assert traps == []  # ConnectHandler jamais appelé, socket direct jamais ouvert


def test_a_refused_hop_closes_the_bastion_and_never_tries_direct(monkeypatch, traps, env):
    link = _Link(fail_channel=True)
    monkeypatch.setattr(collector.BastionLink, "open", classmethod(lambda cls, spec, policy: link))
    with pytest.raises(bastion.BastionError, match="refusé"):
        collector._connect(_router(bastion=env.spec))
    assert link.closed is True and traps == []


def test_a_failed_login_closes_the_bastion_session(monkeypatch, env):
    link = _Link()
    monkeypatch.setattr(collector.BastionLink, "open", classmethod(lambda cls, spec, policy: link))

    def refuse(**_kwargs):
        raise RuntimeError("authentification refusée")

    monkeypatch.setattr(collector, "ConnectHandler", refuse)
    hostkeys.set_policy(env.policy)
    try:
        with pytest.raises(RuntimeError):
            collector._connect(_router(bastion=env.spec))
    finally:
        hostkeys.set_policy(None)
    assert link.closed is True


def test_accept_new_learns_the_router_key_through_the_bastion(monkeypatch, traps, env):
    link = _Link()
    monkeypatch.setattr(collector.BastionLink, "open", classmethod(lambda cls, spec, policy: link))
    seen = []
    monkeypatch.setattr(
        hostkeys, "learn", lambda host, port, policy, opener=None: seen.append(opener) or False
    )
    collector._connect(_router(bastion=env.spec))
    assert seen == [link.open_channel]


def test_without_a_bastion_nothing_changes(monkeypatch, env):
    calls = []
    monkeypatch.setattr(collector, "ConnectHandler", lambda **kwargs: calls.append(kwargs) or _Conn())
    hostkeys.set_policy(env.policy)
    try:
        collector._connect(_router())
    finally:
        hostkeys.set_policy(None)
    assert "sock" not in calls[0] and calls[0]["password"] == "pw-long-enough-1"


def test_a_key_is_presented_alone_and_the_password_is_never_sent(monkeypatch, env):
    key_path = env.tmp / "router_key"
    make_key(key_path, PASSPHRASE)
    calls = []
    monkeypatch.setattr(collector, "ConnectHandler", lambda **kwargs: calls.append(kwargs) or _Conn())
    hostkeys.set_policy(env.policy)
    try:
        collector._connect(_router(key_file=str(key_path), key_passphrase=SecretStr(PASSPHRASE, "test")))
    finally:
        hostkeys.set_policy(None)
    kwargs = calls[0]
    assert isinstance(kwargs["pkey"], paramiko.PKey) and "password" not in kwargs
    assert kwargs["allow_agent"] is False and "use_keys" not in kwargs and "key_file" not in kwargs


# --- Ce que le code n'a pas le droit de faire ---------------------------------------------------------------


def _tree(name):
    return ast.parse((inventory.REPO_ROOT / "netcheck" / name).read_text(encoding="utf-8"))


def test_the_bastion_client_never_asks_for_a_session_agent_or_x11():
    forbidden = {
        "invoke_shell",
        "exec_command",
        "open_session",
        "request_x11",
        "get_pty",
        "AgentRequestHandler",
        "ForwardAgent",
        "request_forward_agent",
        "AutoAddPolicy",
        "WarningPolicy",
    }
    names = {n.attr for n in ast.walk(_tree("bastion.py")) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(_tree("bastion.py")) if isinstance(n, ast.Name)}
    assert not names & forbidden, names & forbidden


def test_no_connection_code_enables_agents_or_default_keys():
    offenders = []
    for name in ("bastion.py", "collector.py", "sshkeys.py"):
        for node in ast.walk(_tree(name)):
            if (
                isinstance(node, ast.keyword)
                and isinstance(node.value, ast.Constant)
                and (node.arg, node.value.value)
                in {("allow_agent", True), ("look_for_keys", True), ("use_keys", True)}
            ):
                offenders.append(f"{name}:{node.value.lineno} {node.arg}=True")
    assert offenders == []


def test_the_bastion_connection_sets_both_agent_and_default_keys_off():
    calls = [
        n
        for n in ast.walk(_tree("bastion.py"))
        if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "connect"
    ]
    assert calls
    for call in calls:
        kw = {k.arg: k.value for k in call.keywords}
        assert kw["allow_agent"].value is False and kw["look_for_keys"].value is False and "pkey" in kw
        assert "password" not in kw


def test_the_connect_handler_call_never_uses_key_file_or_use_keys():
    calls = [
        n
        for n in ast.walk(_tree("collector.py"))
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "ConnectHandler"
    ]
    assert calls
    for call in calls:
        keywords = {k.arg for k in call.keywords}
        assert not keywords & {"key_file", "use_keys", "passphrase"}, keywords


# --- Cas ajoutés après les mutations -----------------------------------------------------------------


def test_a_known_hosts_writable_by_others_is_refused_before_any_connection(env):
    env.known_hosts.chmod(0o666)
    with pytest.raises(hostkeys.HostKeyError, match="modifiable"):
        bastion.BastionLink.open(env.spec, env.policy)
    assert env.server.auth_attempts == []


def test_a_failed_connection_closes_the_bastion_client(env, monkeypatch):
    closed = []
    original = paramiko.SSHClient.close
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda self: closed.append(1) or original(self))
    other_path = env.tmp / "unauthorized"
    make_key(other_path)
    spec = Bastion("127.0.0.1", env.server.port, "jump", KeySpec(str(other_path), None))
    with pytest.raises(bastion.BastionError):
        bastion.BastionLink.open(spec, env.policy)
    assert closed == [1]


def test_the_bastion_session_sends_keepalives(env):
    link = bastion.BastionLink.open(env.spec, env.policy)
    try:
        packetizer = link.client.get_transport().packetizer
        assert packetizer._Packetizer__keepalive_interval == 15    # attribut privé de paramiko (nom mutilé)
    finally:
        link.close()
