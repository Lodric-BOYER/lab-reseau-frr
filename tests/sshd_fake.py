"""Faux serveur SSH pour les tests (phase C4) : un bastion, ou un « routeur » qui fait l'échange de clés.

Authentification par clé publique seulement ; canaux `direct-tcpip` autorisés vers une liste (ensemble de
(hôte, port)), refusés ailleurs ; toute demande de session (shell, exec), d'agent ou de X11 est enregistrée
puis refusée. Les canaux acceptés sont reliés à un serveur TCP local (`targets`), pour que de vrais octets
traversent le tunnel. Aucun réseau hors de 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def make_key(path: Path, passphrase: str | None = None) -> paramiko.PKey:
    """Écrit une clé ed25519 au format OpenSSH (0600), éventuellement protégée, et la renvoie chargée."""
    private = ed25519.Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    path.write_bytes(
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption)
    )
    path.chmod(0o600)
    return paramiko.Ed25519Key.from_private_key_file(str(path), passphrase)


class EchoServer:
    """Un « routeur » TCP : renvoie ce qu'il reçoit."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.connections = 0
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def address(self) -> tuple[str, int]:
        return self.sock.getsockname()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)

    def stop(self):
        self.sock.close()


class _Interface(paramiko.ServerInterface):
    def __init__(self, outer: FakeSshd):
        self.outer = outer

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        ok = username == self.outer.username and key.get_base64() in self.outer.authorized
        self.outer.auth_attempts.append((username, key.get_name(), ok))
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.outer.password_attempts += 1
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        self.outer.session_requests.append(kind)  # shell, exec, agent, x11... : jamais accordé
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.outer.forward_requests.append(tuple(destination))
        self.outer.pending[chanid] = tuple(destination)
        if tuple(destination) in self.outer.targets:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class FakeSshd:
    """`targets` : {(hôte, port) autorisé: (adresse locale réelle)}. Vide : aucun rebond."""

    def __init__(self, host_key, authorized=(), username="jump", targets=None):
        self.host_key = host_key
        self.authorized = {k.get_base64() for k in authorized}
        self.username = username
        self.targets = dict(targets or {})
        self.auth_attempts: list[tuple[str, str, bool]] = []
        self.password_attempts = 0
        self.session_requests: list[str] = []
        self.forward_requests: list[tuple[str, int]] = []
        self.pending: dict[int, tuple[str, int]] = {}  # numéro de canal -> destination demandée
        self.transports: list[paramiko.Transport] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            try:
                transport.start_server(server=_Interface(self))
            except (paramiko.SSHException, EOFError, OSError):
                continue
            threading.Thread(target=self._accept_channels, args=(transport,), daemon=True).start()

    def _accept_channels(self, transport):
        while transport.is_active():
            channel = transport.accept(timeout=0.2)
            if channel is None:
                continue
            threading.Thread(target=self._pump, args=(channel,), daemon=True).start()

    def _pump(self, channel):
        # Le canal accepté va vers la cible locale qui correspond à la destination demandée pour ce canal.
        target = self.targets.get(self.pending.get(channel.get_id()))
        if target is None:
            channel.close()
            return
        backend = socket.create_connection(target, timeout=5)

        def forward(read, write):
            try:
                while True:
                    data = read(4096)
                    if not data:
                        break
                    write(data)
            except OSError:
                pass
            finally:
                for closer in (backend.close, channel.close):
                    try:
                        closer()
                    except (OSError, EOFError):
                        pass

        threading.Thread(target=forward, args=(channel.recv, backend.sendall), daemon=True).start()
        threading.Thread(target=forward, args=(backend.recv, channel.sendall), daemon=True).start()

    def stop(self):
        self.sock.close()
        for transport in self.transports:
            transport.close()

    def known_hosts_line(self, path: Path, host: str = "127.0.0.1") -> None:
        """Écrit le known_hosts (0600) qui épingle la clé d'hôte de ce faux serveur."""
        from netcheck import hostkeys

        keys = paramiko.HostKeys()
        keys.add(hostkeys.entry_name(host, self.port), self.host_key.get_name(), self.host_key)
        keys.save(str(path))
        path.chmod(0o600)
