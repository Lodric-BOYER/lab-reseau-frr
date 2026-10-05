"""Fournisseur de secrets Vault (phase C3) contre un FAUX serveur Vault local (aucun conteneur, aucun réseau).

Ce qui est prouvé :
- exactement deux appels réseau : POST /v1/auth/approle/login puis GET du chemin configuré ;
- tout autre appel (écriture de secret, lecture ailleurs, sys/, DELETE...) est refusé AVANT envoi ;
- l'ordre de priorité : variable de driver > fichier de driver > variable générique > fichier générique >
  Vault > LAB_PASS > inventaire, et `LAB_PASS` ne masque jamais Vault ;
- aucune panne de Vault ne retombe en silence sur `LAB_PASS` ni sur l'inventaire ;
- le jeton, le secret_id et le mot de passe lu n'apparaissent dans aucune sortie ;
- pas de redirection suivie, proxy d'environnement ignoré, http:// refusé hors bouclage.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netcheck import cli, collector, credentials, inventory, secrets, snapshot, vault
from netcheck.credentials import CredentialError
from netcheck.model import DeviceState

pytest.importorskip("hvac")
pytestmark = pytest.mark.skipif(os.name == "nt", reason="droits POSIX")

ROLE_ID = "role-id-abc-123"
SECRET_ID = "secret-id-SENTINEL-9f8e7d6c"
TOKEN = "hvs.FAKE-TOKEN-SENTINEL-0123456789"
VAULT_PASSWORD = "Vault-Password-SENTINEL-77"
LAB_PASSWORD = "lab-pass-from-LAB_PASS"
INVENTORY_PASSWORD = "inventory-password-xyz"


class FakeVault:
    """Un Vault minimal : login AppRole et lecture KV v2. Enregistre chaque requête reçue."""

    def __init__(self, document=None):
        self.document = (
            {"username": "vault-user", "password": VAULT_PASSWORD} if document is None else document
        )
        self.requests: list[tuple[str, str]] = []
        self.login_status: int | None = None
        self.read_status: int | None = None
        self.redirect_to: str | None = None
        self.delay = 0.0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _reply(self, status, body=None, headers=None):
                payload = json.dumps(body if body is not None else {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append((self.command, self.path))
                if outer.delay:
                    threading.Event().wait(outer.delay)
                if outer.redirect_to:
                    return self._reply(307, headers={"Location": outer.redirect_to})
                if self.command == "POST" and self.path == "/v1/auth/approle/login":
                    sent = json.loads(body or b"{}")
                    if outer.login_status:
                        return self._reply(outer.login_status, {"errors": ["boom"]})
                    if sent.get("role_id") == ROLE_ID and sent.get("secret_id") == SECRET_ID:
                        return self._reply(200, {"auth": {"client_token": TOKEN, "lease_duration": 300}})
                    return self._reply(400, {"errors": ["invalid role or secret ID"]})
                if self.command == "GET" and self.path == "/v1/secret/data/netcheck/lab":
                    if self.headers.get("X-Vault-Token") != TOKEN:
                        return self._reply(403, {"errors": ["permission denied"]})
                    if outer.read_status:
                        return self._reply(outer.read_status, {"errors": ["boom"]})
                    return self._reply(200, {"data": {"data": outer.document, "metadata": {"version": 1}}})
                return self._reply(404, {"errors": []})

            do_GET = do_POST = do_PUT = do_DELETE = do_LIST = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True
        )
        self.thread.start()

    @property
    def addr(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")):
            monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake():
    server = FakeVault()
    yield server
    server.stop()


def _secret_id_file(tmp_path, content=SECRET_ID + "\n", mode=0o600):
    path = tmp_path / "secret_id"
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return str(path)


@pytest.fixture
def venv(fake, tmp_path):
    """L'environnement de configuration de Vault (sans variable d'identifiant)."""
    return {
        vault.ENV_ADDR: fake.addr,
        vault.ENV_ROLE_ID: ROLE_ID,
        vault.ENV_SECRET_ID_FILE: _secret_id_file(tmp_path),
        vault.ENV_PATH: "netcheck/lab",
    }


LOGIN = ("POST", "/v1/auth/approle/login")
READ = ("GET", "/v1/secret/data/netcheck/lab")


# --- Les deux seuls appels ---------------------------------------------------------------------------


def test_lookup_makes_exactly_the_login_and_the_read(venv, fake):
    value, source = vault.lookup("PASS", "frr", venv)
    assert value == VAULT_PASSWORD
    assert source.label == "Vault (secret/netcheck/lab)"
    assert fake.requests == [LOGIN, READ]


def test_the_secret_is_read_once_per_process(venv, fake):
    vault.lookup("PASS", "frr", venv)
    vault.lookup("USER", "frr", venv)
    vault.lookup("PASS", "srlinux", venv)
    assert fake.requests == [LOGIN, READ]


def test_allowed_calls_are_exactly_two_with_exact_paths(venv):
    config = vault.from_environment(venv)
    assert vault.allowed_calls(config) == {LOGIN, READ}


FORBIDDEN = [
    ("write secret", lambda c: c.write("secret/data/netcheck/lab", foo="bar")),
    (
        "kv v2 create",
        lambda c: c.secrets.kv.v2.create_or_update_secret(
            path="netcheck/lab", secret={"a": 1}, mount_point="secret"
        ),
    ),
    (
        "kv v2 read elsewhere",
        lambda c: c.secrets.kv.v2.read_secret_version(
            path="other", mount_point="secret", raise_on_deleted_version=True
        ),
    ),
    ("read a sub-path", lambda c: c.read("secret/data/netcheck/lab/extra")),
    ("sys health", lambda c: c.sys.read_health_status(method="GET")),
    ("token lookup-self", lambda c: c.auth.token.lookup_self()),
    ("delete secret", lambda c: c.delete("secret/data/netcheck/lab")),
    (
        "kv v2 delete",
        lambda c: c.secrets.kv.v2.delete_latest_version_of_secret(path="netcheck/lab", mount_point="secret"),
    ),
    ("POST on the read path", lambda c: c.adapter.post("/v1/secret/data/netcheck/lab")),
    ("PUT on the read path", lambda c: c.adapter.put("/v1/secret/data/netcheck/lab")),
    ("GET on the login path", lambda c: c.adapter.get("/v1/auth/approle/login")),
    ("login on another mount", lambda c: c.auth.approle.login("r", "s", mount_point="other")),
    ("revoke self", lambda c: c.adapter.post("/v1/auth/token/revoke-self")),
    ("list", lambda c: c.adapter.list("/v1/secret/metadata/netcheck")),
]


@pytest.mark.parametrize("call", [c for _, c in FORBIDDEN], ids=[n for n, _ in FORBIDDEN])
def test_no_other_call_can_be_sent(call, venv, fake):
    client = vault.build_client(vault.from_environment(venv))
    client.token = TOKEN
    with pytest.raises(vault.VaultCallRefused):
        call(client)
    assert fake.requests == []  # refusé AVANT l'envoi : le serveur n'a rien reçu


def test_a_refused_call_is_an_internal_defect_not_a_usage_error():
    assert not issubclass(vault.VaultCallRefused, CredentialError)


# --- Priorité ----------------------------------------------------------------------------------------


def _resolve(env, kind="PASS", driver="frr", fallback=INVENTORY_PASSWORD):
    return credentials.resolve(kind, driver, fallback, "r1", environ=env)


def test_vault_beats_lab_pass_and_the_inventory(venv, fake):
    value, source = _resolve({**venv, "LAB_PASS": LAB_PASSWORD})
    assert value == VAULT_PASSWORD and source.label == "Vault (secret/netcheck/lab)"


def test_lab_pass_wins_when_vault_is_not_configured():
    value, source = _resolve({"LAB_PASS": LAB_PASSWORD})
    assert value == LAB_PASSWORD and source.label == "variable LAB_PASS"


def test_inventory_comes_last_when_vault_has_no_such_key(venv, fake):
    fake.document = {"username": "vault-user"}  # pas de mot de passe dans Vault
    value, source = _resolve(venv)
    assert (value, source.label) == (INVENTORY_PASSWORD, "inventaire")
    value, source = _resolve({**venv, "LAB_PASS": LAB_PASSWORD})
    assert (value, source.label) == (LAB_PASSWORD, "variable LAB_PASS")


@pytest.mark.parametrize("above", ["NETCHECK_FRR_PASS", "NETCHECK_PASS"])
def test_a_variable_beats_vault_and_vault_is_not_even_contacted(above, venv, fake):
    value, source = _resolve({**venv, above: "from-variable-1"})
    assert (value, source.label) == ("from-variable-1", f"variable {above}")
    assert fake.requests == []


@pytest.mark.parametrize("above", ["NETCHECK_FRR_PASS_FILE", "NETCHECK_PASS_FILE"])
def test_a_secret_file_beats_vault(above, venv, fake, tmp_path):
    path = tmp_path / "pw"
    path.write_text("from-file-value\n", encoding="utf-8")
    path.chmod(0o600)
    value, source = _resolve({**venv, above: str(path)})
    assert value == "from-file-value" and source.label.startswith("fichier ")
    assert fake.requests == []


def test_the_documented_order_is_the_implemented_order():
    order = [(provider, var) for provider, var in credentials._candidates("PASS", "frr")]
    assert order == [
        ("env", "NETCHECK_FRR_PASS"),
        ("file", "NETCHECK_FRR_PASS_FILE"),
        ("env", "NETCHECK_PASS"),
        ("file", "NETCHECK_PASS_FILE"),
        ("vault", ""),
        ("env", "LAB_PASS"),
    ]


def test_a_driver_key_beats_the_generic_key_inside_vault(venv, fake):
    fake.document = {
        "password": "generic-password-1",
        "srlinux_password": "srlinux-password-2",
        "username": "generic-user",
        "frr_username": "frr-user",
    }
    assert _resolve(venv, "PASS", "srlinux")[0] == "srlinux-password-2"
    assert _resolve(venv, "PASS", "frr")[0] == "generic-password-1"
    assert _resolve(venv, "USER", "frr")[0] == "frr-user"
    assert _resolve(venv, "USER", "eos")[0] == "generic-user"


def test_an_empty_or_non_text_vault_value_is_an_error(venv, fake):
    for bad in ("", 12345678, ["x"]):
        vault.forget_cache()
        fake.document = {"password": bad}
        with pytest.raises(vault.VaultError, match="password"):
            _resolve(venv)


# --- Jamais de repli silencieux ------------------------------------------------------------------------

FAILURES = [
    (
        "wrong-secret-id",
        lambda f, t: _secret_id_file(t, "autre-secret-id-0000\n"),
        "authentification AppRole",
    ),
    ("login-denied-403", lambda f, t: setattr(f, "login_status", 403), "authentification AppRole"),
    ("login-500", lambda f, t: setattr(f, "login_status", 500), "indisponible"),
    ("sealed-503", lambda f, t: setattr(f, "login_status", 503), "indisponible"),
    ("secret-not-found", lambda f, t: setattr(f, "read_status", 404), "introuvable"),
    ("read-denied", lambda f, t: setattr(f, "read_status", 403), "politique"),
    ("read-500", lambda f, t: setattr(f, "read_status", 500), "indisponible"),
]


@pytest.mark.parametrize(
    ("setup", "fragment"), [(s, f) for _, s, f in FAILURES], ids=[n for n, _, _ in FAILURES]
)
def test_a_vault_failure_never_falls_back_to_lab_pass_or_the_inventory(setup, fragment, venv, fake, tmp_path):
    setup(fake, tmp_path)
    env = {**venv, "LAB_PASS": LAB_PASSWORD, "LAB_USER": "lab-user"}
    with pytest.raises(vault.VaultError, match=fragment) as raised:
        _resolve(env)
    text = str(raised.value)
    for secret in (SECRET_ID, TOKEN, VAULT_PASSWORD, LAB_PASSWORD, INVENTORY_PASSWORD):
        assert secret not in text


def test_unreachable_vault_is_an_explicit_error_without_fallback(venv):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    env = {**venv, vault.ENV_ADDR: f"http://127.0.0.1:{port}", "LAB_PASS": LAB_PASSWORD}
    with pytest.raises(vault.VaultError, match="injoignable"):
        _resolve(env)


def test_a_slow_vault_times_out_with_an_explicit_error(venv, fake, monkeypatch):
    monkeypatch.setattr(vault, "TIMEOUT", 0.3)
    fake.delay = 1.5
    with pytest.raises(vault.VaultError, match="injoignable"):
        _resolve({**venv, "LAB_PASS": LAB_PASSWORD})


def test_a_failure_is_not_cached_as_success(venv, fake):
    fake.read_status = 403
    with pytest.raises(vault.VaultError):
        _resolve(venv)
    fake.read_status = None
    assert _resolve(venv)[0] == VAULT_PASSWORD


def test_a_refused_secret_id_file_stops_before_any_request(venv, fake, tmp_path):
    env = {**venv, vault.ENV_SECRET_ID_FILE: _secret_id_file(tmp_path, mode=0o644)}
    with pytest.raises(CredentialError, match="droits") as raised:
        _resolve({**env, "LAB_PASS": LAB_PASSWORD})
    assert SECRET_ID not in str(raised.value)
    assert fake.requests == []


def test_a_missing_hvac_is_explicit_and_not_a_fallback(venv, monkeypatch):
    monkeypatch.setitem(sys.modules, "hvac", None)
    with pytest.raises(vault.VaultError, match=r"netcheck\[vault\]"):
        _resolve({**venv, "LAB_PASS": LAB_PASSWORD})


def test_a_redirect_is_never_followed(venv, fake):
    target = FakeVault()
    try:
        fake.redirect_to = target.addr + "/v1/stolen"
        with pytest.raises(vault.VaultError):
            _resolve(venv)
        assert target.requests == []
    finally:
        target.stop()


def test_environment_proxies_are_ignored(venv, fake, monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    assert _resolve(venv)[0] == VAULT_PASSWORD


# --- Configuration -------------------------------------------------------------------------------------


def test_vault_is_disabled_without_an_address():
    assert vault.from_environment({}) is None
    assert vault.from_environment({vault.ENV_ADDR: ""}) is None


def test_a_configured_vault_names_what_is_missing():
    with pytest.raises(vault.VaultError) as raised:
        vault.from_environment({vault.ENV_ADDR: "https://vault.example.org:8200"})
    for var in (vault.ENV_ROLE_ID, vault.ENV_SECRET_ID_FILE, vault.ENV_PATH):
        assert var in str(raised.value)


@pytest.mark.parametrize(
    "addr", ["http://vault.example.org:8200", "http://10.0.0.5:8200", "http://[2001:db8::1]:8200"]
)
def test_plain_http_is_refused_outside_loopback(addr, venv):
    with pytest.raises(vault.VaultError, match="bouclage"):
        vault.from_environment({**venv, vault.ENV_ADDR: addr})


@pytest.mark.parametrize(
    "addr",
    [
        "http://127.0.0.1:8200",
        "http://localhost:8200",
        "http://[::1]:8200",
        "http://127.0.0.5:8200",
        "https://vault.example.org:8200",
    ],
)
def test_loopback_http_and_any_https_are_accepted(addr, venv):
    assert vault.from_environment({**venv, vault.ENV_ADDR: addr}).addr == addr


@pytest.mark.parametrize(
    "addr",
    [
        "ftp://127.0.0.1",
        "127.0.0.1:8200",
        "https://",
        "https://user:pw@vault.example.org",
        "https://vault.example.org/v1",
        "https://vault.example.org?x=1",
        "https://vault.example.org:notaport",
    ],
)
def test_malformed_or_credentialed_addresses_are_refused(addr, venv):
    with pytest.raises(vault.VaultError):
        vault.from_environment({**venv, vault.ENV_ADDR: addr})


@pytest.mark.parametrize("bad", ["../etc", "/abs", "a//b", "a/../b", "a b", "a/", "..", "a\nb"])
def test_unsafe_paths_and_mounts_are_refused(bad, venv):
    with pytest.raises(vault.VaultError):
        vault.from_environment({**venv, vault.ENV_PATH: bad})
    with pytest.raises(vault.VaultError):
        vault.from_environment({**venv, vault.ENV_MOUNT: bad})


def test_a_missing_ca_file_is_refused(venv, tmp_path):
    with pytest.raises(vault.VaultError, match="CACERT"):
        vault.from_environment({**venv, vault.ENV_CACERT: str(tmp_path / "absent.pem")})


def test_the_mount_defaults_to_secret_and_can_be_changed(venv):
    assert vault.from_environment(venv).mount == "secret"
    assert vault.from_environment({**venv, vault.ENV_MOUNT: "kv"}).read_path == "/v1/kv/data/netcheck/lab"


def test_tls_verification_cannot_be_turned_off(venv):
    assert not any("VERIFY" in name or "INSECURE" in name for name in dir(vault) if name.isupper())
    client = vault.build_client(vault.from_environment(venv))
    assert client.adapter.session.verify is not False


# --- Secrets et expurgation ------------------------------------------------------------------------------


def test_the_token_and_the_secret_id_enter_the_redaction_registry(venv, fake):
    vault.lookup("PASS", "frr", venv)
    masked = secrets.redact_known(f"a {TOKEN} b {SECRET_ID} c")
    assert TOKEN not in masked and SECRET_ID not in masked and masked.count("****") == 2


def test_the_vault_password_is_a_secretstr_with_the_vault_source(venv, fake, tmp_path):
    router = credentials.resolve_device(
        {"name": "r1", "driver": "frr", "username": "u", "password": "p"},
        environ={**venv, "LAB_PASS": LAB_PASSWORD},
    )
    assert isinstance(router["password"], secrets.SecretStr) and router["password"] == VAULT_PASSWORD
    assert router["credential_sources"]["password"] == "Vault (secret/netcheck/lab)"
    assert VAULT_PASSWORD not in repr(router) and VAULT_PASSWORD not in str(router["credential_sources"])


# --- Bout en bout par la CLI -----------------------------------------------------------------------------


def _inventory_file(tmp_path):
    path = tmp_path / "inv.yml"
    path.write_text(
        "lab: true\n"
        f"defaults: {{device_type: linux, username: inv-user, password: {INVENTORY_PASSWORD}}}\n"
        "routers:\n  r1: {host: 192.0.2.1}\n",
        encoding="utf-8",
    )
    return str(path)


def _cli_env(monkeypatch, venv, tmp_path):
    for name, value in venv.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("LAB_PASS", LAB_PASSWORD)
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)
    used = []

    def collect(routers, *_a, **_k):
        used.extend(r["password"].reveal() for r in routers.values())
        state = DeviceState(
            name="r1", host="192.0.2.1", timestamp="2026-01-01T00:00:00+00:00", reachable=True
        )
        return {"r1": (True, state)}

    monkeypatch.setattr(collector, "collect_all", collect)
    return used


def test_snapshot_uses_vault_says_so_and_leaks_nothing(venv, fake, monkeypatch, tmp_path, capsys):
    used = _cli_env(monkeypatch, venv, tmp_path)
    assert cli.main(["snapshot", "s", "-i", _inventory_file(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert used == [VAULT_PASSWORD]  # la connexion reçoit bien le mot de passe de Vault
    assert "mot de passe : Vault (secret/netcheck/lab) (r1)" in captured.out
    written = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "snaps" / "s").iterdir())
    assert "Vault (secret/netcheck/lab)" in written
    everything = captured.out + captured.err + written
    for secret in (VAULT_PASSWORD, SECRET_ID, TOKEN, LAB_PASSWORD, INVENTORY_PASSWORD):
        assert secret not in everything
    assert fake.requests == [LOGIN, READ]


def test_check_json_report_names_vault_without_secrets(venv, fake, monkeypatch, tmp_path, capsys):
    _cli_env(monkeypatch, venv, tmp_path)
    out = tmp_path / "check.json"
    code = cli.main(["check", "-i", _inventory_file(tmp_path), "--json", str(out)])
    assert code in (0, 1, 2)
    captured = capsys.readouterr()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["credential_sources"]["mot de passe"] == {"Vault (secret/netcheck/lab)": ["r1"]}
    everything = captured.out + captured.err + out.read_text(encoding="utf-8")
    for secret in (VAULT_PASSWORD, SECRET_ID, TOKEN):
        assert secret not in everything


def test_cli_exits_3_with_one_line_when_vault_is_down_and_never_connects(venv, monkeypatch, tmp_path, capsys):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    venv = {**venv, vault.ENV_ADDR: f"http://127.0.0.1:{port}"}
    used = _cli_env(monkeypatch, venv, tmp_path)
    code = cli.main(["snapshot", "s", "-i", _inventory_file(tmp_path)])
    err = capsys.readouterr().err
    assert code == 3 and used == []  # aucune collecte, aucun repli sur LAB_PASS
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 1 and "injoignable" in lines[0] and "Traceback" not in err
    assert LAB_PASSWORD not in err


def test_the_error_without_any_value_names_vault_when_it_is_configured(venv, fake):
    fake.document = {}  # Vault configuré, mais sans cette clé
    with pytest.raises(CredentialError, match="Vault"):
        credentials.resolve("PASS", "frr", None, "r1", environ=venv)
    with pytest.raises(CredentialError) as raised:
        credentials.resolve("PASS", "frr", None, "r1", environ={})
    assert "Vault" not in str(raised.value)  # Vault non configuré : pas de bruit


def test_a_empty_address_variable_means_disabled_not_misconfigured(venv):
    assert vault.from_environment({**venv, vault.ENV_ADDR: ""}) is None


# --- TLS : la vérification est active, une autorité se donne par NETCHECK_VAULT_CACERT ----------------------


@pytest.fixture
def tls_fake(tmp_path):
    import shutil
    import ssl
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl absent")
    key, crt = tmp_path / "key.pem", tmp_path / "crt.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign",
        ],
        check=True,
        capture_output=True,
    )
    server = FakeVault()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(crt), str(key))
    server.server.socket = context.wrap_socket(server.server.socket, server_side=True)
    server.tls_addr = server.addr.replace("http://", "https://")
    server.crt = str(crt)
    yield server
    server.stop()


def test_an_untrusted_certificate_is_refused(tls_fake, tmp_path):
    env = {
        vault.ENV_ADDR: tls_fake.tls_addr,
        vault.ENV_ROLE_ID: ROLE_ID,
        vault.ENV_SECRET_ID_FILE: _secret_id_file(tmp_path),
        vault.ENV_PATH: "netcheck/lab",
    }
    with pytest.raises(vault.VaultError, match="certificat TLS"):
        vault.lookup("PASS", "frr", {**env, "LAB_PASS": LAB_PASSWORD})
    assert tls_fake.requests == []  # la poignée de main échoue : aucune requête, aucun jeton


def test_a_certificate_signed_by_the_given_authority_is_accepted(tls_fake, tmp_path):
    env = {
        vault.ENV_ADDR: tls_fake.tls_addr,
        vault.ENV_ROLE_ID: ROLE_ID,
        vault.ENV_SECRET_ID_FILE: _secret_id_file(tmp_path),
        vault.ENV_PATH: "netcheck/lab",
        vault.ENV_CACERT: tls_fake.crt,
    }
    assert vault.lookup("PASS", "frr", env)[0] == VAULT_PASSWORD
    assert tls_fake.requests == [LOGIN, READ]


# --- La documentation décrit l'ordre implémenté ------------------------------------------------------------


def test_the_readme_table_lists_the_priority_order_in_the_implemented_order():
    readme = (inventory.REPO_ROOT / "README.md").read_text(encoding="utf-8")
    rows = [ln for ln in readme.splitlines() if ln.startswith("| ") and ln.split("|")[1].strip().isdigit()]
    rows = [ln for ln in rows if int(ln.split("|")[1]) <= 7][:7]
    assert [int(ln.split("|")[1]) for ln in rows] == [1, 2, 3, 4, 5, 6, 7]
    expected = [
        "NETCHECK_<DRIVER>_USER",
        "NETCHECK_<DRIVER>_USER_FILE",
        "NETCHECK_USER",
        "NETCHECK_USER_FILE",
        "Vault",
        "LAB_USER",
        "inventaire",
    ]
    for row, marker in zip(rows, expected, strict=True):
        assert marker in row, (marker, row)
    order = [(provider, var) for provider, var in credentials._candidates("USER", "frr")]
    assert [p for p, _ in order] == ["env", "file", "env", "file", "vault", "env"]  # 5e niveau : Vault


# --- Une clé SSH configurée écarte Vault ENTIÈREMENT : ni mot de passe, ni utilisateur (revue de C4) --


def _key_cli(monkeypatch, venv, tmp_path, user="inv-user"):
    """Environnement Vault complet + une clé configurée ; collecteur factice qui note ce qu'il reçoit."""
    from sshd_fake import make_key

    for name, value in venv.items():
        monkeypatch.setenv(name, value)
    key = tmp_path / "id_netcheck"
    make_key(key)
    monkeypatch.setenv("NETCHECK_KEY_FILE", str(key))
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)
    received = []

    def collect(routers, *_a, **_k):
        received.extend((r["username"], r["key_file"], "password" in r) for r in routers.values())
        state = DeviceState(
            name="r1", host="192.0.2.1", timestamp="2026-01-01T00:00:00+00:00", reachable=True
        )
        return {"r1": (True, state)}

    monkeypatch.setattr(collector, "collect_all", collect)
    inv = tmp_path / "inv_key.yml"
    username = f"username: {user}, " if user else ""
    inv.write_text(
        "lab: true\n"
        f"defaults: {{device_type: linux, {username}password: {INVENTORY_PASSWORD}}}\n"
        "routers:\n  r1: {host: 192.0.2.1}\n",
        encoding="utf-8",
    )
    return str(inv), str(key), received


def test_a_configured_key_means_vault_receives_zero_requests(venv, fake, monkeypatch, tmp_path, capsys):
    inv, key, received = _key_cli(monkeypatch, venv, tmp_path)
    assert cli.main(["snapshot", "s", "-i", inv]) == 0
    out = capsys.readouterr().out
    assert fake.requests == []  # le serveur factice n'a reçu AUCUNE requête, pas même l'ouverture de session
    # l'utilisateur vient de l'inventaire, pas du secret Vault (`username: vault-user`), sans mot de passe
    assert received == [("inv-user", key, False)]
    assert "utilisateur : inventaire (r1)" in out
    assert "Vault non consulté : clé configurée (r1)" in out
    assert "Vault (secret/netcheck/lab)" not in out
    assert VAULT_PASSWORD not in out


def test_a_user_variable_is_used_and_vault_still_receives_nothing(venv, fake, monkeypatch, tmp_path, capsys):
    inv, key, received = _key_cli(monkeypatch, venv, tmp_path)
    monkeypatch.setenv("NETCHECK_USER", "from-variable")
    assert cli.main(["snapshot", "s", "-i", inv]) == 0
    assert fake.requests == [] and received == [("from-variable", key, False)]
    assert "utilisateur : variable NETCHECK_USER (r1)" in capsys.readouterr().out


def test_a_missing_user_with_a_key_is_a_clear_usage_error_and_vault_is_not_consulted(
    venv, fake, monkeypatch, tmp_path, capsys
):
    inv, _key, received = _key_cli(monkeypatch, venv, tmp_path, user=None)
    assert cli.main(["snapshot", "s", "-i", inv]) == 3
    err = capsys.readouterr().err
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 1 and "Traceback" not in err
    assert "utilisateur introuvable pour r1 : clé configurée, Vault non consulté" in lines[0]
    assert fake.requests == [] and received == []  # ni requête Vault, ni collecte, ni repli


def test_without_a_key_vault_is_still_consulted_for_the_user(venv, fake):
    router = {
        "name": "r1",
        "host": "192.0.2.1",
        "driver": "frr",
        "device_type": "linux",
        "password": "x" * 12,
    }
    resolved = credentials.resolve_device(router, environ=venv)
    assert resolved["username"] == "vault-user"  # le témoin : sans clé, rien n'a changé
    assert fake.requests == [LOGIN, READ]
