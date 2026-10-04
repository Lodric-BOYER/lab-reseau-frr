"""Authentification par clé SSH et bloc `bastion:` de l'inventaire (phase C4) : fichier de clé soumis aux
règles de C2, phrase secrète en SecretStr, priorité, source « clé : chemin », rien de secret en sortie.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sshd_fake import make_key

from netcheck import cli, collector, credentials, inventory, snapshot
from netcheck.credentials import CredentialError
from netcheck.model import DeviceState
from netcheck.secrets import SecretStr
from netcheck.sshkeys import Bastion

PASSPHRASE = "Passphrase-Sentinel-31415"
INVENTORY_PASSWORD = "inventory-password-xyz"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="droits POSIX")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")):
            monkeypatch.delenv(var, raising=False)


def _router(**extra) -> dict:
    return {
        "name": "r1",
        "host": "192.0.2.1",
        "driver": "frr",
        "device_type": "linux",
        "username": "netops",
        "password": INVENTORY_PASSWORD,
        **extra,
    }


def _key(tmp_path, name="id_netcheck", passphrase=None):
    path = tmp_path / name
    make_key(path, passphrase)
    return path


# --- Les règles de C2 s'appliquent au fichier de clé -----------------------------------------------------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o604])
def test_a_key_file_readable_by_others_is_refused(mode, tmp_path):
    path = _key(tmp_path)
    path.chmod(mode)
    with pytest.raises(CredentialError, match="droits") as raised:
        credentials.resolve_device(_router(key_file=str(path)), environ={})
    assert path.read_text(encoding="utf-8")[:30] not in str(raised.value)  # jamais le contenu


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_0600_and_0400_are_accepted(mode, tmp_path):
    path = _key(tmp_path)
    path.chmod(mode)
    assert credentials.resolve_device(_router(key_file=str(path)), environ={})["key_file"] == str(path)


def test_a_symlink_a_directory_and_a_missing_file_are_refused(tmp_path):
    real = _key(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(CredentialError, match="lien symbolique"):
        credentials.resolve_device(_router(key_file=str(link)), environ={})
    with pytest.raises(CredentialError, match="pas un fichier régulier"):
        credentials.resolve_device(_router(key_file=str(tmp_path)), environ={})
    with pytest.raises(CredentialError, match="illisible"):
        credentials.resolve_device(_router(key_file=str(tmp_path / "absent")), environ={})


def test_a_huge_file_is_refused(tmp_path):
    path = tmp_path / "big"
    path.write_bytes(b"x" * 70000)
    path.chmod(0o600)
    with pytest.raises(CredentialError, match="octets"):
        credentials.resolve_device(_router(key_file=str(path)), environ={})


def test_a_file_that_is_not_a_key_is_refused_without_quoting_it(tmp_path):
    path = tmp_path / "garbage"
    path.write_text("mot-de-passe-ou-autre-secret-123456\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(CredentialError, match="illisible ou invalide") as raised:
        credentials.resolve_device(_router(key_file=str(path)), environ={})
    assert "mot-de-passe" not in str(raised.value)


# --- Phrase secrète ------------------------------------------------------------------------------------


def test_an_encrypted_key_without_passphrase_says_so(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    with pytest.raises(CredentialError, match="phrase secrète") as raised:
        credentials.resolve_device(_router(key_file=str(path)), environ={})
    assert PASSPHRASE not in str(raised.value)


def test_a_wrong_passphrase_is_refused_without_quoting_it(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    with pytest.raises(CredentialError, match="incorrecte") as raised:
        credentials.resolve_device(
            _router(key_file=str(path)), environ={"NETCHECK_KEY_PASSPHRASE": "faux-faux-1"}
        )
    assert "faux-faux-1" not in str(raised.value)


def _passfile(tmp_path, content=PASSPHRASE + "\n", mode=0o600):
    path = tmp_path / "pass"
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return str(path)


def test_the_passphrase_comes_from_a_0600_file_and_is_a_secretstr(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    router = credentials.resolve_device(
        _router(key_file=str(path)), environ={"NETCHECK_KEY_PASSPHRASE_FILE": _passfile(tmp_path)}
    )
    assert isinstance(router["key_passphrase"], SecretStr) and router["key_passphrase"] == PASSPHRASE
    assert PASSPHRASE not in repr(router) and PASSPHRASE not in str(router["credential_sources"])


def test_a_passphrase_file_with_loose_permissions_is_refused(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    with pytest.raises(CredentialError, match="droits"):
        credentials.resolve_device(
            _router(key_file=str(path)),
            environ={"NETCHECK_KEY_PASSPHRASE_FILE": _passfile(tmp_path, mode=0o644)},
        )


def test_passphrase_priority_driver_before_generic_variable_before_file(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    env = {
        "NETCHECK_FRR_KEY_PASSPHRASE": PASSPHRASE,
        "NETCHECK_KEY_PASSPHRASE": "mauvais-1",
        "NETCHECK_KEY_PASSPHRASE_FILE": _passfile(tmp_path, "mauvais-2\n"),
    }
    assert (
        credentials.resolve_device(_router(key_file=str(path)), environ=env)["key_passphrase"] == PASSPHRASE
    )
    env2 = {
        "NETCHECK_KEY_PASSPHRASE": PASSPHRASE,
        "NETCHECK_KEY_PASSPHRASE_FILE": _passfile(tmp_path, "mauvais\n"),
    }
    assert (
        credentials.resolve_device(_router(key_file=str(path)), environ=env2)["key_passphrase"] == PASSPHRASE
    )


def test_a_key_without_passphrase_has_none(tmp_path):
    path = _key(tmp_path)
    assert credentials.resolve_device(_router(key_file=str(path)), environ={})["key_passphrase"] is None


# --- Priorité et source --------------------------------------------------------------------------------


def test_key_priority_driver_variable_then_generic_variable_then_inventory(tmp_path):
    a, b, c = (_key(tmp_path, n) for n in ("a", "b", "c"))
    inv = _router(key_file=str(c))
    both = {"NETCHECK_FRR_KEY_FILE": str(a), "NETCHECK_KEY_FILE": str(b)}
    assert credentials.resolve_device(inv, environ=both)["key_file"] == str(a)
    assert credentials.resolve_device(inv, environ={"NETCHECK_KEY_FILE": str(b)})["key_file"] == str(b)
    assert credentials.resolve_device(inv, environ={})["key_file"] == str(c)
    assert credentials.resolve_device({**inv, "driver": "srlinux"}, environ=both)["key_file"] == str(b)


def test_a_configured_key_means_no_password_ever(tmp_path):
    path = _key(tmp_path)
    router = credentials.resolve_device(
        _router(key_file=str(path)),
        environ={"LAB_PASS": "lab-pass-from-LAB_PASS", "NETCHECK_PASS": "var-pass-xyz"},
    )
    assert "password" not in router  # ni résolu, ni présenté : jamais en repli
    assert router["credential_sources"] == {
        "username": "inventaire",
        "key": str(path),
        "password_ignored": "clé configurée",
    }
    assert INVENTORY_PASSWORD not in repr(router)


def test_without_a_key_nothing_changes(tmp_path):
    router = credentials.resolve_device(_router(), environ={})
    assert router["password"] == INVENTORY_PASSWORD and "key_file" not in router


def test_the_source_is_shown_as_key_colon_path(tmp_path):
    path = _key(tmp_path)
    routers = {
        "r1": credentials.resolve_device(_router(key_file=str(path)), environ={}),
        "r2": credentials.resolve_device(_router(name="r2"), environ={}),
    }
    described = credentials.describe_sources(routers)
    assert described["clé"] == {str(path): ["r1"]}
    assert described["mot de passe"] == {"inventaire": ["r2"]}
    assert f"clé : {path} (r1)" in credentials.format_sources(described)


def test_the_key_kind_is_absent_when_no_router_uses_one():
    described = credentials.describe_sources({"r1": credentials.resolve_device(_router(), environ={})})
    assert "clé" not in described and "bastion" not in described


# --- Bloc bastion de l'inventaire ----------------------------------------------------------------------


def _inventory(tmp_path, bastion_block: str, extra: str = "") -> str:
    path = tmp_path / "inv.yml"
    path.write_text(
        "lab: true\n"
        f"defaults: {{device_type: linux, username: u, password: {INVENTORY_PASSWORD}}}\n"
        f"{bastion_block}"
        f"routers:\n  r1: {{host: 192.0.2.1{extra}}}\n",
        encoding="utf-8",
    )
    return str(path)


def _bastion_block(key_path, **extra) -> str:
    fields = {"host": "192.0.2.2", "username": "jump", "key_file": str(key_path), **extra}
    return "bastion:\n" + "".join(f"  {k}: {v}\n" for k, v in fields.items())


def test_the_bastion_is_resolved_and_shared_by_every_router(tmp_path):
    key = _key(tmp_path)
    inv = inventory.load(path=_inventory(tmp_path, _bastion_block(key, port=2222)))
    assert isinstance(inv.bastion, Bastion) and inv.bastion.label == "jump@192.0.2.2:2222"
    assert inv.routers["r1"]["bastion"] is inv.bastion and inv.bastion.key.path == str(key)


def test_offline_loading_ignores_the_bastion_key(tmp_path):
    path = _inventory(tmp_path, _bastion_block(tmp_path / "absent-key"))
    inv = inventory.load(path=path, resolve_credentials=False)  # hors ligne : aucune clé n'est lue
    assert inv.bastion is None and "bastion" not in inv.routers["r1"]


def test_the_bastion_key_can_come_from_the_environment(tmp_path, monkeypatch):
    key = _key(tmp_path)
    block = "bastion:\n  host: 192.0.2.2\n  username: jump\n"  # pas de key_file dans l'inventaire
    with pytest.raises(CredentialError, match="aucune clé"):
        inventory.load(path=_inventory(tmp_path, block))
    monkeypatch.setenv("NETCHECK_BASTION_KEY_FILE", str(key))
    assert inventory.load(path=_inventory(tmp_path, block)).bastion.key.path == str(key)


def test_the_bastion_passphrase_is_a_secretstr_from_a_file(tmp_path, monkeypatch):
    key = _key(tmp_path, passphrase=PASSPHRASE)
    block = _bastion_block(key)
    with pytest.raises(CredentialError, match="phrase secrète"):
        inventory.load(path=_inventory(tmp_path, block))
    monkeypatch.setenv("NETCHECK_BASTION_KEY_PASSPHRASE_FILE", _passfile(tmp_path))
    inv = inventory.load(path=_inventory(tmp_path, block))
    assert isinstance(inv.bastion.key.passphrase, SecretStr) and PASSPHRASE not in repr(inv.bastion)


def test_the_bastion_key_file_follows_the_c2_rules(tmp_path):
    key = _key(tmp_path)
    key.chmod(0o644)
    with pytest.raises(CredentialError, match="droits"):
        inventory.load(path=_inventory(tmp_path, _bastion_block(key)))


def test_a_bastion_never_has_a_password(tmp_path):
    key = _key(tmp_path)
    with pytest.raises(Exception, match="mot de passe") as raised:
        inventory.load(path=_inventory(tmp_path, _bastion_block(key, password="x")))
    assert "x" != str(raised.value)


@pytest.mark.parametrize(
    ("block", "fragment"),
    [
        ("bastion: jump@host\n", "objet"),
        ("bastion:\n  username: jump\n", "host"),
        ("bastion:\n  host: h\n", "username"),
        ("bastion:\n  host: h\n  username: jump\n  port: 99999\n", "port"),
        ("bastion:\n  host: h\n  username: jump\n  port: true\n", "port"),
        ("bastion:\n  host: h\n  username: jump\n  key_file: 5\n", "key_file"),
        ("bastion:\n  host: h\n  username: jump\n  agent: yes\n", "inconnue"),
        ("bastion:\n  host: h\n  username: jump\n  ForwardAgent: yes\n", "inconnue"),
    ],
)
def test_a_bad_bastion_block_is_a_usage_error(block, fragment, tmp_path):
    with pytest.raises(ValueError, match=fragment):
        inventory.load(path=_inventory(tmp_path, block))


def test_bastion_is_declared_once_not_per_router(tmp_path):
    key = _key(tmp_path)
    with pytest.raises(ValueError, match="une fois"):
        inventory.load(path=_inventory(tmp_path, _bastion_block(key), extra=", bastion: x"))


# --- Bout en bout par la CLI -----------------------------------------------------------------------------


def _cli_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)
    used = []

    def collect(routers, *_a, **_k):
        used.extend(
            sorted(k for r in routers.values() for k in r if k in {"password", "key_file", "bastion"})
        )
        state = DeviceState(
            name="r1", host="192.0.2.1", timestamp="2026-01-01T00:00:00+00:00", reachable=True
        )
        return {"r1": (True, state)}

    monkeypatch.setattr(collector, "collect_all", collect)
    return used


def test_snapshot_says_key_and_bastion_and_leaks_nothing(monkeypatch, tmp_path, capsys):
    router_key = _key(tmp_path, "router", PASSPHRASE)
    bastion_key = _key(tmp_path, "bastion_key", PASSPHRASE + "-bastion")
    pass_router = tmp_path / "pass_router"
    pass_router.write_text(PASSPHRASE + "\n", encoding="utf-8")
    pass_router.chmod(0o600)
    pass_bastion = tmp_path / "pass_bastion"
    pass_bastion.write_text(PASSPHRASE + "-bastion\n", encoding="utf-8")
    pass_bastion.chmod(0o600)
    monkeypatch.setenv("NETCHECK_KEY_FILE", str(router_key))
    monkeypatch.setenv("NETCHECK_KEY_PASSPHRASE_FILE", str(pass_router))
    monkeypatch.setenv("NETCHECK_BASTION_KEY_PASSPHRASE_FILE", str(pass_bastion))
    used = _cli_setup(monkeypatch, tmp_path)
    inv = _inventory(tmp_path, _bastion_block(bastion_key))
    assert cli.main(["snapshot", "s", "-i", inv]) == 0
    captured = capsys.readouterr()
    assert f"clé : {router_key} (r1)" in captured.out
    assert "bastion : jump@192.0.2.2 (clé " + str(bastion_key) + ")" in captured.out
    assert "Identifiants, mot de passe :" not in captured.out  # aucun mot de passe utilisé : la clé seule
    # celui de l'inventaire est dit ignoré
    assert "mot de passe ignoré : clé configurée (r1)" in captured.out
    assert used == ["bastion", "key_file"]  # le collecteur reçoit la clé et le bastion, pas de mot de passe
    written = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "snaps" / "s").iterdir())
    everything = captured.out + captured.err + written
    for secret in (PASSPHRASE, PASSPHRASE + "-bastion", INVENTORY_PASSWORD):
        assert secret not in everything
    assert "BEGIN OPENSSH PRIVATE KEY" not in everything
    meta = json.loads((tmp_path / "snaps" / "s" / "meta.json").read_text(encoding="utf-8"))
    assert meta["credential_sources"]["clé"] == {str(router_key): ["r1"]}
    assert "bastion" in meta["credential_sources"]


def test_a_bad_bastion_key_is_a_one_line_usage_error_before_any_connection(monkeypatch, tmp_path, capsys):
    key = _key(tmp_path)
    key.chmod(0o644)
    used = _cli_setup(monkeypatch, tmp_path)
    assert cli.main(["snapshot", "s", "-i", _inventory(tmp_path, _bastion_block(key))]) == 3
    err = capsys.readouterr().err
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 1 and "droits" in lines[0] and "Traceback" not in err
    assert used == []


# --- Cas ajoutés après les mutations -----------------------------------------------------------------


def _write_key(path, kind, passphrase=None, fmt="OpenSSH"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    private = (
        rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    )
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    layout = getattr(serialization.PrivateFormat, fmt)
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, layout, encryption))
    path.chmod(0o600)


@pytest.mark.parametrize(
    ("kind", "fmt"),
    [
        ("rsa", "OpenSSH"),
        ("rsa", "TraditionalOpenSSL"),
        ("ecdsa", "OpenSSH"),
        ("ecdsa", "TraditionalOpenSSL"),
    ],
)
@pytest.mark.parametrize("passphrase", [None, PASSPHRASE])
def test_rsa_and_ecdsa_keys_load_too_with_or_without_a_passphrase(kind, fmt, passphrase, tmp_path):
    path = tmp_path / f"id_{kind}"
    _write_key(path, kind, passphrase, fmt)
    env = {"NETCHECK_KEY_PASSPHRASE": passphrase} if passphrase else {}
    assert credentials.resolve_device(_router(key_file=str(path)), environ=env)["key_file"] == str(path)


def test_passphrase_variable_beats_file_at_the_same_level(tmp_path):
    path = _key(tmp_path, passphrase=PASSPHRASE)
    for prefix in ("NETCHECK_FRR_KEY_PASSPHRASE", "NETCHECK_KEY_PASSPHRASE"):
        env = {prefix: PASSPHRASE, prefix + "_FILE": _passfile(tmp_path, "mauvaise-phrase\n")}
        resolved = credentials.resolve_device(_router(key_file=str(path)), environ=env)
        assert resolved["key_passphrase"] == PASSPHRASE


@pytest.mark.parametrize("value", ["5", "''", "[a]", "true"])
def test_a_router_key_file_that_is_not_a_path_is_a_usage_error(value, tmp_path):
    path = tmp_path / "inv.yml"
    path.write_text(
        "lab: true\ndefaults: {device_type: linux, username: u, password: pw-long-enough}\n"
        f"routers:\n  r1: {{host: 192.0.2.1, key_file: {value}}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="key_file"):
        inventory.load(path=path)


# --- Clé configurée ET mot de passe fourni : « mot de passe ignoré : clé configurée » ------------------


@pytest.mark.parametrize(
    ("label", "environ", "router_extra"),
    [
        ("variable NETCHECK_PASS", {"NETCHECK_PASS": "var-pass-xyz"}, {"password": None}),
        ("variable du driver", {"NETCHECK_FRR_PASS": "var-pass-xyz"}, {"password": None}),
        # un fichier de mot de passe introuvable ne fait pas échouer : il n'est pas lu, seule sa présence
        # compte
        ("fichier NETCHECK_PASS_FILE", {"NETCHECK_PASS_FILE": "/nonexistent/pass"}, {"password": None}),
        ("fichier du driver", {"NETCHECK_FRR_PASS_FILE": "/nonexistent/pass"}, {"password": None}),
        ("LAB_PASS", {"LAB_PASS": "lab-pass-xyz"}, {"password": None}),
        ("Vault configuré", {"NETCHECK_VAULT_ADDR": "https://vault.invalid:8200"}, {"password": None}),
        ("inventaire", {}, {}),
    ],
)
def test_a_password_provided_anywhere_is_reported_as_ignored_when_a_key_is_configured(
    label, environ, router_extra, tmp_path, monkeypatch
):
    from netcheck import vault

    monkeypatch.setattr(vault, "lookup", lambda *a, **k: pytest.fail("Vault ne doit pas être interrogé"))
    path = _key(tmp_path)
    router = {k: v for k, v in _router(key_file=str(path), **router_extra).items() if v is not None}
    env = {"NETCHECK_USER": "netops", **environ}  # identifiant fourni : aucun besoin de Vault
    resolved = credentials.resolve_device(router, environ=env)
    assert "password" not in resolved
    described = credentials.describe_sources({"r1": resolved})
    assert described["mot de passe ignoré"] == {"clé configurée": ["r1"]}
    assert "mot de passe" not in credentials.format_sources(described)[0]
    assert "mot de passe ignoré : clé configurée (r1)" in credentials.format_sources(described)


def test_no_password_line_when_a_key_is_configured_and_no_password_exists_anywhere(tmp_path):
    path = _key(tmp_path)
    router = {k: v for k, v in _router(key_file=str(path)).items() if k != "password"}
    described = credentials.describe_sources({"r1": credentials.resolve_device(router, environ={})})
    assert "mot de passe ignoré" not in described
    assert not any(line.startswith("mot de passe") for line in credentials.format_sources(described))


def test_the_ignored_line_never_appears_without_a_key():
    described = credentials.describe_sources({"r1": credentials.resolve_device(_router(), environ={})})
    assert "mot de passe ignoré" not in described and "mot de passe" in described


def test_vault_is_never_asked_for_the_password_when_a_key_is_configured(tmp_path, monkeypatch):
    from netcheck import vault

    asked = []

    def spy(kind, driver, env):
        asked.append(kind)

    monkeypatch.setattr(vault, "lookup", spy)
    path = _key(tmp_path)
    env = {"NETCHECK_VAULT_ADDR": "https://vault.invalid:8200"}
    # identifiant de l'inventaire : Vault peut encore être consulté pour l'utilisateur (ordre de C3), jamais
    # pour le mot de passe
    credentials.resolve_device(_router(key_file=str(path)), environ=env)
    assert asked == ["USER"]
    # sans clé, le mot de passe est bien demandé : la différence vient de la clé
    asked.clear()
    credentials.resolve_device(_router(), environ=env)
    assert asked == ["USER", "PASS"]


def test_vault_is_not_contacted_at_all_when_a_key_and_a_user_are_given(tmp_path, monkeypatch):
    from netcheck import vault

    monkeypatch.setattr(vault, "lookup", lambda *a, **k: pytest.fail("Vault contacté"))
    path = _key(tmp_path)
    env = {"NETCHECK_VAULT_ADDR": "https://vault.invalid:8200", "NETCHECK_USER": "netops"}
    resolved = credentials.resolve_device(_router(key_file=str(path)), environ=env)
    assert resolved["credential_sources"]["password_ignored"] == "clé configurée"


# --- Contournement du bug paramiko 5.0.0 : une clé chiffrée de CHAQUE type se charge ------------------


def _encrypted_key(path, kind):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    private = {
        "rsa": lambda: rsa.generate_private_key(65537, 2048),
        "ecdsa": lambda: ec.generate_private_key(ec.SECP256R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate,
    }[kind]()
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.BestAvailableEncryption(PASSPHRASE.encode()),
        )
    )
    path.chmod(0o600)


@pytest.mark.parametrize("kind", ["rsa", "ecdsa", "ed25519"])
def test_an_encrypted_key_of_each_type_loads_as_the_right_paramiko_class(kind, tmp_path):
    import paramiko

    from netcheck import sshkeys

    path = tmp_path / f"id_{kind}"
    _encrypted_key(path, kind)
    expected = {"rsa": paramiko.RSAKey, "ecdsa": paramiko.ECDSAKey, "ed25519": paramiko.Ed25519Key}[kind]
    loaded = sshkeys.load_private_key(sshkeys.KeySpec(str(path), SecretStr(PASSPHRASE, "test")), "clé de r1")
    assert isinstance(loaded, expected)


@pytest.mark.parametrize("kind", ["rsa", "ecdsa", "ed25519"])
def test_an_encrypted_key_of_each_type_with_a_wrong_or_missing_passphrase_is_refused(kind, tmp_path):
    from netcheck import sshkeys

    path = tmp_path / f"id_{kind}"
    _encrypted_key(path, kind)
    with pytest.raises(CredentialError, match="phrase secrète incorrecte") as wrong:
        wrong_spec = sshkeys.KeySpec(str(path), SecretStr("mauvaise-phrase-1", "test"))
        sshkeys.load_private_key(wrong_spec, "clé de r1")
    assert PASSPHRASE not in str(wrong.value) and "mauvaise-phrase-1" not in str(wrong.value)
    with pytest.raises(CredentialError, match="protégée par une phrase secrète"):
        sshkeys.load_private_key(sshkeys.KeySpec(str(path), None), "clé de r1")


def test_the_buggy_paramiko_from_path_api_is_not_used():
    from netcheck import sshkeys

    source = Path(sshkeys.__file__).read_text()
    assert ".from_path(" not in source and "from_private_key_file(" in source
