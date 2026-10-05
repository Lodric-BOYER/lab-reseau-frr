"""Résolution des identifiants : variables, fichiers 0600, inventaire (phase C2, netcheck/credentials.py)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from netcheck import cli, collector, credentials, inventory, snapshot
from netcheck.credentials import CredentialError
from netcheck.secrets import SecretStr

SECRET = "Fichier-Secret-77aa91"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="droits POSIX")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")):
            monkeypatch.delenv(var, raising=False)


def _secret_file(tmp_path: Path, content: str = SECRET + "\n", mode: int = 0o600, name: str = "s") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    p.chmod(mode)
    return p


# -- Ordre de priorité ------------------------------------------------------------------------

def _resolve(env: dict, fallback="inv-value", driver="srlinux", kind="PASS"):
    return credentials.resolve(kind, driver, fallback, "r5", environ=env)


def test_priority_order_from_most_to_least_specific(tmp_path):
    f = {n: _secret_file(tmp_path, name=n, content=f"fichier-{n}-valeur\n") for n in ("a", "b", "c")}
    env = {
        "NETCHECK_SRLINUX_PASS": "driver-env",
        "NETCHECK_SRLINUX_PASS_FILE": str(f["a"]),
        "NETCHECK_PASS": "generic-env",
        "NETCHECK_PASS_FILE": str(f["b"]),
        "LAB_PASS": "lab-env",
    }
    # (variable qui doit gagner, valeur attendue, source attendue), du plus au moins prioritaire.
    expected = [
        ("NETCHECK_SRLINUX_PASS", "driver-env", "variable NETCHECK_SRLINUX_PASS"),
        ("NETCHECK_SRLINUX_PASS_FILE", "fichier-a-valeur", f"fichier {f['a']}"),
        ("NETCHECK_PASS", "generic-env", "variable NETCHECK_PASS"),
        ("NETCHECK_PASS_FILE", "fichier-b-valeur", f"fichier {f['b']}"),
        ("LAB_PASS", "lab-env", "variable LAB_PASS"),
    ]
    for winner, value, label in expected:
        got, source = _resolve(env)
        assert (got, source.label) == (value, label)
        env.pop(winner)          # on retire le niveau gagnant : le suivant doit prendre sa place
    got, source = _resolve(env)
    assert (got, source.label) == ("inv-value", "inventaire")


def test_driver_level_beats_generic_even_across_providers(tmp_path):
    # Le NETCHECK_PASS posé pour FRR n'écrase pas le fichier propre à SR Linux (garantie de la v0.3, D1).
    f = _secret_file(tmp_path)
    env = {"NETCHECK_PASS": "pour-frr", "NETCHECK_SRLINUX_PASS_FILE": str(f)}
    assert _resolve(env, driver="srlinux")[0] == SECRET
    assert _resolve(env, driver="frr")[0] == "pour-frr"


def test_variable_beats_file_at_the_same_level(tmp_path):
    f = _secret_file(tmp_path)
    got, source = _resolve({"NETCHECK_PASS": "variable", "NETCHECK_PASS_FILE": str(f)})
    assert (got, source.kind) == ("variable", "variable")


def test_empty_variables_count_as_unset():
    got, source = _resolve({"NETCHECK_PASS": "", "NETCHECK_SRLINUX_PASS": "", "LAB_PASS": ""})
    assert (got, source.label) == ("inv-value", "inventaire")


def test_user_and_password_resolve_independently(tmp_path):
    f = _secret_file(tmp_path)
    env = {"NETCHECK_USER": "alice", "NETCHECK_PASS_FILE": str(f)}
    assert _resolve(env, "netops", kind="USER") == ("alice", credentials.Source("variable", "NETCHECK_USER"))
    assert _resolve(env, "pw", kind="PASS")[0] == SECRET


def test_nothing_anywhere_is_an_error_that_names_what_was_tried():
    with pytest.raises(CredentialError) as err:
        credentials.resolve("PASS", "eos", None, "r4", environ={})
    message = str(err.value)
    assert "mot de passe" in message and "r4" in message
    assert "NETCHECK_EOS_PASS" in message and "NETCHECK_PASS_FILE" in message and "LAB_PASS" in message


# -- Fichiers de secret --------------------------------------------------------------------------

def test_file_content_is_read_as_text_without_its_final_newline(tmp_path):
    assert credentials.read_secret_file(_secret_file(tmp_path, "mot de passe avec espaces \n")) \
        == "mot de passe avec espaces "
    assert credentials.read_secret_file(_secret_file(tmp_path, "valeur\r\n", name="crlf")) == "valeur"
    assert credentials.read_secret_file(_secret_file(tmp_path, "sans-fin-de-ligne", name="nolf")) \
        == "sans-fin-de-ligne"
    odd = "$tout'\"`;|&"
    assert credentials.read_secret_file(_secret_file(tmp_path, odd, name="chars")) == odd
    assert credentials.read_secret_file(_secret_file(tmp_path, SECRET, mode=0o400, name="ro")) == SECRET


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o666, 0o604, 0o700, 0o200])
def test_a_file_with_other_permissions_is_refused_without_quoting_its_content(tmp_path, mode):
    p = _secret_file(tmp_path, mode=mode)
    with pytest.raises(CredentialError) as err:
        credentials.read_secret_file(p, "NETCHECK_PASS (r1)")
    assert "chmod 600" in str(err.value) and SECRET not in str(err.value)


def test_symlink_directory_missing_empty_multiline_and_huge_files_are_refused(tmp_path):
    real = _secret_file(tmp_path)
    link = tmp_path / "lien"
    link.symlink_to(real)
    cases = {
        "lien symbolique": link,
        "pas un fichier régulier": tmp_path,
        "illisible": tmp_path / "absent",
        "vide": _secret_file(tmp_path, "", name="vide"),
        "vide (seulement une fin de ligne)": _secret_file(tmp_path, "\n", name="nl"),
        "plusieurs lignes": _secret_file(tmp_path, "a=1\nb=2\n", name="env"),
        "plus de": _secret_file(tmp_path, "x" * 5000, name="gros"),
    }
    for fragment, path in cases.items():
        with pytest.raises(CredentialError) as err:
            credentials.read_secret_file(path)
        assert fragment.split(" (")[0] in str(err.value), fragment
    # Les messages ne citent jamais le contenu d'un fichier refusé.
    with pytest.raises(CredentialError) as err:
        credentials.read_secret_file(_secret_file(tmp_path, "ligne1-secrete\nligne2\n", name="multi"))
    assert "ligne1-secrete" not in str(err.value)


def test_a_file_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    p = _secret_file(tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(p).st_uid + 1)
    with pytest.raises(CredentialError, match="n'appartient pas"):
        credentials.read_secret_file(p)


def test_a_designated_file_that_fails_never_falls_back_to_the_inventory(tmp_path):
    bad = _secret_file(tmp_path, mode=0o644)
    with pytest.raises(CredentialError):
        credentials.resolve("PASS", "frr", "valeur-de-l-inventaire", "r1",
                            environ={"NETCHECK_PASS_FILE": str(bad)})
    with pytest.raises(CredentialError):
        credentials.resolve("PASS", "frr", "valeur-de-l-inventaire", "r1",
                            environ={"NETCHECK_PASS_FILE": str(tmp_path / "absent")})


def test_tilde_in_a_file_path_is_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _secret_file(tmp_path, name="secret-home")
    env = {"NETCHECK_PASS_FILE": "~/secret-home"}
    got, source = credentials.resolve("PASS", "frr", None, "r1", environ=env)
    assert got == SECRET and source.name == str(tmp_path / "secret-home")


# -- Routeur résolu, sources, rapports ---------------------------------------------------------

def _router(**extra) -> dict:
    return {"name": "r1", "host": "192.0.2.1", "driver": "frr", "device_type": "linux",
            "username": "netops", "password": "netops", **extra}


def test_resolve_device_returns_a_secretstr_and_the_sources_without_values(tmp_path):
    f = _secret_file(tmp_path)
    original = _router()
    r = credentials.resolve_device(original, environ={"NETCHECK_PASS_FILE": str(f), "NETCHECK_USER": "alice"})
    assert isinstance(r["password"], SecretStr) and r["password"] == SECRET
    assert r["username"] == "alice"
    assert r["credential_sources"] == {"username": "variable NETCHECK_USER", "password": f"fichier {f}"}
    assert SECRET not in repr(r) and SECRET not in str(r["credential_sources"])
    assert original == _router()                       # le routeur d'origine n'est pas modifié


def test_describe_and_format_sources_group_routers_by_source():
    routers = {
        "r1": credentials.resolve_device({**_router(name="r1")}, environ={"NETCHECK_PASS": "pw-generique"}),
        "r2": credentials.resolve_device({**_router(name="r2")}, environ={"NETCHECK_PASS": "pw-generique"}),
        "r3": credentials.resolve_device({**_router(name="r3")}, environ={}),
    }
    described = credentials.describe_sources(routers)
    assert described["mot de passe"] == {"variable NETCHECK_PASS": ["r1", "r2"], "inventaire": ["r3"]}
    assert described["utilisateur"] == {"inventaire": ["r1", "r2", "r3"]}
    lines = credentials.format_sources(described)
    assert lines[:2] == ["utilisateur : inventaire (r1, r2, r3)",
                         "mot de passe : variable NETCHECK_PASS (r1, r2) ; inventaire (r3)"]
    assert lines[2].startswith("remarque : ") and lines[2].endswith("(r3)")   # « netops » : trop court
    assert credentials.describe_sources({"r1": _router()}) is None     # hors ligne : rien à dire


# -- Inventaire : paresseux hors ligne ------------------------------------------------------------

def _inventory_file(tmp_path: Path) -> str:
    path = tmp_path / "inv.yml"
    path.write_text("lab: true\ndefaults: {device_type: linux, username: u, password: inv-pass}\n"
                    "routers:\n  r1: {host: 192.0.2.1}\n", encoding="utf-8")
    return str(path)


def test_offline_loading_resolves_nothing_and_never_reads_a_secret_file(tmp_path, monkeypatch):
    monkeypatch.setenv("NETCHECK_PASS_FILE", str(tmp_path / "n-existe-pas"))
    inv = inventory.load(path=_inventory_file(tmp_path), resolve_credentials=False)
    assert "credential_sources" not in inv.routers["r1"]
    assert inv.routers["r1"]["password"] == "inv-pass"
    with pytest.raises(CredentialError):
        inventory.load(path=_inventory_file(tmp_path))


def test_loading_records_the_source_of_each_credential(tmp_path, monkeypatch):
    monkeypatch.setenv("NETCHECK_FRR_USER", "specifique")
    r = inventory.load(path=_inventory_file(tmp_path)).routers["r1"]
    assert r["credential_sources"] == {"username": "variable NETCHECK_FRR_USER", "password": "inventaire"}
    assert isinstance(r["password"], SecretStr)


# -- CLI --------------------------------------------------------------------------------------------

def _never_collect(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("aucune collecte ne doit avoir lieu")
    monkeypatch.setattr(collector, "collect_all", boom)
    monkeypatch.setattr(collector, "wait_for_convergence", boom)


@pytest.mark.parametrize("command", ["snapshot", "check", "assert", "guard", "monitor"])
def test_a_refused_secret_file_stops_every_live_command_with_code_3(command, monkeypatch, tmp_path, capsys):
    bad = _secret_file(tmp_path, mode=0o644)
    monkeypatch.setenv("NETCHECK_PASS_FILE", str(bad))
    monkeypatch.setattr(snapshot, "load", lambda name: {})
    _never_collect(monkeypatch)
    inv = _inventory_file(tmp_path)
    script = tmp_path / "c.sh"
    script.write_text("true\n", encoding="utf-8")
    argv = {
        "snapshot": ["snapshot", "s", "-i", inv],
        "check": ["check", "-i", inv],
        "assert": ["assert", "--intent", str(inventory.REPO_ROOT / "intents" / "lab.yml"), "-i", inv],
        "guard": ["guard", "--change", str(script), "--yes", "-i", inv],
        "monitor": ["monitor", "--baseline", "b", "-i", inv],
    }[command]
    assert cli.main(argv) == 3
    err = capsys.readouterr().err
    assert "chmod 600" in err and SECRET not in err


# Le snapshot est VIDE : le code attendu est exact et ne dépend pas de l'environnement.
#   diff   : deux relevés vides, rien à comparer -> aucun constat, OK (0) ;
#   check  : aucun couple (règle, équipement) évalué -> « rien n'a été audité » (3) ;
#   assert : chaque assertion vise un équipement absent -> NON ÉVALUABLE -> ATTENTION (1).
@pytest.mark.parametrize(("argv", "expected"), [
    (["diff", "avant", "apres"], 0),
    (["check", "--snapshot", "s"], 3),
    (["assert", "--intent", str(inventory.REPO_ROOT / "intents" / "lab.yml"), "--snapshot", "s"], 1),
], ids=["diff", "check", "assert"])
def test_snapshot_based_commands_never_resolve_credentials(argv, expected, monkeypatch, tmp_path, capsys):
    # diff, check --snapshot, assert --snapshot lisent des fichiers : un secret mal réglé ne les bloque pas.
    monkeypatch.setenv("NETCHECK_PASS_FILE", str(tmp_path / "n-existe-pas"))
    monkeypatch.setattr(snapshot, "load", lambda name: {})
    code = cli.main([*argv, "-i", _inventory_file(tmp_path)])
    err = capsys.readouterr().err
    assert "NETCHECK_PASS_FILE" not in err, err
    assert code == expected


def test_offline_commands_ignore_the_secret_configuration(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("NETCHECK_PASS_FILE", str(tmp_path / "n-existe-pas"))
    inv = _inventory_file(tmp_path)
    configs = str(inventory.REPO_ROOT / "configs")
    code = cli.main(["check", "--config-dir", configs, "--driver", "frr", "-i", inv])
    assert code in (0, 1, 2)                                   # un verdict, pas une erreur d'identifiant
    assert "NETCHECK_PASS_FILE" not in capsys.readouterr().err


# -- Note d'information : mot de passe trop court pour l'expurgation par valeur ---------------------------

NOTE = ("expurgation par valeur inactive pour ce secret (moins de 8 caractères), "
        "seule la protection SecretStr s'applique")


def _routers_with_passwords(**passwords: str) -> dict:
    return {name: credentials.resolve_device(_router(name=name), environ={"NETCHECK_PASS": value})
            for name, value in passwords.items()}


def test_a_short_password_gets_an_information_note_listing_the_devices():
    routers = _routers_with_passwords(r1="netops", r2="long-enough-pw", r3="a")
    described = credentials.describe_sources(routers)
    assert described["remarque"] == {NOTE: ["r1", "r3"]}
    assert credentials.format_sources(described)[-1] == f"remarque : {NOTE} (r1, r3)"


@pytest.mark.parametrize(("password", "expected"), [("a" * 7, True), ("a" * 8, False)])
def test_the_note_threshold_is_exactly_eight_characters(password, expected):
    described = credentials.describe_sources(_routers_with_passwords(r1=password))
    assert ("remarque" in described) is expected


def test_no_note_when_every_password_is_long_enough():
    routers = _routers_with_passwords(r1="long-enough-pw", r2="another-long-pw")
    assert "remarque" not in credentials.describe_sources(routers)


def test_the_note_never_reveals_the_length_or_the_value():
    described = credentials.describe_sources(_routers_with_passwords(r1="zq9", r2="zq9wxyz"))
    short = credentials.format_sources(described)
    assert [ln for ln in short if ln.startswith("remarque")] == [f"remarque : {NOTE} (r1, r2)"]
    text = "\n".join(short)
    assert "zq9" not in text
    # Même texte pour 2 et 7 caractères : rien n'en dépend.
    one = credentials.describe_sources(_routers_with_passwords(r1="zq9"))["remarque"]
    other = credentials.describe_sources(_routers_with_passwords(r1="zq9wxyz"))["remarque"]
    assert one == other


def test_secretstr_redactable_is_a_boolean_without_the_length():
    assert SecretStr("x" * 8).redactable is True and SecretStr("x" * 7).redactable is False


def _fake_collect(monkeypatch):
    from netcheck.model import DeviceState
    state = DeviceState(name="r1", host="192.0.2.1", timestamp="2026-01-01T00:00:00+00:00", reachable=True)
    monkeypatch.setattr(collector, "collect_all", lambda *_a, **_k: {"r1": (True, state)})


@pytest.mark.parametrize(("password", "note"), [("netops", True), ("long-enough-password", False)])
def test_snapshot_prints_the_note_without_changing_the_exit_code(password, note, monkeypatch, tmp_path,
                                                                 capsys):
    _fake_collect(monkeypatch)
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)   # cmd_snapshot : chemin relatif à la racine
    monkeypatch.setenv("NETCHECK_PASS", password)
    code = cli.main(["snapshot", "s", "-i", _inventory_file(tmp_path)])
    captured = capsys.readouterr()
    assert code == 0                                    # ni un avertissement ni une erreur : code inchangé
    assert (NOTE in captured.out) is note
    assert password not in captured.out + captured.err
    assert NOTE not in captured.err                     # jamais sur stderr (cron)
    meta = (tmp_path / "snaps" / "s" / "meta.json").read_text(encoding="utf-8")
    assert (NOTE in meta) is note and password not in meta
