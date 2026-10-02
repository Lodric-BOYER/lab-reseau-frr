"""Tests de automation/monitor.sh (Phase E) : lecture du fichier d'environnement.

Exigences validées : le fichier n'est JAMAIS exécuté (lu comme du texte, seule la ligne
NETCHECK_WEBHOOK_URL= est retenue) ; il doit appartenir à l'utilisateur, être un fichier régulier
et n'être lisible que par lui (0600), sinon refus clair (code 3) ; l'URL n'est jamais affichée.

Le vrai `python -m netcheck` est remplacé (NETCHECK_PYTHON) par un faux interpréteur qui enregistre
ce qu'il reçoit : on prouve ce que le script transmet, sans lancer netcheck.
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "automation" / "monitor.sh"
SECRET = "https://hooks.example.org/services/SENTINEL-SECRET-77aa"

FAKE_PYTHON = """#!/bin/bash
printf '%s' "${NETCHECK_WEBHOOK_URL-UNSET}" > "$FAKE_OUT.url"
printf '%s\\n' "$@" > "$FAKE_OUT.args"
printf '%s' "${FOO-UNSET}" > "$FAKE_OUT.foo"
"""


@pytest.fixture
def env(tmp_path):
    fake = tmp_path / "fake-python"
    fake.write_text(FAKE_PYTHON)
    fake.chmod(0o755)
    out = tmp_path / "out"

    def run(env_file_body=None, mode=0o600, extra_env=None, args=("--baseline", "nominal"), *, link=False):
        env_file = tmp_path / "netcheck.env"
        if env_file_body is not None:
            if link:
                real = tmp_path / "real.env"
                real.write_text(env_file_body)
                real.chmod(mode)
                env_file.symlink_to(real)
            else:
                env_file.write_text(env_file_body)
                env_file.chmod(mode)
        environment = {
            "PATH": os.environ["PATH"], "HOME": str(tmp_path), "NETCHECK_PYTHON": str(fake),
            "NETCHECK_ENV_FILE": str(env_file), "FAKE_OUT": str(out), **(extra_env or {}),
        }
        proc = subprocess.run(["bash", str(SCRIPT), *args], env=environment, capture_output=True,
                              text=True, timeout=30)
        def read(suffix):
            file = Path(f"{out}.{suffix}")
            return file.read_text() if file.exists() else None
        return proc, read("url"), read("args"), read("foo")

    run.tmp = tmp_path
    return run


def test_url_is_read_from_the_file_and_arguments_are_passed_through(env):
    proc, url, args, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n")
    assert proc.returncode == 0
    assert url == SECRET
    assert args.splitlines() == ["-m", "netcheck", "monitor", "--baseline", "nominal"]
    assert SECRET not in proc.stdout + proc.stderr


@pytest.mark.parametrize("line", [
    f"NETCHECK_WEBHOOK_URL='{SECRET}'", f'NETCHECK_WEBHOOK_URL="{SECRET}"', f"NETCHECK_WEBHOOK_URL={SECRET}",
])
def test_quotes_around_the_value_are_stripped(env, line):
    _, url, _, _ = env(line + "\n")
    assert url == SECRET


def test_file_without_trailing_newline_and_crlf_endings(env):
    assert env(f"NETCHECK_WEBHOOK_URL={SECRET}")[1] == SECRET
    assert env(f"NETCHECK_WEBHOOK_URL={SECRET}\r\n")[1] == SECRET


def test_other_lines_are_ignored_and_never_executed(env):
    marker = env.tmp / "EXECUTED"
    body = "\n".join([
        f"touch {marker}",
        f"$(touch {marker})",
        f"`touch {marker}`",
        f"export FOO=injected; touch {marker}",
        "FOO=injected",
        "# NETCHECK_WEBHOOK_URL=https://commentaire.example.org/x",
        f"NETCHECK_WEBHOOK_URL={SECRET}",
        f"NETCHECK_WEBHOOK_URL=https://second.example.org/ignored; touch {marker}",
        f"NETCHECK_WEBHOOK_URL=$(touch {marker})",
    ]) + "\n"
    proc, url, _, foo = env(body)
    assert proc.returncode == 0
    assert not marker.exists(), "le fichier d'environnement a été EXÉCUTÉ"
    assert url == SECRET, "la première ligne NETCHECK_WEBHOOK_URL= l'emporte"
    assert foo == "UNSET", "les autres variables du fichier ne sont pas exportées"


def test_value_with_shell_metacharacters_is_passed_as_plain_text(env):
    marker = env.tmp / "EXECUTED"
    weird = f"https://example.org/h?a=1&b=$(touch {marker});`touch {marker}`|x"
    _, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={weird}\n")
    assert url == weird and not marker.exists()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o666, 0o700, 0o604, 0o755])
def test_file_readable_by_others_is_refused_with_a_clear_message(env, mode):
    proc, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n", mode=mode)
    assert proc.returncode == 3
    assert url is None, "netcheck ne doit pas être lancé"
    assert "600" in proc.stderr and "chmod 600" in proc.stderr
    assert SECRET not in proc.stdout + proc.stderr


def test_0400_is_accepted(env):
    proc, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n", mode=0o400)
    assert proc.returncode == 0 and url == SECRET


def test_symlink_is_refused(env):
    proc, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n", link=True)
    assert proc.returncode == 3 and url is None
    assert "lien symbolique" in proc.stderr


def test_directory_is_refused(env):
    d = env.tmp / "netcheck.env"
    d.mkdir()
    d.chmod(0o600)
    proc, url, _, _ = env(None)
    assert proc.returncode == 3 and url is None


def test_file_owned_by_someone_else_is_refused(env):
    shim = env.tmp / "bin"
    shim.mkdir()
    (shim / "id").write_text("#!/bin/bash\necho 424242\n")
    (shim / "id").chmod(0o755)
    proc, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n",
                          extra_env={"PATH": f"{shim}:{os.environ['PATH']}"})
    assert proc.returncode == 3 and url is None
    assert "n'appartient pas à l'utilisateur courant" in proc.stderr


def test_missing_file_is_not_an_error_alerts_are_just_off(env):
    proc, url, args, _ = env(None)
    assert proc.returncode == 0 and url == "UNSET"
    assert args.startswith("-m\nnetcheck\nmonitor")


def test_file_without_the_key_exports_nothing(env):
    proc, url, _, _ = env("AUTRE=1\n")
    assert proc.returncode == 0 and url == "UNSET"


def test_an_already_exported_url_wins_over_the_file(env):
    _, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n",
                       extra_env={"NETCHECK_WEBHOOK_URL": "https://deja.example.org/env"})
    assert url == "https://deja.example.org/env"


def test_a_refused_file_is_not_even_looked_at_when_the_url_is_already_in_the_environment(env):
    # Environnement explicite = choix explicite : le fichier n'est pas consulté.
    proc, url, _, _ = env(f"NETCHECK_WEBHOOK_URL={SECRET}\n", mode=0o644,
                          extra_env={"NETCHECK_WEBHOOK_URL": "https://deja.example.org/env"})
    assert proc.returncode == 0 and url == "https://deja.example.org/env"


def test_script_is_executable_and_shell_safe():
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    head = SCRIPT.read_text().splitlines()
    assert head[0] == "#!/usr/bin/env bash"
    assert "set -euo pipefail" in head
    body = "\n".join(line for line in head if not line.lstrip().startswith("#"))
    assert "source " not in body and "\n. " not in body and "eval " not in body
