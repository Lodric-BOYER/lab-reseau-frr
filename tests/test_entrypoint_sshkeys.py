"""Point d'entrée de l'image frr-ssh (docker/entrypoint-sshkeys.sh) : sshd n'est lancé qu'une fois les clés
d'hôte présentes, et tout échec arrête le conteneur (code 1, message sur stderr) au lieu de laisser un
conteneur vivant sans sshd. Le script est exécuté tel quel, avec ses chemins absolus (/usr/sbin/sshd,
/sbin/tini, /etc/ssh) redirigés vers un bac à sable et de faux binaires qui journalisent leurs appels."""

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "docker" / "entrypoint-sshkeys.sh"


def _fake(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _sandbox(tmp_path: Path, keygen: str, sshd: str) -> tuple[Path, dict]:
    ssh = tmp_path / "etc-ssh"
    ssh.mkdir()
    log = tmp_path / "calls.log"
    bins = tmp_path / "bin"
    bins.mkdir()
    # ssh-keygen résolu par le PATH ; sshd et tini par leur chemin absolu, réécrit dans la copie du script.
    _fake(bins / "ssh-keygen", keygen.replace("@SSH@", str(ssh)).replace("@LOG@", str(log)))
    sshd_path = tmp_path / "sshd"
    tini_path = tmp_path / "tini"
    _fake(sshd_path, sshd.replace("@SSH@", str(ssh)).replace("@LOG@", str(log)))
    _fake(tini_path, f'echo "tini $*" >> {log}\n')
    text = SCRIPT.read_text()
    for old, new in (
        ("/usr/sbin/sshd", str(sshd_path)),
        ("/sbin/tini", str(tini_path)),
        ("/etc/ssh/", f"{ssh}/"),
    ):
        assert old in text, f"le script ne contient plus {old} : adapter le test"
        text = text.replace(old, new)
    copy = tmp_path / "entrypoint.sh"
    copy.write_text(text)
    env = {**os.environ, "PATH": f"{bins}:{os.environ['PATH']}"}
    return copy, env


def _run(copy: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(copy), *args], capture_output=True, text=True, env=env, timeout=30)


KEYGEN_OK = (
    'echo "ssh-keygen $*" >> @LOG@\necho k > @SSH@/ssh_host_ed25519_key\n'
    "echo p > @SSH@/ssh_host_ed25519_key.pub\n"
)
SSHD_OK = (
    'if [ -s @SSH@/ssh_host_ed25519_key ]; then echo "sshd keys_present" >> @LOG@; '
    'else echo "sshd NO_KEYS" >> @LOG@; fi\n'
)


def test_nominal_order_is_keygen_then_sshd_then_tini_with_the_original_command(tmp_path):
    copy, env = _sandbox(tmp_path, KEYGEN_OK, SSHD_OK)
    r = _run(copy, env, "/usr/lib/frr/docker-start")
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls.log").read_text().splitlines()
    assert calls == ["ssh-keygen -A", "sshd keys_present", "tini -- /usr/lib/frr/docker-start"]


def test_sshd_never_starts_when_ssh_keygen_fails(tmp_path):
    copy, env = _sandbox(tmp_path, 'echo "ssh-keygen $*" >> @LOG@\nexit 1\n', SSHD_OK)
    r = _run(copy, env, "cmd")
    assert r.returncode == 1
    assert "ssh-keygen -A a échoué" in r.stderr
    assert (tmp_path / "calls.log").read_text().splitlines() == ["ssh-keygen -A"]  # ni sshd ni tini


def test_a_keygen_that_claims_success_without_producing_the_key_stops_the_container(tmp_path):
    copy, env = _sandbox(tmp_path, 'echo "ssh-keygen $*" >> @LOG@\nexit 0\n', SSHD_OK)
    r = _run(copy, env, "cmd")
    assert r.returncode == 1
    assert "ed25519 absente" in r.stderr
    assert "sshd" not in (tmp_path / "calls.log").read_text()


def test_an_empty_host_key_counts_as_missing(tmp_path):
    keygen = (
        'echo "ssh-keygen $*" >> @LOG@\n: > @SSH@/ssh_host_ed25519_key\n'
        "echo p > @SSH@/ssh_host_ed25519_key.pub\n"
    )
    copy, env = _sandbox(tmp_path, keygen, SSHD_OK)
    r = _run(copy, env, "cmd")
    assert r.returncode == 1 and "ed25519 absente" in r.stderr


def test_a_missing_public_key_counts_as_missing(tmp_path):
    keygen = 'echo "ssh-keygen $*" >> @LOG@\necho k > @SSH@/ssh_host_ed25519_key\n'
    copy, env = _sandbox(tmp_path, keygen, SSHD_OK)
    r = _run(copy, env, "cmd")
    assert r.returncode == 1 and "ed25519 absente" in r.stderr


def test_a_failing_sshd_stops_the_container_before_frr_starts(tmp_path):
    copy, env = _sandbox(tmp_path, KEYGEN_OK, 'echo "sshd start" >> @LOG@\nexit 255\n')
    r = _run(copy, env, "cmd")
    assert r.returncode == 1
    assert "sshd n'a pas démarré" in r.stderr
    assert "tini" not in (tmp_path / "calls.log").read_text()


def test_the_failure_message_goes_to_stderr_only(tmp_path):
    copy, env = _sandbox(tmp_path, "exit 1\n", SSHD_OK)
    r = _run(copy, env, "cmd")
    assert r.stdout == ""
    assert r.stderr.startswith("entrypoint-sshkeys: ")


def test_the_real_script_has_no_unconditional_exit_zero_path():
    text = SCRIPT.read_text()
    assert "set +e" not in text
    assert text.count("exec /sbin/tini") == 1
    assert text.index("ssh-keygen -A") < text.index("/usr/sbin/sshd") < text.index("exec /sbin/tini")


def test_the_image_reports_an_unhealthy_container_when_sshd_stops_listening():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text()
    assert "HEALTHCHECK" in dockerfile and "':22 '" in dockerfile
    assert dockerfile.index("HEALTHCHECK") < dockerfile.index("ENTRYPOINT")


@pytest.mark.parametrize("topology", ["lab.clab.yml", "lab-multivendor.clab.yml", "lab-cEOS.clab.yml"])
def test_topologies_no_longer_start_a_second_sshd_with_exec(topology):
    # sshd est lancé (et contrôlé) par le point d'entrée : un `exec: /usr/sbin/sshd` en plus échouerait
    # silencieusement (adresse déjà utilisée) et masquerait le vrai diagnostic.
    nodes = yaml.safe_load((ROOT / topology).read_text())["topology"]["nodes"]
    for name, node in nodes.items():
        assert not any("sshd" in cmd for cmd in node.get("exec", [])), (
            f"{topology} : {name} lance encore sshd"
        )
