"""lab-access/pin_hostkeys.sh : épinglage des clés d'hôte d'un lab (phase C1).

Le script est joué pour de vrai (bash), avec un FAUX `docker` placé en tête du PATH : il répond comme le
démon pour `inspect` et `exec ... cat <clé publique>`. Les clés sont de vraies clés ed25519 (`ssh-keygen`).
Le lab réel est vérifié par les scénarios d'intégration, pas ici.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import paramiko
import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "lab-access" / "pin_hostkeys.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("ssh-keygen")) or os.name == "nt",
    reason="bash et ssh-keygen requis")

FAKE_DOCKER = """#!/bin/bash
case "$1" in
  inspect)
    if [ "$2" = "-f" ]; then
      fmt="$3"; c="$4"
      case "$fmt" in
        *Config.Image*) echo "${STUB_IMAGE:-frr-ssh:10.2.1}" ;;
        *IPAddress*)
          case "$c" in
            *-bastion) echo "${STUB_BASTION_IP:-${STUB_SUBNET}.2}" ;;
            *)         echo "${STUB_SUBNET}.1${c##*-r}" ;;
          esac ;;
      esac
    else
      [ -f "$STUB_DIR/$2.pub" ] || exit 1
    fi ;;
  exec) cat "$STUB_DIR/$2.pub" ;;
esac
"""


def _make_key(directory: Path, name: str) -> str:
    base = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "root@fake", "-f", str(base)],
                   check=True)
    return (directory / f"{name}.pub").read_text(encoding="utf-8").strip()


@pytest.fixture
def stub(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    keys = tmp_path / "keys"
    keys.mkdir()
    return tmp_path, bindir, keys


def _install_keys(keys: Path, prefix: str, count: int = 5, same: tuple[int, int] | None = None) -> dict:
    pubs = {}
    for i in range(1, count + 1):
        # `same=(a, b)` : le routeur b annonce la clé du routeur a.
        pubs[i] = pubs[same[0]] if same and i == same[1] else _make_key(keys, f"gen{i}")
        (keys / f"{prefix}-r{i}.pub").write_text(pubs[i] + "\n", encoding="utf-8")
    return pubs


def _run(stub, lab="frr", extra_env=None, args=None):
    tmp_path, bindir, keys = stub
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "STUB_DIR": str(keys),
           "STUB_SUBNET": {"frr": "172.20.20", "multivendor": "172.20.21", "ceos": "172.20.22"}.get(lab, ""),
           "NETCHECK_KNOWN_HOSTS": str(tmp_path / "kh" / "known_hosts"), **(extra_env or {})}
    return subprocess.run(["bash", str(SCRIPT), *(args if args is not None else [lab])], cwd=REPO, env=env,
                          capture_output=True, text=True, check=False)


def test_five_distinct_keys_are_pinned_with_private_permissions(stub):
    pubs = _install_keys(stub[2], "clab-frr-lab")
    result = _run(stub)
    assert result.returncode == 0, result.stderr
    kh = stub[0] / "kh" / "known_hosts"
    assert stat.S_IMODE(kh.stat().st_mode) == 0o600
    assert stat.S_IMODE(kh.parent.stat().st_mode) == 0o700
    hostkeys = paramiko.HostKeys(str(kh))
    for i in range(1, 6):
        entry = hostkeys.lookup(f"172.20.20.1{i}")
        assert entry is not None, i
        assert entry["ssh-ed25519"].get_base64() == pubs[i].split()[1]
    assert len(kh.read_text(encoding="utf-8").splitlines()) == 5


def test_a_key_shared_by_two_routers_is_refused_and_nothing_is_written(stub):
    _install_keys(stub[2], "clab-frr-lab", same=(1, 3))
    result = _run(stub)
    assert result.returncode == 1
    assert "IDENTIQUE" in result.stderr and "r3" in result.stderr
    assert not (stub[0] / "kh" / "known_hosts").exists()


def test_previous_entries_of_the_lab_are_replaced_and_other_lines_are_kept(stub):
    pubs = _install_keys(stub[2], "clab-frr-lab")
    kh = stub[0] / "kh" / "known_hosts"
    kh.parent.mkdir()
    stale = _make_key(stub[2], "stale").split()
    kh.write_text(f"172.20.20.11 {stale[0]} {stale[1]}\n10.9.9.9 {stale[0]} {stale[1]}\n"
                  f"172.20.21.12 {stale[0]} {stale[1]}\n", encoding="utf-8")
    result = _run(stub)
    assert result.returncode == 0, result.stderr
    text = kh.read_text(encoding="utf-8")
    assert stale[1] in text                       # les lignes des autres adresses sont conservées
    assert text.count("10.9.9.9") == 1 and text.count("172.20.21.12") == 1
    assert text.count("172.20.20.11 ") == 1       # l'ancienne entrée de r1 est remplacée
    assert pubs[1].split()[1] in text
    assert f"172.20.20.11 {stale[0]} {stale[1]}" not in text


def test_a_missing_container_stops_the_pinning_and_leaves_the_file_unchanged(stub):
    _install_keys(stub[2], "clab-frr-lab", count=4)         # pas de r5
    kh = stub[0] / "kh" / "known_hosts"
    kh.parent.mkdir()
    kh.write_text("10.9.9.9 ssh-ed25519 AAAA\n", encoding="utf-8")
    result = _run(stub)
    assert result.returncode == 1
    assert "absent" in result.stderr
    assert kh.read_text(encoding="utf-8") == "10.9.9.9 ssh-ed25519 AAAA\n"


def test_an_unexpected_address_is_refused(stub):
    _install_keys(stub[2], "clab-frr-lab")
    result = _run(stub, extra_env={"STUB_SUBNET": "172.20.99"})
    assert result.returncode == 1
    assert "inattendue" in result.stderr


def test_unknown_lab_name_is_a_usage_error(stub):
    result = _run(stub, args=["inconnu"])
    assert result.returncode == 2
    assert "usage" in result.stderr


# --- Bastion (phase C4) --------------------------------------------------------------------------------


def _bastion_key(stub, prefix="clab-frr-lab") -> str:
    pub = _make_key(stub[2], "genb")
    (stub[2] / f"{prefix}-bastion.pub").write_text(pub + "\n", encoding="utf-8")
    return pub


def test_the_bastion_key_is_pinned_with_the_routers_in_the_same_file(stub):
    _install_keys(stub[2], "clab-frr-lab")
    pub = _bastion_key(stub)
    result = _run(stub)
    assert result.returncode == 0, result.stderr
    known = (stub[0] / "kh" / "known_hosts").read_text(encoding="utf-8").splitlines()
    assert len(known) == 6 and f"172.20.20.2 {' '.join(pub.split()[:2])}" in known
    assert "bastion : oui" in result.stdout and "bastion 172.20.20.2 SHA256:" in result.stdout


def test_a_lab_without_a_bastion_is_still_pinned(stub):
    _install_keys(stub[2], "clab-frr-lab")
    result = _run(stub)
    assert result.returncode == 0 and "bastion : non" in result.stdout
    assert len((stub[0] / "kh" / "known_hosts").read_text(encoding="utf-8").splitlines()) == 5


def test_a_bastion_key_identical_to_a_router_key_is_refused_and_nothing_is_written(stub):
    pubs = _install_keys(stub[2], "clab-frr-lab")
    (stub[2] / "clab-frr-lab-bastion.pub").write_text(pubs[3] + "\n", encoding="utf-8")
    result = _run(stub)
    assert result.returncode == 1 and "bastion : clé IDENTIQUE" in result.stderr
    assert not (stub[0] / "kh" / "known_hosts").exists()


def test_a_bastion_at_an_unexpected_address_is_refused(stub):
    _install_keys(stub[2], "clab-frr-lab")
    _bastion_key(stub)
    result = _run(stub, extra_env={"STUB_BASTION_IP": "172.20.20.77"})
    assert result.returncode == 1 and "bastion : adresse 172.20.20.77 inattendue" in result.stderr


def test_repinning_replaces_the_bastion_line_and_keeps_other_labs(stub):
    _install_keys(stub[2], "clab-frr-lab")
    _bastion_key(stub)
    assert _run(stub).returncode == 0
    known = stub[0] / "kh" / "known_hosts"
    known.write_text(known.read_text(encoding="utf-8") + "10.9.9.9 ssh-ed25519 AAAAautre\n", encoding="utf-8")
    new_pub = _make_key(stub[2], "genb2")
    (stub[2] / "clab-frr-lab-bastion.pub").write_text(new_pub + "\n", encoding="utf-8")
    assert _run(stub).returncode == 0
    lines = known.read_text(encoding="utf-8").splitlines()
    assert sum(ln.startswith("172.20.20.2 ") for ln in lines) == 1 and len(lines) == 7
    assert any(ln.startswith("10.9.9.9 ") for ln in lines)
    assert new_pub.split()[1] in "\n".join(lines)
