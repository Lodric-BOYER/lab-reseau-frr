"""tests/lib_lab.sh : barrière « lab prêt » (port joignable ET bannière SSH) et diagnostic sans secret.
Les nœuds sont de faux serveurs TCP locaux ; docker est remplacé par un faux binaire."""

import os
import socket
import stat
import subprocess
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "tests" / "lib_lab.sh"


class FakeNode:
    """Serveur TCP local : `banner` envoyée à la connexion, ou rien (None) en gardant la connexion ouverte."""

    def __init__(self, banner: bytes | None, host: str = "127.0.0.1"):
        self.sock = socket.socket()
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.conns: list[socket.socket] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)
            if self.banner is not None:
                conn.sendall(self.banner)

    def close(self):
        self.sock.close()
        for c in self.conns:
            c.close()


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def bash(script: str, env=None, cwd=None) -> subprocess.CompletedProcess:
    full = f'source "{LIB}"\nok() {{ echo "OK $1"; }}\nko() {{ echo "KO $1"; }}\nFAIL=0\n{script}'
    return subprocess.run(
        ["bash", "-c", full], capture_output=True, text=True, env=env or os.environ, cwd=cwd, timeout=60
    )


def test_lab_ready_when_every_node_sends_an_ssh_banner():
    a, b = FakeNode(b"SSH-2.0-OpenSSH_9.9\r\n"), FakeNode(b"SSH-2.0-Arista\r\n")
    try:
        r = bash(f"lab_ready t 10 r1=127.0.0.1:{a.port} bastion=127.0.0.1:{b.port}; echo rc=$?")
    finally:
        a.close(), b.close()
    assert "rc=0" in r.stdout and "lab non prêt" not in r.stdout


def test_a_closed_port_is_reported_by_node_name_as_lab_not_ready():
    good = FakeNode(b"SSH-2.0-x\r\n")
    port = closed_port()
    try:
        r = bash(f"lab_ready t 1 r1=127.0.0.1:{good.port} r2=127.0.0.1:{port}; echo rc=$?")
    finally:
        good.close()
    assert "rc=1" in r.stdout
    assert f"lab non prêt : r2 (127.0.0.1:{port}) : port fermé ou injoignable" in r.stdout
    assert "r1" not in r.stdout.replace("rc=1", "")


def test_an_open_port_without_banner_is_not_ready():
    silent = FakeNode(None)
    try:
        r = bash(f"lab_ready t 1 r3=127.0.0.1:{silent.port}; echo rc=$?")
    finally:
        silent.close()
    assert "rc=1" in r.stdout
    assert "lab non prêt : r3" in r.stdout and "port ouvert mais aucune bannière SSH" in r.stdout


def test_a_banner_that_is_not_ssh_is_not_ready():
    web = FakeNode(b"HTTP/1.1 400 Bad Request\r\n")
    try:
        r = bash(f"lab_ready t 1 r4=127.0.0.1:{web.port}; echo rc=$?")
    finally:
        web.close()
    assert "rc=1" in r.stdout and "lab non prêt : r4" in r.stdout


def test_a_node_that_comes_up_late_is_waited_for():
    # le serveur n'existe pas au premier passage ; il apparaît ~2 s plus tard, avant l'échéance de 20 s
    port = closed_port()
    started = []

    def late():
        import time

        time.sleep(2)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(4)
        started.append(s)
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-late\r\n")

    threading.Thread(target=late, daemon=True).start()
    try:
        r = bash(f"lab_ready t 20 r5=127.0.0.1:{port}; echo rc=$?")
    finally:
        for s in started:
            s.close()
    assert "rc=0" in r.stdout


def _fake_docker(tmp_path: Path, logs: str = "") -> dict:
    bins = tmp_path / "bin"
    bins.mkdir()
    docker = bins / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  ps) case "$*" in\n'
        '        *"Names}}\\t"*) printf "clab-t-r1\\tUp 5 minutes\\nclab-t-bastion\\tUp 5 minutes\\n";;\n'
        '        *"-a"*) printf "clab-t-r1\\nclab-t-r2\\nclab-t-bastion\\nclab-t-pc1\\n";;\n'
        '        *) printf "clab-t-r1\\nclab-t-bastion\\nclab-t-pc1\\n";;\n'
        "      esac;;\n"
        '  inspect) echo "état=running code_sortie=0 OOM=false santé=aucune redémarrages=0 démarré=t";;\n'
        f'  logs) printf "%s\\n" "{logs}";;\n'
        '  exec) echo "EXEC:$2";;\n'
        '  stats) echo "CONTAINER CPU MEM";;\n'
        "esac\n"
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    return {**os.environ, "PATH": f"{bins}:{os.environ['PATH']}"}


def _repo_copy(tmp_path: Path) -> Path:
    """Le diagnostic écrit sous <racine>/reports : on lui donne une racine jetable."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "lib_lab.sh").write_text(LIB.read_text())
    return root


def test_diagnostics_file_is_private_complete_and_free_of_secrets(tmp_path):
    env = _fake_docker(tmp_path, logs="sshd started password=hunter2hunter2 token: s.abcdef")
    root = _repo_copy(tmp_path)
    r = subprocess.run(
        ["bash", "-c", f'source "{root}/tests/lib_lab.sh"; lab_diagnostics clab-t essai'],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    files = list((root / "reports" / "diagnostics").glob("essai-*.txt"))
    assert len(files) == 1
    out = files[0]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700
    text = out.read_text()
    for needle in (
        "# hôte",
        "# docker stats",
        "--- clab-t-r1",
        "--- clab-t-bastion",
        "journal du conteneur",
        "état=running",
        "EXEC:clab-t-r1",
        "--- clab-t-r2",
    ):  # r2 : conteneur arrêté, vu avec -a
        assert needle in text, needle
    assert (
        "clab-t-pc1" not in text.split("# conteneurs du lab")[1].split("---")[1]
    )  # ni PC ni autre sans sshd
    assert "hunter2hunter2" not in text and "s.abcdef" not in text and "password=***" in text
    assert "diagnostic écrit dans" in r.stdout


def test_diagnostics_never_inspects_the_container_environment(tmp_path):
    # `docker inspect` sans -f (ou avec .Config.Env) afficherait l'environnement des conteneurs
    assert "docker inspect -f" in LIB.read_text()
    assert ".Config" not in LIB.read_text()


def test_lab_ready_lab_failure_announces_it_apart_and_exits_20(tmp_path):
    env = _fake_docker(tmp_path)
    root = _repo_copy(tmp_path)
    port = closed_port()
    script = (
        f'source "{root}/tests/lib_lab.sh"\nok() {{ echo "OK $1"; }}\nko() {{ echo "KO $1"; }}\n'
        f"LAB=clab-t\nLAB_READY_PORT={port}\nlab_ready_lab 127.0.0 essai 1\necho UNREACHABLE\n"
    )
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 20
    assert "UNREACHABLE" not in r.stdout
    for name, ip in (("r1", "11"), ("r2", "12"), ("r3", "13"), ("r4", "14"), ("r5", "15"), ("bastion", "2")):
        assert f"KO lab non prêt : {name} (127.0.0.{ip}:" in r.stdout, name
    assert "Lab non prêt" in r.stdout and "pas un échec de netcheck" in r.stdout
    assert list((root / "reports" / "diagnostics").glob("essai-lab-non-pret-*.txt"))


def test_lab_ready_lab_success_counts_one_check_and_continues(tmp_path):
    nodes = [FakeNode(b"SSH-2.0-x\r\n", host="0.0.0.0")]  # répond sur 127.0.0.11 à .15 et .2 aussi
    try:
        # un seul faux serveur : son port est partagé par r1 à r5 et le bastion
        script = f"LAB_READY_PORT={nodes[0].port}\nlab_ready_lab 127.0.0 essai 10\necho CONTINUE"
        r = bash(script)
    finally:
        nodes[0].close()
    assert r.returncode == 0 and "OK lab prêt" in r.stdout and "CONTINUE" in r.stdout


def test_diag_if_failed_only_runs_on_failures(tmp_path):
    env = _fake_docker(tmp_path)
    root = _repo_copy(tmp_path)
    base = f'source "{root}/tests/lib_lab.sh"\nLAB=clab-t\n'
    r = subprocess.run(
        ["bash", "-c", base + "FAIL=0; lab_diag_if_failed s; echo rc=$?"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert "rc=0" in r.stdout and not (root / "reports").exists()
    r = subprocess.run(
        ["bash", "-c", base + "FAIL=2; lab_diag_if_failed s; echo rc=$?"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert "rc=0" in r.stdout and list((root / "reports" / "diagnostics").glob("s-echec-*.txt"))
