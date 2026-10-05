"""Outils de lab (lab-access/, tests/tools/) : TLS gardé, aucun secret en argument, vérification après envoi,
cloisonnement vis-à-vis de netcheck/, config.cli sans commentaire.

Conditions posées à la revue de la phase C5 pour conserver lab-access/pathz_lab.py :
1. `curl --insecure` n'existe que derrière `--insecure` + `--lab-inventory` (`lab: true`), annoncé sur stderr.
2. Le mot de passe d'admin ne passe jamais dans la ligne de commande (argv inspecté sur CHAQUE appel).
3. netcheck/ n'importe rien de lab-access/ ; l'outil est épinglé sur SR Linux 26.7.2.
4. Après l'envoi, le script relit l'équipement et échoue bruyamment si la politique n'est pas effective.
"""

import ast
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab-access"))
sys.path.insert(0, str(ROOT / "tests" / "tools"))

import labtls  # noqa: E402
import pathz_lab as pz  # noqa: E402
import ro_probe  # noqa: E402

POLICY = ROOT / "lab-access" / "pathz" / "netcheck-ro.json"
LAB_INVENTORIES = sorted((ROOT / "automation").glob("inventory*.yml"))
SECRET = "S3cret-Pass-Word-9"


# --- un faux équipement : répond à Rotate, Get, Probe et gNMI Get comme le ferait SR Linux ---------------


def _path_of(message: bytes) -> str:
    elems = []
    for number, value in pz.decode_fields(message):
        assert number == 3
        name, keys = "", []
        for n, v in pz.decode_fields(value):
            if n == 1:
                name = v.decode()
            elif n == 2:
                entry = dict(pz.decode_fields(v))
                keys.append(f"[{entry[1].decode()}={entry[2].decode()}]")
        elems.append(name + "".join(keys))
    return "/" + "/".join(elems)


class FakeDevice:
    """Remplace subprocess.run : relève chaque appel curl (argv, configuration lue AU MOMENT de l'appel)."""

    def __init__(
        self, policy, *, version=None, device="v26.7.2-519", wrong=(), status="0", rc=0, probe_frames=None
    ):
        self.policy = policy
        self.version = policy["version"] if version is None else version
        self.device, self.wrong, self.status, self.rc = device, set(wrong), status, rc
        self.probe_frames = probe_frames
        self.calls: list[dict] = []
        self.answers = {
            (who, path, mode): action.lower() for who, path, mode, action, _ in pz.expected_probes(policy)
        }

    def __call__(self, args, input=None, **_kw):  # noqa: A002
        config = Path(args[args.index("-K") + 1])
        method = "/".join(args[-1].split("/")[-2:])
        call = {
            "args": list(args),
            "method": method,
            "config": config.read_text(encoding="utf-8"),
            "mode": config.stat().st_mode & 0o777,
            "input": input,
        }
        self.calls.append(call)
        Path(args[args.index("-D") + 1]).write_text(
            f"HTTP/2 200\r\ngrpc-status: {self.status}\r\ngrpc-message: boum\r\n", encoding="utf-8"
        )
        frames = []
        if self.status == "0":
            if method == "gnsi.pathz.v1.Pathz/Get":
                frames = [pz.f_str(1, self.version) + pz.f_int(2, 1)] if self.version else []
            elif method == "gnmi.gNMI/Get":
                frames = [b"\x0a\x20" + self.device.encode()] if self.device else []
            elif method == "gnsi.pathz.v1.Pathz/Probe":
                fields = dict(pz.decode_fields(input[5:]))
                key = (fields[1].decode(), _path_of(fields[2]), {1: "read", 2: "write"}[fields[3]])
                action = self.answers.get(key, "deny")
                if key in self.wrong:
                    action = "deny" if action == "permit" else "permit"
                frames = (
                    self.probe_frames
                    if self.probe_frames is not None
                    else [pz.f_int(1, {"deny": 1, "permit": 2}[action])]
                )
        out = b"".join(b"\x00" + len(f).to_bytes(4, "big") + f for f in frames)
        return type("R", (), {"stdout": out, "returncode": self.rc})()

    def methods(self):
        return [c["method"] for c in self.calls]


@pytest.fixture
def policy():
    return json.loads(POLICY.read_text(encoding="utf-8"))


@pytest.fixture
def device(monkeypatch, policy):
    fake = FakeDevice(policy)
    monkeypatch.setattr(pz.subprocess, "run", fake)
    return fake


@pytest.fixture(autouse=True)
def _fresh_announcements():
    labtls._announced.clear()


@pytest.fixture
def pwfile(tmp_path):
    f = tmp_path / "pw"
    f.write_text(SECRET + "\n", encoding="utf-8")
    f.chmod(0o600)
    return str(f)


def _cli(pwfile, *extra, cmd="verify", policy=POLICY):
    return [cmd, str(policy), "--target", "192.0.2.5", "--user", "admin", "--password-file", pwfile, *extra]


# === 1. TLS ===========================================================================================


def test_tls_is_strict_by_default_no_insecure_flag_reaches_curl(device, policy):
    pz.push("192.0.2.5", "admin", SECRET, policy)
    for call in device.calls:
        assert not {"-k", "-sk", "--insecure"} & set(call["args"])


def test_the_default_tls_arguments_are_empty():
    assert labtls.curl_tls_args() == []


def test_insecure_without_a_lab_inventory_is_refused():
    with pytest.raises(labtls.TlsRefused, match="lab-inventory"):
        labtls.curl_tls_args(insecure=True)


@pytest.mark.parametrize(
    "content",
    [
        "lab: false\n",
        "# lab: true\n",
        "  lab: true\n",  # imbriqué : pas à la racine
        "routers:\n  lab: true\n",
        'lab: "true"\n',
        "lab: yes\n",
        "labs: true\n",
        "",
    ],
)
def test_insecure_is_refused_when_the_inventory_does_not_declare_lab_true(tmp_path, content):
    inv = tmp_path / "inv.yml"
    inv.write_text(content, encoding="utf-8")
    with pytest.raises(labtls.TlsRefused, match="lab: true"):
        labtls.curl_tls_args(insecure=True, lab_inventory=str(inv))


def test_insecure_is_refused_for_a_missing_inventory(tmp_path):
    with pytest.raises(labtls.TlsRefused):
        labtls.curl_tls_args(insecure=True, lab_inventory=str(tmp_path / "absent.yml"))


@pytest.mark.parametrize("inventory", LAB_INVENTORIES, ids=lambda p: p.name)
def test_the_real_lab_inventories_allow_insecure_and_say_so(inventory, capsys):
    assert yaml.safe_load(inventory.read_text(encoding="utf-8"))["lab"] is True
    assert labtls.curl_tls_args(insecure=True, lab_inventory=str(inventory)) == ["--insecure"]
    err = capsys.readouterr().err
    assert "AVERTISSEMENT" in err and "NON vérifiée" in err and str(inventory) in err and "lab: true" in err


def test_the_warning_is_printed_once_per_process(capsys):
    inv = str(LAB_INVENTORIES[0])
    labtls.curl_tls_args(insecure=True, lab_inventory=inv)
    labtls.curl_tls_args(insecure=True, lab_inventory=inv)
    assert capsys.readouterr().err.count("AVERTISSEMENT") == 1


def test_insecure_and_cacert_exclude_each_other(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    with pytest.raises(labtls.TlsRefused, match="s'excluent"):
        labtls.curl_tls_args(insecure=True, cacert=str(ca), lab_inventory=str(LAB_INVENTORIES[0]))


def test_cacert_is_passed_to_curl_and_must_exist(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    assert labtls.curl_tls_args(cacert=str(ca)) == ["--cacert", str(ca)]
    with pytest.raises(labtls.TlsRefused, match="introuvable"):
        labtls.curl_tls_args(cacert=str(tmp_path / "absent.pem"))


def test_the_cli_refuses_insecure_without_inventory_and_never_calls_curl(device, pwfile, capsys):
    assert pz.main(_cli(pwfile, "--insecure")) == 3
    assert "refusé" in capsys.readouterr().err and device.calls == []


def test_the_cli_refuses_a_non_lab_inventory_and_never_calls_curl(device, pwfile, tmp_path):
    inv = tmp_path / "prod.yml"
    inv.write_text("lab: false\n", encoding="utf-8")
    assert pz.main(_cli(pwfile, "--insecure", "--lab-inventory", str(inv))) == 3
    assert device.calls == []


def test_the_cli_passes_insecure_to_every_curl_call_once_authorised(device, pwfile, capsys):
    assert pz.main(_cli(pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0]))) == 0
    assert device.calls and all("--insecure" in c["args"] for c in device.calls)
    assert "AVERTISSEMENT" in capsys.readouterr().err


def test_a_tls_failure_says_so_and_names_the_lab_remedy(monkeypatch, policy, pwfile):
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, status="?", rc=60))
    with pytest.raises(SystemExit) as raised:
        pz.main(["get", "--target", "192.0.2.5", "--user", "admin", "--password-file", pwfile])
    message = str(raised.value)
    assert "échec TLS" in message and "--insecure --lab-inventory" in message and "--cacert" in message


def test_curl_is_never_given_k_in_lab_access_or_tests_tools_outside_labtls():
    offenders = []
    for folder in ("lab-access", "tests/tools"):
        for path in sorted((ROOT / folder).glob("*.py")):
            if path.name == "labtls.py":
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r'"-k"|"-sk"|"--insecure"|\bcurl\b.* -k\b', line) and "add_argument" not in line:
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert offenders == []


def test_no_shell_script_calls_curl_with_k_or_insecure():
    offenders = []
    for path in sorted(ROOT.rglob("*.sh")):
        if ".venv" in path.parts or ".git" in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bcurl\b[^|;&]*(\s-[a-zA-Z]*k[a-zA-Z]*\b|--insecure)", line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


def test_the_ssh_probes_refuse_to_run_without_a_lab_inventory(monkeypatch, capsys):
    monkeypatch.setattr(ro_probe, "eos", lambda args: pytest.fail("la sonde EOS ne doit pas partir"))
    assert ro_probe.main(["eos", "--host", "192.0.2.4", "--key", "k"]) == 3
    assert "lab-inventory" in capsys.readouterr().err


def test_the_services_probe_refuses_curl_without_insecure_and_inventory(monkeypatch, capsys, tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("x", encoding="utf-8")
    monkeypatch.setattr(ro_probe, "services", lambda args: pytest.fail("la sonde ne doit pas partir"))
    base = ["services", "--host", "192.0.2.5", "--user", "u", "--password-file", str(pw)]
    assert ro_probe.main(base) == 3
    assert ro_probe.main([*base, "--insecure"]) == 3
    assert "refusé" in capsys.readouterr().err


# === 2. identifiants : jamais dans la ligne de commande ================================================


def test_the_password_is_in_no_argv_and_no_body_for_any_pathz_call(device, policy):
    pz.push("192.0.2.5", "admin", SECRET, policy)
    pz.get("192.0.2.5", "admin", SECRET)
    pz.probe("192.0.2.5", "admin", SECRET, "x", "/interface", "read")
    pz.device_version("192.0.2.5", "admin", SECRET)
    assert len(device.calls) > 10
    for call in device.calls:
        assert not any(SECRET in str(a) or "password" in str(a).lower() for a in call["args"])
        assert SECRET.encode() not in (call["input"] or b"")
        assert f"password: {SECRET}" in call["config"]
        assert call["mode"] == 0o600


def test_the_version_request_names_a_path_and_the_json_ietf_encoding(device):
    pz.device_version(
        "192.0.2.5", "admin", SECRET
    )  # SR Linux refuse un Get sans encodage (observé : grpc 12)
    fields = dict(pz.decode_fields(device.calls[0]["input"][5:]))
    assert _path_of(fields[2]) == "/system/information/version" and fields[5] == 4


def test_the_curl_configuration_file_is_not_left_behind(device, policy):
    pz.push("192.0.2.5", "admin", SECRET, policy)
    for call in device.calls:
        assert not Path(call["args"][call["args"].index("-K") + 1]).exists()


def test_there_is_no_password_option_on_the_command_line(pwfile):
    with pytest.raises(SystemExit) as raised:
        pz.main([*_cli(pwfile), "--password", SECRET])
    assert raised.value.code == 2
    with pytest.raises(SystemExit) as raised:
        ro_probe.main(["services", "--host", "h", "--user", "u", "--password", SECRET])
    assert raised.value.code == 2
    # abréviations désactivées aussi sur les sondes SSH : « --admin-password » ≠ « --admin-password-file »
    with pytest.raises(SystemExit) as raised:
        ro_probe.main(["srlinux", "--host", "h", "--key", "k", "--admin-password", SECRET])
    assert raised.value.code == 2


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_a_password_file_that_others_can_read_is_refused_before_any_call(device, pwfile, mode):
    Path(pwfile).chmod(mode)
    with pytest.raises(SystemExit, match="droits"):
        pz.main(_cli(pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0])))
    assert device.calls == []


def test_the_probe_tool_curl_calls_never_carry_the_password_either(monkeypatch, tmp_path):
    seen = []

    def fake_run(args, input=None, **_kw):  # noqa: A002
        config = Path(args[args.index("-K") + 1])
        seen.append(
            {
                "args": list(args),
                "config": config.read_text(encoding="utf-8"),
                "mode": stat.S_IMODE(config.stat().st_mode),
            }
        )
        if "-D" in args:
            Path(args[args.index("-D") + 1]).write_text("grpc-status: 7\r\n", encoding="utf-8")
        return type("R", (), {"stdout": b"", "returncode": 0})()

    monkeypatch.setattr(ro_probe.subprocess, "run", fake_run)
    ro_probe._gnmi("192.0.2.5", "netcheck-ro", SECRET, "Get", b"", ["--insecure"])
    ro_probe._jsonrpc("192.0.2.5", "netcheck-ro", SECRET)
    assert len(seen) == 2
    for call in seen:
        assert not any(SECRET in str(a) for a in call["args"])
        assert SECRET in call["config"] and call["mode"] == 0o600
    assert "--insecure" in seen[0]["args"] and "-k" not in seen[0]["args"] and "-sk" not in seen[0]["args"]


def test_accounts_lab_writes_the_admin_password_to_a_0600_file_before_anything_else():
    text = (ROOT / "lab-access" / "accounts_lab.sh").read_text(encoding="utf-8")
    body = text.split("srl_admin_password_file()", 1)[1].split("\n}", 1)[0]
    assert body.index('chmod 600 "$f"') < body.index('> "$f"')
    assert "--password " not in text and "--password=" not in text
    assert text.count("--password-file") == 2  # push et verify : toujours par fichier


# === 3. cloisonnement et épinglage =====================================================================


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_netcheck_imports_nothing_from_lab_access_or_the_test_tools():
    lab_modules = {p.stem for p in (ROOT / "lab-access").glob("*.py")} | {
        p.stem for p in (ROOT / "tests" / "tools").glob("*.py")
    }
    assert {"pathz_lab", "labtls", "ro_probe"} <= lab_modules
    offenders = []
    for path in sorted((ROOT / "netcheck").rglob("*.py")):
        if ".venv" in path.parts:
            continue
        hit = (_imports(path) & lab_modules) | ({"lab_access"} & _imports(path))
        if hit:
            offenders.append(f"{path.relative_to(ROOT)} : {sorted(hit)}")
    assert offenders == []


def test_netcheck_never_reaches_into_lab_access_by_path_or_by_sys_path():
    """Seul `automation/` (labtools, code partagé et versionné avec netcheck) est ajouté à sys.path."""
    offenders = []
    for path in sorted((ROOT / "netcheck").rglob("*.py")):
        if ".venv" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "lab-access" in node.value:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} chaîne « lab-access »")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("insert", "append", "extend")
                and ast.unparse(node.func.value) == "sys.path"
                and "AUTOMATION_DIR" not in ast.unparse(node)
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} {ast.unparse(node)}")
    assert offenders == []


def test_the_automation_folder_netcheck_puts_on_sys_path_imports_nothing_from_lab_access():
    lab_modules = {p.stem for p in (ROOT / "lab-access").glob("*.py")} | {
        p.stem for p in (ROOT / "tests" / "tools").glob("*.py")
    }
    for path in sorted((ROOT / "automation").glob("*.py")):
        assert not (_imports(path) & lab_modules), path.name


def test_netcheck_has_no_grpc_or_protobuf_dependency():
    for name in ("requirements.txt", "requirements-dev.txt"):
        text = (ROOT / "netcheck" / name).read_text(encoding="utf-8").lower()
        for word in ("grpc", "protobuf", "gnsic", "gnmi", "pygnmi"):
            assert word not in text, (name, word)


@pytest.mark.parametrize("module", ["pathz_lab.py", "labtls.py"])
def test_the_lab_tools_use_the_standard_library_only(module):
    allowed = set(sys.stdlib_module_names) | {"labtls", "__future__"}
    assert _imports(ROOT / "lab-access" / module) <= allowed


def test_the_tool_is_pinned_to_the_srlinux_version_of_the_lab():
    assert pz.VALIDATED_FOR == "26.7.2"
    topology = yaml.safe_load((ROOT / "lab-multivendor.clab.yml").read_text(encoding="utf-8"))
    images = [n["image"] for n in topology["topology"]["nodes"].values() if n.get("kind") == "nokia_srlinux"]
    assert images and all(f":{pz.VALIDATED_FOR}-" in image for image in images)


def test_an_other_srlinux_version_is_refused_with_code_3_and_nothing_is_pushed(
    monkeypatch, policy, pwfile, capsys
):
    fake = FakeDevice(policy, device="v26.3.1-100")
    monkeypatch.setattr(pz.subprocess, "run", fake)
    argv = _cli(pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0]), cmd="push")
    assert pz.main(argv) == 3
    assert "26.7.2" in capsys.readouterr().err
    assert "gnsi.pathz.v1.Pathz/Rotate" not in fake.methods()


def test_an_unreadable_version_is_refused_too(monkeypatch, policy, pwfile):
    fake = FakeDevice(policy, device="")
    monkeypatch.setattr(pz.subprocess, "run", fake)
    assert pz.main(_cli(pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0]), cmd="push")) == 3
    assert "gnsi.pathz.v1.Pathz/Rotate" not in fake.methods()


def test_allow_other_version_goes_on_and_the_verification_still_decides(monkeypatch, policy, pwfile):
    fake = FakeDevice(policy, device="v26.3.1-100")
    monkeypatch.setattr(pz.subprocess, "run", fake)
    argv = _cli(
        pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0]), "--allow-other-version", cmd="push"
    )
    assert pz.main(argv) == 0
    assert "gnsi.pathz.v1.Pathz/Rotate" in fake.methods()


# === 4. vérification après envoi : jamais de succès silencieux ========================================


def test_push_sends_then_reads_back_the_version_and_one_probe_per_expectation(device, policy, capsys):
    pz.push("192.0.2.5", "admin", SECRET, policy)
    methods = device.methods()
    n = len(pz.expected_probes(policy))
    assert methods[0] == "gnsi.pathz.v1.Pathz/Rotate"
    assert methods[1] == "gnsi.pathz.v1.Pathz/Get"
    assert methods[2:] == ["gnsi.pathz.v1.Pathz/Probe"] * n and n >= len(policy["rules"])
    out = capsys.readouterr().out
    assert "effective" in out and "netcheck-ro-v1" in out and f"{n} sonde(s) conformes" in out


def test_every_rule_and_every_expectation_is_probed(device, policy):
    pz.verify("192.0.2.5", "admin", SECRET, policy)
    probed = set()
    for call in device.calls:
        if call["method"].endswith("Probe"):
            f = dict(pz.decode_fields(call["input"][5:]))
            probed.add((f[1].decode(), _path_of(f[2]), {1: "read", 2: "write"}[f[3]]))
    for rule in policy["rules"]:
        assert (rule["user"], rule.get("sonde", rule["path"]), rule["mode"]) in probed, rule["id"]
    for item in policy["attendus"]:
        assert (item["user"], item["path"], item["mode"]) in probed


def test_a_probe_that_contradicts_the_policy_fails_loudly_and_names_the_line(monkeypatch, policy):
    wrong = [("netcheck-ro", "/interface[name=ethernet-1/1]", "write")]
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, wrong=wrong))
    with pytest.raises(SystemExit) as raised:
        pz.verify("192.0.2.5", "admin", SECRET, policy)
    message = str(raised.value)
    assert (
        "NON EFFECTIVE" in message
        and "netcheck-ro write /interface[name=ethernet-1/1] : PERMIT au lieu de DENY" in message
    )


def test_every_mismatch_is_listed_not_only_the_first(monkeypatch, policy):
    wrong = [
        ("netcheck-ro", "/interface[name=ethernet-1/1]", "write"),
        ("netcheck-ro", "/acl", "read"),
        ("admin", "/system/aaa", "write"),
    ]
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, wrong=wrong))
    with pytest.raises(SystemExit) as raised:
        pz.verify("192.0.2.5", "admin", SECRET, policy)
    assert str(raised.value).count(" au lieu de ") == 3


@pytest.mark.parametrize("version", ["autre-version", ""])
def test_another_active_version_is_not_effective(monkeypatch, policy, version):
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, version=version))
    with pytest.raises(SystemExit, match="version active"):
        pz.verify("192.0.2.5", "admin", SECRET, policy)


def test_an_empty_probe_reply_is_a_failure_not_a_success(monkeypatch, policy):
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, probe_frames=[]))
    with pytest.raises(SystemExit, match="NON EFFECTIVE"):
        pz.verify("192.0.2.5", "admin", SECRET, policy)


def test_an_unspecified_probe_answer_is_a_failure(monkeypatch, policy):
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, probe_frames=[pz.f_int(1, 0)]))
    with pytest.raises(SystemExit, match="UNSPECIFIED"):
        pz.verify("192.0.2.5", "admin", SECRET, policy)


@pytest.mark.parametrize("status", ["3", "7", "14", "?"])
def test_a_rotate_refused_by_the_device_stops_before_the_verification(monkeypatch, policy, status):
    fake = FakeDevice(policy, status=status)
    monkeypatch.setattr(pz.subprocess, "run", fake)
    with pytest.raises(SystemExit, match="Pathz.Rotate"):
        pz.push("192.0.2.5", "admin", SECRET, policy)
    assert fake.methods() == ["gnsi.pathz.v1.Pathz/Rotate"]


def test_a_policy_without_any_probe_cannot_be_verified(device):
    with pytest.raises(SystemExit, match="aucune règle"):
        pz.verify("192.0.2.5", "admin", SECRET, {"version": "v", "rules": []})


def test_verify_sends_nothing(device, policy):
    pz.verify("192.0.2.5", "admin", SECRET, policy)
    assert "gnsi.pathz.v1.Pathz/Rotate" not in device.methods()


def test_the_cli_exit_code_is_zero_only_when_the_policy_is_effective(monkeypatch, policy, pwfile):
    argv = _cli(pwfile, "--insecure", "--lab-inventory", str(LAB_INVENTORIES[0]), cmd="push")
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy))
    assert pz.main(argv) == 0
    monkeypatch.setattr(pz.subprocess, "run", FakeDevice(policy, wrong=[("admin", "/system/aaa", "write")]))
    with pytest.raises(SystemExit) as raised:
        pz.main(argv)
    assert raised.value.code not in (0, None)


def _names(path: str) -> list[str]:
    """Éléments d'un chemin sans leurs clés : /interface[name=e1/1]/x -> ['interface', 'x']."""
    return [re.sub(r"\[.*", "", part) for part in pz.split_path(path)]


def _covers(rule: dict, user: str, path: str, mode: str) -> bool:
    """La règle `permit` accorde-t-elle (utilisateur, chemin, mode) ? Écrire implique lire (observé)."""
    if rule["user"] != user or rule["action"] != "permit":
        return False
    if rule["mode"] == "read" and mode == "write":
        return False
    prefix = _names(rule["path"])
    return _names(path)[: len(prefix)] == prefix


def test_every_probe_path_is_concrete_and_covered_by_its_own_rule(policy):
    for rule in policy["rules"]:
        sonde = rule.get("sonde", rule["path"])
        assert _names(sonde)[: len(_names(rule["path"]))] == _names(rule["path"]), rule["id"]
        if "sonde" in rule:
            assert re.search(r"\[[^=\]]+=[^\]]+\]", sonde) or rule["path"] == sonde, rule["id"]
    listed = [
        r
        for r in policy["rules"]
        if r["user"] == "netcheck-ro"
        and _names(r["path"])
        in (
            ["interface"],
            ["network-instance", "interface"],
        )
    ]
    assert all("sonde" in r for r in listed)  # une liste sans clé fait refuser la sonde (jokers)


def test_the_expectations_never_contradict_a_rule_and_are_well_formed(policy):
    seen = set()
    for item in policy["attendus"]:
        assert set(item) <= {"user", "path", "mode", "action", "pourquoi"} and item.get("pourquoi")
        assert item["action"] in pz.ACTIONS and item["mode"] in pz.MODES and item["path"].startswith("/")
        key = (item["user"], item["path"], item["mode"])
        assert key not in seen
        seen.add(key)
        covered = any(_covers(r, *key) for r in policy["rules"])
        assert covered == (item["action"] == "permit"), key
    assert any(
        i["action"] == "deny" and i["user"] == "netcheck-ro" and i["mode"] == "write"
        for i in policy["attendus"]
    )
    assert any(i["user"] == "admin" and i["mode"] == "write" for i in policy["attendus"])


def test_the_covering_helper_follows_the_observed_pathz_semantics(policy):
    rules = policy["rules"]
    assert any(_covers(r, "admin", "/anything/at/all", "write") for r in rules)
    assert any(_covers(r, "netcheck-ro", "/interface[name=x]/statistics", "read") for r in rules)
    assert not any(_covers(r, "netcheck-ro", "/interface[name=x]", "write") for r in rules)
    assert not any(_covers(r, "netcheck-ro", "/system/aaa", "read") for r in rules)
    assert not any(_covers(r, "nobody", "/interface[name=x]", "read") for r in rules)


def test_comments_and_expectations_are_never_sent_to_the_device(policy):
    stripped = {k: v for k, v in policy.items() if k not in ("commentaire", "attendus")}
    stripped["rules"] = [{k: v for k, v in r.items() if k != "sonde"} for r in policy["rules"]]
    assert pz.encode_rotate(policy, 7) == pz.encode_rotate(stripped, 7)


def test_accounts_lab_pushes_with_verification_and_status_verifies_without_sending():
    text = (ROOT / "lab-access" / "accounts_lab.sh").read_text(encoding="utf-8")
    assert re.search(
        r'pathz_lab\.py push "\$PATHZ_POLICY".*\\\n\s+--insecure --lab-inventory "\$LAB_INVENTORY"', text
    )
    assert re.search(
        r'pathz_lab\.py verify "\$PATHZ_POLICY".*\\\n\s+--insecure --lab-inventory "\$LAB_INVENTORY"', text
    )
    assert "LAB_INVENTORY=automation/inventory-multivendor.yml" in text
    inventory = yaml.safe_load(
        (ROOT / "automation" / "inventory-multivendor.yml").read_text(encoding="utf-8")
    )
    assert inventory["lab"] is True
    assert "NON effective" in text  # le message d'échec ne parle jamais de « succès » à demi


def test_lib_ro_passes_the_lab_inventory_to_every_probe():
    text = (ROOT / "tests" / "lib_ro.sh").read_text(encoding="utf-8")
    calls = re.findall(r"ro_probe\.py (?:eos|srlinux|services)[^\n]*", text)
    assert len(calls) == 4 and all('--lab-inventory "$C5_LAB_INV"' in c for c in calls)
    assert all("--insecure" in c for c in calls if " services " in c)


def _report(text: str) -> list[str]:
    """Fait lire `text` à c5_report (tests/lib_ro.sh) avec des ok/ko qui se contentent d'écrire."""
    script = (
        'ok() { echo "OK:$1"; }; ko() { echo "KO:$1"; }; source tests/lib_ro.sh; '
        "c5_report <<'EOF'\n" + text + "\nEOF"
    )
    out = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


def test_c5_report_shows_ok_and_ko_lines_and_the_guard_warning_is_not_a_failure():
    warning = "AVERTISSEMENT : TLS non vérifié (--insecure) -- identité NON vérifiée, permis car `lab: true`."
    lines = _report("OK un contrôle\nKO un autre\n" + warning)
    assert lines[0] == "OK:un contrôle" and lines[1] == "KO:un autre"
    assert lines[2].startswith("  ⚠️  AVERTISSEMENT : TLS non vérifié") and "(lab seulement)" in lines[2]
    assert not any(line.startswith("KO:") for line in lines[2:])


@pytest.mark.parametrize(
    "garbage",
    [
        "Traceback (most recent call last):",
        '  File "x.py", line 1',
        "ModuleNotFoundError: paramiko",
        "OKAY presque",
    ],
)
def test_c5_report_treats_any_other_text_as_a_failure(garbage):
    assert _report(garbage) == [f"KO:sortie inattendue de la sonde : {garbage}"]


def test_the_deliberately_false_expectation_uses_a_concrete_path():
    """Un joker ferait échouer Pathz.Probe (grpc 3) AVANT la comparaison : le message ne serait pas prouvé."""
    text = (ROOT / "tests" / "lib_ro.sh").read_text(encoding="utf-8")
    path = re.search(r'"path": "([^"]+)", "mode": "write", "action": "permit", "pourquoi": "FAUX', text)
    assert path and re.search(r"\[[^=\]]+=[^\]]+\]", path.group(1))


def test_every_probe_in_lib_ro_goes_through_c5_report():
    text = (ROOT / "tests" / "lib_ro.sh").read_text(encoding="utf-8")
    assert text.count("c5_report < <(netcheck/.venv/bin/python tests/tools/ro_probe.py") == 4
    assert 'ok "${line#OK }" ||' not in text


# === 5. config.cli : aucun commentaire (le chargeur de containerlab avorte en silence) ===================


def _comments(text: str) -> list[tuple[int, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        quoted = False
        for char in line:
            if char == '"':
                quoted = not quoted
            elif char == "#" and not quoted:
                found.append((number, line.strip()))
                break
    return found


CONFIG_CLI = sorted((ROOT / "configs-multivendor").glob("*/config.cli"))


def test_there_is_a_config_cli_to_check():
    assert [p.parent.name for p in CONFIG_CLI] == ["r5"]


@pytest.mark.parametrize("path", CONFIG_CLI, ids=lambda p: p.parent.name)
def test_config_cli_has_no_comment_at_all(path):
    assert _comments(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "line",
    ["# note", "   # note", 'set / system banner login-banner "x"  # note', "set / x y # z"],
)
def test_the_comment_detector_finds_comments_the_way_the_loader_would(line):
    assert _comments(line) != []


def test_the_comment_detector_ignores_a_hash_inside_quotes():
    assert _comments('set / system banner login-banner "Acces #1 reserve"') == []


def test_the_role_lines_the_post_deploy_check_expects_are_in_config_cli():
    lines = [
        ln
        for ln in CONFIG_CLI[0].read_text(encoding="utf-8").splitlines()
        if ln.startswith("set / system aaa authorization role netcheck-ro")
    ]
    assert len(lines) == 3
    assert any(" services [ cli ]" in ln for ln in lines)
    assert any('deny-command-list [ ".*" ]' in ln for ln in lines)
    allow = [ln for ln in lines if "allow-command-list" in ln][0]
    assert len(re.findall(r'"\^', allow)) == 10


def test_test_lab_multivendor_checks_the_role_is_loaded_before_provisioning():
    text = (ROOT / "test_lab_multivendor.sh").read_text(encoding="utf-8")
    assert "tests/tools/srl_role_check.py configs-multivendor/r5/config.cli" in text
    assert "info flat from running system aaa authorization role netcheck-ro" in text
    assert text.index("rôle netcheck-ro chargé") < text.index("accounts_lab.sh multivendor provision")


# --- srl_role_check : le fichier demandé = la configuration courante --------------------------------

# Réponse RÉELLE de SR Linux 26.7.2 (r5, lab mixte) : liste triée, antislashs doublés, `.*` sans guillemets.
_ALLOW = [
    "^environment cli-engine type basic$",
    "^environment complete-on-space false$",
    r"^info from running interface \\*$",
    "^info from running network-instance default protocols ospf$",
    "^info from running system authentication$",
    "^info from running system banner$",
    r"^info from state interface \\* \\| as json$",
    r"^info from state network-instance \\* interface \\* \\| as json$",
    r"^info from state network-instance \\* route-table \\| as json$",
    r"^show network-instance default protocols ospf neighbor \\| as json$",
]
_ROLE = "set / system aaa authorization role netcheck-ro "
LIVE_ROLE = (
    f"{_ROLE}services [ cli ]\n"
    f"{_ROLE}cli deny-command-list [ .* ]\n"
    f"{_ROLE}cli allow-command-list [ " + " ".join(f'"{item}"' for item in _ALLOW) + " ]\n"
)


@pytest.fixture
def role_check():
    import srl_role_check

    return srl_role_check


def _wanted() -> str:
    return CONFIG_CLI[0].read_text(encoding="utf-8")


def test_the_real_config_cli_matches_the_real_srlinux_answer(role_check):
    assert role_check.compare(_wanted(), LIVE_ROLE) == []
    assert sorted(role_check.parse(_wanted())) == [
        "cli allow-command-list",
        "cli deny-command-list",
        "services",
    ]


def test_a_role_that_did_not_load_is_reported(role_check):
    problems = role_check.compare(_wanted(), "")
    assert len(problems) == 3 and all("absent de la configuration courante" in p for p in problems)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda live: live.replace('"^info from running system banner$" ', ""),
        lambda live: live.replace('system banner$"', 'system banner$" "^bash$"'),
        lambda live: live.replace("[ .* ]", "[ ]"),
        lambda live: live.replace("services [ cli ]", "services [ cli gnmi json-rpc ]"),
        lambda live: live.replace("\\\\*$", "\\\\.*$", 1),
        lambda live: "\n".join(live.splitlines()[:2]) + "\n",
        lambda live: "\n".join(live.splitlines()[1:]) + "\n",
    ],
    ids=[
        "entry-missing",
        "entry-extra",
        "deny-empty",
        "services-wider",
        "regex-changed",
        "allow-gone",
        "services-gone",
    ],
)
def test_any_difference_between_the_file_and_the_device_is_reported(role_check, mutation):
    mutated = mutation(LIVE_ROLE)
    assert mutated != LIVE_ROLE
    assert role_check.compare(_wanted(), mutated) != []


def test_a_file_without_role_lines_cannot_be_compared(role_check):
    assert "rien à comparer" in role_check.compare("set / system name host-name r5\n", LIVE_ROLE)[0]


def test_a_line_on_the_device_that_the_file_does_not_ask_for_is_reported(role_check):
    extra = LIVE_ROLE + "set / system aaa authorization role netcheck-ro cli extra-list [ x ]\n"
    assert any("absent de config.cli" in p for p in role_check.compare(_wanted(), extra))


def test_the_cli_exit_codes(role_check, monkeypatch, capsys, tmp_path):
    import io

    cfg = tmp_path / "config.cli"
    cfg.write_text(_wanted(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", io.StringIO(LIVE_ROLE))
    assert role_check.main([str(cfg)]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert role_check.main([str(cfg)]) == 1
    assert "absent de la configuration courante" in capsys.readouterr().err
    assert role_check.main([]) == 2
