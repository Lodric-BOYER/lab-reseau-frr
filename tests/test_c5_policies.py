"""Phase C5 : les trois politiques du compte netcheck-ro restent alignées sur les listes blanches des drivers.

- SR Linux : la politique Pathz (lab-access/pathz/netcheck-ro.json) donne lecture seule sur les SEULS chemins
  des huit commandes du driver ; l'encodeur protobuf de lab-access/pathz_lab.py produit des messages que l'on
  relit ici avec un décodeur indépendant ; le rôle de configs-multivendor/r5/config.cli autorise exactement
  ces huit commandes
  (+ les deux `environment` de Netmiko) et refuse tout le reste.
- EOS : le rôle de configs-ceos/r4/startup-config autorise exactement les douze commandes de la liste blanche
  (sans `| json`, qu'EOS n'évalue pas) et les commandes de session de Netmiko, puis refuse tout.
"""

import json
import re
import shlex
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab-access"))

import pathz_lab as pz  # noqa: E402

from netcheck.drivers.eos import EosDriver  # noqa: E402
from netcheck.drivers.srlinux import SrlinuxDriver  # noqa: E402

POLICY = ROOT / "lab-access" / "pathz" / "netcheck-ro.json"


# --- décodeur protobuf indépendant (ne partage rien avec l'encodeur) ------------------------------


def _varint(b: bytes, i: int):
    shift = value = 0
    while True:
        c = b[i]
        i += 1
        value |= (c & 0x7F) << shift
        if not c & 0x80:
            return value, i
        shift += 7


def _fields(b: bytes):
    i = 0
    while i < len(b):
        tag, i = _varint(b, i)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            value, i = _varint(b, i)
        elif wire == 2:
            n, i = _varint(b, i)
            value, i = b[i : i + n], i + n
        else:
            raise AssertionError(f"type de fil inattendu {wire}")
        yield number, value


def _path(b: bytes) -> str:
    elems = []
    for number, value in _fields(b):
        assert number == 3
        name, keys = "", {}
        for n, v in _fields(value):
            if n == 1:
                name = v.decode()
            elif n == 2:
                entry = dict(_fields(v))
                keys[entry[1].decode()] = entry[2].decode()
        elems.append(name + "".join(f"[{k}={v}]" for k, v in keys.items()))
    return "/" + "/".join(elems)


def _rules(policy_bytes: bytes) -> list[dict]:
    out = []
    for number, value in _fields(policy_bytes):
        if number != 1:
            continue
        rule = {}
        for n, v in _fields(value):
            rule[{1: "id", 2: "user", 3: "group", 4: "path", 5: "action", 6: "mode"}[n]] = (
                _path(v) if n == 4 else (v.decode() if isinstance(v, bytes) else v)
            )
        out.append(rule)
    return out


# --- encodage -------------------------------------------------------------------------------------


def test_the_root_path_is_an_empty_path():
    assert pz.encode_path("/") == b""


def test_a_path_is_encoded_as_gnmi_path_elements():
    assert pz.encode_path("/interface") == pz.f_bytes(3, pz.f_str(1, "interface"))
    assert _path(pz.encode_path("/network-instance/protocols/ospf")) == "/network-instance/protocols/ospf"


def test_list_keys_are_encoded_and_a_slash_inside_a_key_value_is_not_a_separator():
    path = "/interface[name=ethernet-1/1]/subinterface[index=0]"
    assert _path(pz.encode_path(path)) == path
    assert pz.split_path(path) == ["interface[name=ethernet-1/1]", "subinterface[index=0]"]


@pytest.mark.parametrize("bad", ["interface", "", "/a[b", "/a]b[", "/[name=x]"])
def test_a_malformed_path_is_refused(bad):
    with pytest.raises(ValueError):
        pz.encode_path(bad)


def test_a_rule_uses_the_field_numbers_of_the_gnsi_proto():
    rule = {"id": "r", "user": "u", "path": "/interface", "action": "permit", "mode": "write"}
    decoded = _rules(pz.f_bytes(1, pz.encode_rule(rule)))[0]
    assert decoded == {"id": "r", "user": "u", "path": "/interface", "action": 2, "mode": 2}
    group = {"id": "g", "group": "admins", "path": "/", "action": "deny", "mode": "read"}
    decoded = _rules(pz.f_bytes(1, pz.encode_rule(group)))[0]
    assert decoded == {"id": "g", "group": "admins", "path": "/", "action": 1, "mode": 1}


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "r", "path": "/", "action": "permit", "mode": "read"},  # ni user ni group
        {"id": "r", "user": "u", "group": "g", "path": "/", "action": "permit", "mode": "read"},  # les deux
        {"id": "r", "user": "u", "path": "/", "action": "allow", "mode": "read"},
        {"id": "r", "user": "u", "path": "/", "action": "permit", "mode": "append"},
        {"user": "u", "path": "/", "action": "permit", "mode": "read"},
    ],
)
def test_an_incomplete_or_ambiguous_rule_is_refused(rule):
    with pytest.raises(ValueError):
        pz.encode_rule(rule)


def test_rotate_sends_the_upload_then_the_finalize_message():
    policy = {
        "version": "v1",
        "rules": [{"id": "r", "user": "u", "path": "/", "action": "permit", "mode": "read"}],
    }
    upload, finalize = pz.encode_rotate(policy, 12345)
    assert [n for n, _ in _fields(upload)] == [1, 3] and [n for n, _ in _fields(finalize)] == [2]
    assert dict(_fields(upload))[3] == 1  # force_overwrite : rejouable après chaque déploiement
    body = dict(_fields(dict(_fields(upload))[1]))
    assert body[1] == b"v1" and body[2] == 12345 and len(_rules(body[3])) == 1
    assert dict(_fields(finalize)) == {2: b""}


def test_groups_are_encoded_after_the_rules():
    policy = {"version": "v", "rules": [], "groups": [{"name": "admins", "users": ["admin", "ops"]}]}
    data = pz.encode_policy(policy)
    ((number, group),) = list(_fields(data))
    assert number == 2
    fields = list(_fields(group))
    assert fields[0] == (1, b"admins") and [v for n, v in fields[1:] if n == 2]


# --- la politique du dépôt ------------------------------------------------------------------------


def _policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def test_the_policy_file_encodes_and_ignores_its_comment():
    policy = _policy()
    assert "commentaire" in policy and policy["version"] == "netcheck-ro-v1"
    decoded = _rules(pz.encode_policy(policy))
    assert [r["id"] for r in decoded] == [r["id"] for r in policy["rules"]]


def test_admin_keeps_full_access_with_a_single_write_rule_that_nothing_overrides():
    # MODE_WRITE implique la lecture ; une règle de lecture ajoutée ensuite sur le même chemin l'annulerait
    admin = [r for r in _policy()["rules"] if r.get("user") == "admin"]
    assert admin == [
        {"id": "admin-acces-complet", "user": "admin", "path": "/", "action": "permit", "mode": "write"}
    ]


def test_netcheck_ro_has_read_permits_only_and_never_the_root():
    rules = [r for r in _policy()["rules"] if r.get("user") == "netcheck-ro"]
    assert rules and all(r["action"] == "permit" and r["mode"] == "read" for r in rules)
    assert all(r["path"] != "/" and "*" not in r["path"] for r in rules)


def test_netcheck_ro_paths_are_exactly_those_of_the_eight_driver_commands():
    paths = sorted(r["path"] for r in _policy()["rules"] if r.get("user") == "netcheck-ro")
    assert paths == sorted(
        [
            "/interface",
            "/network-instance/interface",
            "/network-instance/route-table",
            "/network-instance/protocols/ospf",
            "/system/authentication",
            "/system/banner",
            "/system/name",
        ]
    )
    # chaque commande du driver tombe sous un de ces chemins (table écrite à la main, une ligne par commande)
    covers = {
        "info from state interface * | as json": "/interface",
        "info from state network-instance * interface * | as json": "/network-instance/interface",
        "info from state network-instance * route-table | as json": "/network-instance/route-table",
        "show network-instance default protocols ospf neighbor | as json": "/network-instance/protocols/ospf",
        "info from running interface *": "/interface",
        "info from running network-instance default protocols ospf": "/network-instance/protocols/ospf",
        "info from running system authentication": "/system/authentication",
        "info from running system banner": "/system/banner",
    }
    driver = SrlinuxDriver()
    assert sorted(driver.translate(c) for c in driver.REQUIRED_COMMANDS) == sorted(covers)
    assert set(covers.values()) <= set(paths)


def test_no_secret_or_aaa_path_is_readable_by_netcheck_ro():
    for r in _policy()["rules"]:
        if r.get("user") == "netcheck-ro":
            assert not r["path"].startswith(
                ("/system/aaa", "/system/tls", "/system/ssh-server", "/system/grpc-server")
            )


# --- SR Linux : le rôle de config.cli -------------------------------------------------------------


def _srl_role() -> tuple[list[str], list[str], str]:
    lines = (ROOT / "configs-multivendor" / "r5" / "config.cli").read_text(encoding="utf-8").splitlines()
    mine = [ln for ln in lines if ln.startswith("set / system aaa authorization role netcheck-ro")]
    allow = next(ln for ln in mine if " cli allow-command-list " in ln)
    deny = next(ln for ln in mine if " cli deny-command-list " in ln)
    services = next(ln for ln in mine if " services " in ln)
    quoted = lambda ln: shlex.split(ln.split("[", 1)[1].rsplit("]", 1)[0])  # noqa: E731
    return quoted(allow), quoted(deny), services


def test_the_srlinux_allow_list_matches_exactly_the_eight_commands_and_the_two_environment_ones():
    allow, _, _ = _srl_role()
    driver = SrlinuxDriver()
    commands = [driver.translate(c) for c in driver.REQUIRED_COMMANDS] + [
        "environment complete-on-space false",
        "environment cli-engine type basic",
    ]
    assert len(allow) == 10 and len(commands) == 10
    for command in commands:
        matching = [rx for rx in allow if re.match(rx, command)]
        assert len(matching) == 1, (command, matching)
    for rx in allow:
        assert rx.startswith("^") and rx.endswith("$")


@pytest.mark.parametrize(
    "other",
    [
        "show version",
        "info from running /",
        "info from running system aaa",
        "enter candidate",
        "bash id",
        "save file /tmp/x",
        "file cat /etc/passwd",
        "info from running interface * | as json",
        "info from running interface",
        "info from state system aaa authentication",
        " info from running interface *",
        "tools system reboot",
    ],
)
def test_nothing_else_matches_the_srlinux_allow_list(other):
    allow, _, _ = _srl_role()
    assert not any(re.match(rx, other) for rx in allow)


def test_the_srlinux_role_is_cli_only_and_denies_everything_else_explicitly():
    _, deny, services = _srl_role()
    assert services.endswith("services [ cli ]")  # ni gNMI, ni JSON-RPC (refus observé en direct)
    assert deny == [".*"]
    # un deny plus étroit à côté de la liste blanche la rendrait permissive (observé) : jamais présent
    assert len(deny) == 1


# --- EOS : le rôle de startup-config --------------------------------------------------------------


def _eos_permits() -> list[str]:
    text = (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
    return re.findall(r"^   \d+ permit mode exec command (\^.*\$)$", text, re.M)


def _eos_denies() -> list[tuple[int, str]]:
    text = (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
    return [(int(n), rest) for n, rest in re.findall(r"^   (\d+) deny (.*)$", text, re.M)]


def test_the_eos_permits_are_exactly_the_twelve_whitelisted_commands_plus_netmiko_session_commands():
    permits = _eos_permits()
    assert len(permits) == 14 and all(p.startswith("^") and p.endswith("$") for p in permits)
    # EOS évalue la commande SANS `| json` (format de sortie) : on compare sans ce suffixe
    for cli in sorted(EosDriver.ALLOWED_CLI):
        bare = cli.removesuffix(" | json")
        matching = [p for p in permits if re.fullmatch(p, bare)]
        assert len(matching) == 1, (cli, matching)
    for session in ("enable", "terminal width 511", "terminal length 0"):
        assert [p for p in permits if re.fullmatch(p, session)], session


@pytest.mark.parametrize(
    "other",
    [
        "show version",
        "show startup-config",
        "show running-config sanitized",
        "show running-config all",
        "show ip bgp neighbors",
        "show ip bgp summary vrf all",
        "show interfaces status",
        "configure terminal",
        "copy running-config flash:x",
        "write memory",
        "bash",
        "reload",
        "show ip route",
        "terminal width",
        "terminal monitor",
        "enable secret x",
    ],
)
def test_nothing_else_matches_the_eos_permits(other):
    assert not [p for p in _eos_permits() if re.fullmatch(p, other)]


def test_the_eos_role_ends_with_explicit_denies_in_exec_and_configuration_modes():
    denies = _eos_denies()
    assert [d for _, d in denies] == [
        "mode exec command .*",
        "mode config command .*",
        "mode config-all command .*",
        "command .*",
    ]
    permit_numbers = [
        int(n)
        for n in re.findall(
            r"^   (\d+) permit",
            (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8"),
            re.M,
        )
    ]
    assert (
        max(permit_numbers) < min(n for n, _ in denies) and max(n for n, _ in denies) <= 256
    )  # séquences ≤ 256 (EOS)


def test_the_two_aaa_lines_that_make_the_eos_role_effective_are_in_the_startup_config():
    text = (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
    assert "\naaa authorization exec default local\n" in text
    assert "\naaa authorization commands all default local\n" in text
    assert text.index("aaa authorization commands all default local") < text.index("role netcheck-ro")


# --- l'appel gRPC : aucun secret en argument, droits du fichier de mot de passe -------------------


class _Curl:
    """Faux `curl` : relève la ligne de commande et le fichier de configuration AU MOMENT de l'appel."""

    def __init__(self, status="0", frames=(), rc=0):
        self.status, self.frames, self.rc = status, frames, rc
        self.calls: list[dict] = []

    def __call__(self, args, input=None, **_kw):  # noqa: A002
        config = Path(args[args.index("-K") + 1])
        Path(args[args.index("-D") + 1]).write_text(
            f"HTTP/2 200\r\ngrpc-status: {self.status}\r\ngrpc-message: boum\r\n", encoding="utf-8"
        )
        self.calls.append(
            {
                "args": list(args),
                "body": input,
                "config": config.read_text(encoding="utf-8"),
                "mode": config.stat().st_mode & 0o777,
            }
        )
        out = b"".join(b"\x00" + len(f).to_bytes(4, "big") + f for f in self.frames)
        return type("R", (), {"stdout": out, "returncode": self.rc})()


@pytest.fixture
def curl(monkeypatch):
    fake = _Curl()
    monkeypatch.setattr(pz.subprocess, "run", fake)
    return fake


def test_the_password_goes_in_a_0600_curl_config_never_in_the_command_line(curl):
    pz.get("192.0.2.5", "admin", "S3cret-Pass-Word")
    call = curl.calls[0]
    assert not any("S3cret" in str(a) for a in call["args"])
    assert (
        'header = "password: S3cret-Pass-Word"' in call["config"]
        and 'header = "username: admin"' in call["config"]
    )
    assert call["mode"] == 0o600
    assert not {"-k", "-sk", "--insecure"} & set(call["args"])  # vérification TLS stricte par défaut
    assert "-s" in call["args"] and "--http2" in call["args"]
    assert call["args"][-1] == "https://192.0.2.5:57400/gnsi.pathz.v1.Pathz/Get"


def test_the_curl_config_does_not_survive_the_call(curl):
    pz.get("192.0.2.5", "admin", "pw")
    assert not Path(curl.calls[0]["args"][curl.calls[0]["args"].index("-K") + 1]).exists()


def test_push_sends_both_messages_in_one_request(curl):
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    with pytest.raises(SystemExit, match="NON EFFECTIVE"):  # ce faux curl ne répond à aucune sonde
        pz.push("192.0.2.5", "admin", "pw", policy)
    body = curl.calls[0]["body"]
    frames, i = [], 0
    while i < len(body):
        n = int.from_bytes(body[i + 1 : i + 5], "big")
        frames.append(body[i + 5 : i + 5 + n])
        i += 5 + n
    assert len(frames) == 2 and [list(_fields(f))[0][0] for f in frames] == [1, 2]
    assert curl.calls[0]["args"][-1].endswith("/gnsi.pathz.v1.Pathz/Rotate")


@pytest.mark.parametrize("status", ["3", "6", "7", "?"])
def test_push_stops_on_any_grpc_status_but_zero(monkeypatch, status):
    monkeypatch.setattr(pz.subprocess, "run", _Curl(status=status))
    with pytest.raises(SystemExit, match="Pathz.Rotate"):
        pz.push("192.0.2.5", "admin", "pw", {"version": "v", "rules": []})


def test_probe_encodes_user_path_mode_and_the_active_policy_instance(curl):
    curl.frames = [b"\x08\x02"]
    assert (
        pz.probe("192.0.2.5", "admin", "pw", "netcheck-ro", "/interface[name=ethernet-1/1]", "read")
        == "PERMIT"
    )
    fields = dict(_fields(curl.calls[0]["body"][5:]))
    assert fields[1] == b"netcheck-ro" and fields[3] == 1 and fields[4] == 1  # mode read, instance ACTIVE
    assert _path(fields[2]) == "/interface[name=ethernet-1/1]"
    curl.frames = [b"\x08\x01"]
    assert pz.probe("192.0.2.5", "admin", "pw", "x", "/system", "write") == "DENY"
    assert dict(_fields(curl.calls[1]["body"][5:]))[3] == 2


def test_get_asks_for_the_active_policy(curl):
    pz.get("192.0.2.5", "admin", "pw")
    assert curl.calls[0]["body"][5:] == b"\x08\x01"


def test_the_password_file_must_be_0600_or_0400(tmp_path):
    f = tmp_path / "pw"
    f.write_text("secret\n", encoding="utf-8")
    for mode in (0o644, 0o640, 0o666, 0o604):
        f.chmod(mode)
        with pytest.raises(SystemExit, match="droits"):
            pz._password(str(f))
    for mode in (0o600, 0o400):
        f.chmod(mode)
        assert pz._password(str(f)) == "secret"


# --- image FRR : compte, doas, sshd ---------------------------------------------------------------


def _dockerfile() -> str:
    return (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")


def test_the_image_installs_doas_and_creates_a_key_only_account_outside_frrvty():
    text = _dockerfile()
    assert "apk add --no-cache openssh-server doas" in text
    assert "adduser -D -s /bin/sh netcheck-ro" in text
    assert "s/^netcheck-ro:!:/netcheck-ro:*:/" in text  # « * » : « ! » ferait refuser la clé par sshd
    # aucun mot de passe pour netcheck-ro (le chpasswd de netops, lui, existe)
    assert not any("chpasswd" in ln and "netcheck-ro" in ln for ln in text.splitlines())
    assert "addgroup netcheck-ro" not in text  # surtout pas frrvty
    assert "chown root:root /home/netcheck-ro/.ssh" in text  # la clé n'appartient pas à l'utilisateur


def test_the_image_copies_the_doas_rules_and_the_sshd_block_with_safe_permissions():
    text = _dockerfile()
    assert "COPY doas.conf /etc/doas.conf" in text and "chmod 640 /etc/doas.conf" in text
    assert "COPY sshd_netcheck_ro.conf /etc/ssh/sshd_config.d/10-netcheck-ro.conf" in text
    assert "authorized_keys" not in text and "BEGIN" not in text  # aucune clé dans l'image


def test_the_sshd_block_is_key_only_without_forwarding_agent_x11_or_tunnel():
    lines = [
        ln.strip()
        for ln in (ROOT / "docker" / "sshd_netcheck_ro.conf").read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert lines[0] == "Match User netcheck-ro"
    assert sorted(lines[1:]) == sorted(
        [
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AllowTcpForwarding no",
            "AllowAgentForwarding no",
            "X11Forwarding no",
            "PermitTunnel no",
            "PermitUserRC no",
            "PermitTTY yes",
        ]
    )


def test_every_top_level_word_of_the_real_eos_startup_config_is_a_known_root_keyword():
    # sans `role` dans ROOT_KEYWORDS, `check --config-dir configs-ceos` signalerait ce mot (information)
    driver = EosDriver()
    text = (ROOT / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
    words = {word for _, _, word in driver.parse_config(text).root_statements()}
    assert "role" in words and "aaa" in words
    assert words - driver.ROOT_KEYWORDS == set(), sorted(words - driver.ROOT_KEYWORDS)
