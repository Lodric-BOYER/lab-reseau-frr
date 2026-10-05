"""Phase C5, FRR : liste blanche EXACTE des commandes CLI réelles, option `privilege_wrapper: doas`.

Même modèle que pour EOS (test_drivers_eos.py) : seules ces dix chaînes complètes peuvent partir,
en clair (`vtysh -c '…'`) ou, pour le compte en lecture seule, par `doas -u frr /usr/bin/vtysh` (règles de
docker/doas.conf à arguments exacts). Un test statique garde l'unique fabrique de commande.
"""

import ast
import json
import shlex
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netcheck import collector, inventory
from netcheck.drivers import frr
from netcheck.drivers.frr import FrrDriver
from netcheck.usage import UsageError

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "dualstack" / "frr" / "r3.json"

LOGICAL = [
    ("show interface json", "show interface json"),
    ("show ip route json", "show ip route vrf all json"),
    ("show ipv6 route json", "show ipv6 route vrf all json"),
    ("show ip ospf neighbor json", "show ip ospf neighbor json"),
    ("show ipv6 ospf neighbor json", "show ipv6 ospf6 neighbor json"),
    ("show bgp ipv4 unicast summary json", "show bgp ipv4 unicast summary json"),
    ("show bgp ipv4 unicast json", "show bgp ipv4 unicast json"),
    ("show bgp ipv6 unicast summary json", "show bgp ipv6 unicast summary json"),
    ("show bgp ipv6 unicast json", "show bgp ipv6 unicast json"),
    ("show running-config", "show running-config"),
]
PLAIN = [f"vtysh -c '{vty}'" for _, vty in LOGICAL]
DOAS = [
    f"doas -u frr /usr/bin/vtysh{'' if vty == 'show running-config' else ' -u'} -c '{vty}'"
    for _, vty in LOGICAL
]


def test_the_ten_plain_commands_are_exactly_what_translate_gives():
    driver = FrrDriver()
    assert sorted(driver.translate(c) for c in driver.REQUIRED_COMMANDS) == sorted(PLAIN)
    assert driver.ALLOWED_CLI == frozenset(PLAIN) and len(PLAIN) == 10


def test_the_ten_doas_commands_are_exactly_what_translate_gives():
    driver = FrrDriver("doas")
    assert sorted(driver.translate(c) for c in driver.REQUIRED_COMMANDS) == sorted(DOAS)
    assert driver.ALLOWED_CLI == frozenset(DOAS) and len(DOAS) == 10


def test_the_view_mode_flag_covers_nine_commands_and_never_show_running_config():
    # `show running-config` n'existe pas en vue (« Unknown command » observé sur FRR 10.2.1) : sans -u, seul.
    with_u = [c for c in DOAS if "/usr/bin/vtysh -u -c " in c]
    assert len(with_u) == 9 and not any("running-config" in c for c in with_u)


@pytest.mark.parametrize("cli", PLAIN)
def test_plain_commands_are_accepted_by_a_plain_driver(cli):
    FrrDriver().check_cli(cli)


@pytest.mark.parametrize("cli", DOAS)
def test_doas_commands_are_accepted_by_a_doas_driver(cli):
    FrrDriver("doas").check_cli(cli)


@pytest.mark.parametrize("cli", DOAS)
def test_a_plain_driver_refuses_the_doas_forms(cli):
    with pytest.raises(PermissionError):
        FrrDriver().check_cli(cli)


@pytest.mark.parametrize("cli", PLAIN)
def test_a_doas_driver_refuses_the_plain_forms(cli):
    with pytest.raises(PermissionError):
        FrrDriver("doas").check_cli(cli)


def _variants(cli: str) -> list[tuple[str, str]]:
    return [
        ("point-virgule", f"{cli}; configure terminal"),
        ("et commercial", f"{cli} && reload"),
        ("pipe", f"{cli} | tee /tmp/x"),
        ("redirection", f"{cli} > /tmp/x"),
        ("ajout", f"{cli} >> /tmp/x"),
        ("espace final", f"{cli} "),
        ("espace initial", f" {cli}"),
        ("casse", cli.upper()),
        ("retour ligne", f"{cli}\nconfigure terminal"),
        ("retour chariot", f"{cli}\rreload"),
        ("substitution", f"{cli} $(reload)"),
        ("accent grave", f"{cli} `id`"),
        ("second -c", f"{cli} -c 'configure terminal'"),
        ("espace doublé", cli.replace(" -c ", " -c  ")),
        ("guillemets doubles", cli.replace("'", '"')),
    ]


@pytest.mark.parametrize(("label", "cli"), [(f"{b} :: {lab}", v) for b in PLAIN for lab, v in _variants(b)])
def test_every_variant_of_each_plain_command_is_refused(label, cli):
    with pytest.raises(PermissionError):
        FrrDriver().check_cli(cli)


@pytest.mark.parametrize(("label", "cli"), [(f"{b} :: {lab}", v) for b in DOAS for lab, v in _variants(b)])
def test_every_variant_of_each_doas_command_is_refused(label, cli):
    with pytest.raises(PermissionError):
        FrrDriver("doas").check_cli(cli)


@pytest.mark.parametrize("driver", [FrrDriver(), FrrDriver("doas")])
@pytest.mark.parametrize(
    "cli",
    [
        "vtysh -c 'configure terminal'",
        "vtysh -c 'write memory'",
        "vtysh -c 'show version'",
        "vtysh",
        "vtysh -c 'show running-config' -c 'configure terminal'",
        "doas -u root id",
        "doas id",
        "doas -s",
        "sh",
        "doas -u frr /usr/bin/vtysh -c 'configure terminal'",
        "doas -u frr /usr/bin/vtysh",
        "doas /usr/bin/vtysh -u -c 'show interface json'",
        "doas -u frr /bin/sh",
        "",
        "enable",
        "doas -u frr /usr/bin/vtysh -u -c 'show running-config'",  # -u refusé là où la vue n'existe pas
        "doas -u frr /usr/bin/vtysh -c 'show interface json'",  # sans -u là où il est exigé
    ],
)
def test_anything_but_the_exact_ten_is_refused(driver, cli):
    with pytest.raises(PermissionError):
        driver.check_cli(cli)


def test_an_unknown_wrapper_is_an_internal_error():
    with pytest.raises(ValueError, match="privilege_wrapper"):
        FrrDriver("sudo")


# --- for_router : l'option vient du routeur, jamais d'un état partagé ---------------------------------------


def test_for_router_returns_the_same_driver_without_the_option():
    driver = FrrDriver()
    assert driver.for_router({"name": "r1"}) is driver


def test_for_router_builds_a_doas_driver_without_touching_the_shared_one():
    shared = FrrDriver()
    configured = shared.for_router({"name": "r1", "privilege_wrapper": "doas"})
    assert configured is not shared and configured.wrapper == "doas" and shared.wrapper is None
    assert shared.translate("show interface json") == "vtysh -c 'show interface json'"
    assert configured.for_router({"name": "r1", "privilege_wrapper": "doas"}) is configured


def test_the_registry_driver_resolved_for_a_router_honours_the_option():
    driver = collector._resolve_driver({"name": "r1", "privilege_wrapper": "doas"}).for_router(
        {"name": "r1", "privilege_wrapper": "doas"}
    )
    assert driver.wrapper == "doas"


def test_non_frr_drivers_ignore_the_option_through_the_base_class():
    from netcheck.drivers.eos import EosDriver

    driver = EosDriver()
    assert driver.for_router({"name": "r4", "privilege_wrapper": "doas"}) is driver


# --- collecte : ce qui part réellement ------------------------------------------------------------------


def _connection(sent: list[str], refuse: str | None = None):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))["commands"]
    by_cli = {FrrDriver("doas").translate(c): raw[c] for c in FrrDriver.REQUIRED_COMMANDS}
    by_cli |= {FrrDriver().translate(c): raw[c] for c in FrrDriver.REQUIRED_COMMANDS}
    conn = MagicMock()

    def send(cli, **_kw):
        sent.append(cli)
        return refuse if refuse is not None else by_cli[cli]

    conn.send_command.side_effect = send
    return conn


def _router(**extra):
    return {
        "name": "r3",
        "host": "203.0.113.3",
        "driver": "frr",
        "device_type": "linux",
        "username": "netcheck-ro",
        "password": "x" * 12,
        **extra,
    }


def test_collect_sends_exactly_the_ten_doas_commands_when_the_option_is_set(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=_connection(sent)))
    state = collector.collect(_router(privilege_wrapper="doas"))
    assert sorted(sent) == sorted(DOAS) and state.driver == "frr"


def test_collect_sends_exactly_the_ten_plain_commands_without_the_option(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=_connection(sent)))
    collector.collect(_router())
    assert sorted(sent) == sorted(PLAIN)


def test_collect_with_an_explicit_plain_driver_still_applies_the_router_option(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=_connection(sent)))
    collector.collect(_router(privilege_wrapper="doas"), FrrDriver())
    assert sorted(sent) == sorted(DOAS)


def test_an_explicit_doas_driver_stays_doas_for_a_router_without_the_option(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=_connection(sent)))
    collector.collect(_router(), FrrDriver("doas"))
    assert sorted(sent) == sorted(DOAS)


def test_for_router_keeps_a_doas_driver_when_the_router_has_no_option():
    driver = FrrDriver("doas")
    assert driver.for_router({"name": "r1"}) is driver


class _InjectingDriver(FrrDriver):
    def __init__(self, evil):
        super().__init__()
        self._evil = evil

    def translate(self, command):
        return self._evil if command == "show ip ospf neighbor json" else super().translate(command)


@pytest.mark.parametrize(
    "evil", ["vtysh -c 'configure terminal'", "vtysh -c 'show ip ospf neighbor json'; reload"]
)
def test_collect_refuses_an_injected_command_before_connecting(monkeypatch, evil):
    connect = MagicMock(side_effect=AssertionError("ConnectHandler ne doit jamais être appelé"))
    monkeypatch.setattr(collector, "ConnectHandler", connect)
    with pytest.raises(PermissionError):
        collector.collect(_router(), _InjectingDriver(evil))
    connect.assert_not_called()


def test_a_doas_refusal_is_reported_clearly_not_parsed(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(
        collector,
        "ConnectHandler",
        MagicMock(return_value=_connection(sent, refuse="doas: Operation not permitted")),
    )
    with pytest.raises(RuntimeError, match="vtysh inutilisable"):
        collector.collect(_router(privilege_wrapper="doas"))


# --- inventaire ---------------------------------------------------------------------------------------------


def _inventory(tmp_path, extra: str, driver: str | None = "frr"):
    path = tmp_path / "inv.yml"
    driver_field = f", driver: {driver}" if driver else ""
    path.write_text(
        "defaults: {device_type: linux, username: u, password: pw-long-enough}\n"
        f"routers:\n  r1: {{host: 192.0.2.1{driver_field}{extra}}}\n",
        encoding="utf-8",
    )
    return path


def test_the_inventory_accepts_the_doas_option_for_frr(tmp_path):
    inv = inventory.load(path=_inventory(tmp_path, ", privilege_wrapper: doas"))
    assert inv.routers["r1"]["privilege_wrapper"] == "doas"


@pytest.mark.parametrize("value", ["sudo", "''", "true", "1"])
def test_the_inventory_refuses_any_other_wrapper(tmp_path, value):
    with pytest.raises(UsageError, match="privilege_wrapper"):
        inventory.load(path=_inventory(tmp_path, f", privilege_wrapper: {value}"))


def test_a_router_without_a_driver_field_is_frr_so_the_option_is_accepted(tmp_path):
    inv = inventory.load(path=_inventory(tmp_path, ", privilege_wrapper: doas", driver=None))
    assert "driver" not in inv.routers["r1"] and inv.routers["r1"]["privilege_wrapper"] == "doas"


@pytest.mark.parametrize("driver", ["srlinux", "eos"])
def test_the_inventory_refuses_the_option_for_other_drivers(tmp_path, driver):
    with pytest.raises(UsageError, match="driver frr"):
        inventory.load(path=_inventory(tmp_path, ", privilege_wrapper: doas", driver))


# --- docker/doas.conf : mêmes dix commandes que le driver --------------------------------------------


def _doas_rules() -> list[list[str]]:
    lines = (ROOT / "docker" / "doas.conf").read_text(encoding="utf-8").splitlines()
    return [shlex.split(line) for line in lines if line.strip() and not line.lstrip().startswith("#")]


def test_the_doas_rules_are_exactly_the_drivers_ten_commands():
    rules = _doas_rules()
    rebuilt = set()
    for tokens in rules:
        assert tokens[:6] == ["permit", "nopass", "netcheck-ro", "as", "frr", "cmd"], tokens
        assert tokens[6] == "/usr/bin/vtysh" and tokens[7] == "args"
        rebuilt.add("doas -u frr /usr/bin/vtysh " + shlex.join(tokens[8:]))
    assert len(rules) == 10 and rebuilt == set(DOAS)


def test_the_doas_rules_never_keep_the_environment_nor_run_as_root():
    text = (ROOT / "docker" / "doas.conf").read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in (
        "keepenv",
        "setenv",
        "as root",
        "persist",
        ":wheel",
        "permit nopass :",
        " cmd sh",
        "-s",
    ):
        assert forbidden not in body, forbidden
    assert "*" not in body


# --- test statique : une seule fabrique de commande ---------------------------------------------------


def test_only_the_cli_factory_builds_a_vtysh_command_line():
    tree = ast.parse(Path(frr.__file__).read_text(encoding="utf-8"))
    docstrings = {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and n.body
        and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
    }
    found: dict[str, str] = {}

    class Visitor(ast.NodeVisitor):
        stack: list[str] = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        def visit_Constant(self, node):
            where = self.stack[-1] if self.stack else "(module)"
            if isinstance(node.value, str) and id(node) not in docstrings and "vtysh" in node.value:
                if where not in ("_cli", "clean_output"):
                    found[node.value] = where

    Visitor().visit(tree)
    # hors de _cli, seule la constante _DOAS (niveau module) contient « vtysh » ; clean_output n'en cite
    # le nom que dans un message d'erreur
    assert found == {"doas -u frr /usr/bin/vtysh": "(module)"}, (
        f"commande vtysh construite hors de _cli : {found}"
    )
    assert frr._DOAS == "doas -u frr /usr/bin/vtysh"


def test_allowed_cli_is_derived_from_the_factory_not_written_by_hand():
    source = Path(frr.__file__).read_text(encoding="utf-8")
    assert "frozenset(_cli(c, None) for c in REQUIRED_COMMANDS)" in source
    assert "frozenset(_cli(c, wrapper) for c in self.REQUIRED_COMMANDS)" in source
