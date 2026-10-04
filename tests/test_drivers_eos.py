"""Tests du driver Arista EOS (Phase F) : normalisation, liste blanche EXACTE, enable().

Fixtures capturées sur le vrai lab cEOS (tests/fixtures/ceos/, image ceos:4.34.8M) par les six
commandes du driver, via une vraie session Netmiko `arista_eos` : un état nominal et quatre états
dégradés (OSPF tombé, BGP en Idle(MaxPath), BGP en Connect, interface coupée). Jamais inventées.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from netcheck import assertions, collector, diff, management
from netcheck.assertions import Status
from netcheck.drivers.eos import EosDriver
from netcheck.drivers.frr import FrrDriver
from netcheck.drivers.srlinux import SrlinuxDriver
from netcheck.model import DeviceState

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ceos"
RAW_FILES = {
    "show interface json": "interface.json",
    "show ip route json": "route.json",
    "show ip ospf neighbor json": "ospf_neighbor.json",
    "show bgp ipv4 unicast summary json": "bgp_summary.json",
    "show bgp ipv4 unicast json": "bgp_prefixes.json",
    "show running-config": "running_config.txt",
}
MGMT = {"eth0", "Management0"}
DUALSTACK = Path(__file__).resolve().parent / "fixtures" / "dualstack" / "ceos"


def read(scenario: str, filename: str) -> str:
    return (FIXTURES / scenario / filename).read_text(encoding="utf-8")


def state(scenario: str = "r4") -> DeviceState:
    raw = {command: read(scenario, filename) for command, filename in RAW_FILES.items()}
    s = EosDriver().parse(raw, "r4", "172.20.22.14")
    s.driver = "eos"
    return s


# ------------------------------------------------------------------------------------------
# Normalisation (état nominal)
# ------------------------------------------------------------------------------------------

def test_parse_interfaces_nominal():
    by_name = {i.name: i for i in EosDriver()._parse_interfaces(read("r4", "interface.json"))}
    assert set(by_name) == {"Ethernet1", "Ethernet2", "Management0", "Loopback0"}
    e2 = by_name["Ethernet2"]
    assert (e2.admin_up, e2.oper_up, e2.addresses, e2.description) == (
        True, True, ["10.2.45.1/30"], "vers-r5")
    assert by_name["Ethernet1"].addresses == ["172.16.34.2/30"]
    assert by_name["Loopback0"].addresses == ["10.2.255.4/32"]
    assert by_name["Management0"].addresses == ["172.20.22.14/24"]
    # EOS écrit "" pour « pas de description » : le modèle veut None (comme FRR).
    assert by_name["Management0"].description is None and by_name["Loopback0"].description is None


def test_is_loopback_comes_from_the_hardware_field_never_from_the_name():
    by_name = {i.name: i for i in EosDriver()._parse_interfaces(read("r4", "interface.json"))}
    assert by_name["Loopback0"].is_loopback is True
    assert by_name["Ethernet1"].is_loopback is False
    assert by_name["Management0"].is_loopback is False
    # Un nom trompeur ne change rien : seul `hardware` fait foi.
    fake = '{"interfaces": {"Loopback9": {"hardware": "ethernet", "interfaceStatus": "connected", ' \
           '"lineProtocolStatus": "up", "interfaceAddress": []}}}'
    assert EosDriver()._parse_interfaces(fake)[0].is_loopback is False
    # Champ absent -> inconnu (None), jamais deviné d'après le nom.
    unknown = '{"interfaces": {"Loopback9": {"interfaceStatus": "connected", "interfaceAddress": []}}}'
    assert EosDriver()._parse_interfaces(unknown)[0].is_loopback is None


def test_parse_routes_nominal_protocols_and_nexthops():
    by_prefix = {r.prefix: r for r in EosDriver()._parse_routes(read("r4", "route.json"))}
    assert set(by_prefix) == {
        "10.1.0.0/16", "10.2.0.0/16", "10.2.255.4/32", "10.2.255.5/32", "10.2.45.0/30",
        "172.16.34.0/30", "172.20.22.0/24", "192.168.1.0/24", "192.168.2.0/24"}
    assert by_prefix["192.168.2.0/24"].protocol == "ospf"
    assert by_prefix["192.168.2.0/24"].distance == 110 and by_prefix["192.168.2.0/24"].metric == 20
    assert [(n.ip, n.interface) for n in by_prefix["192.168.2.0/24"].nexthops] == [("10.2.45.2", "Ethernet2")]
    assert by_prefix["10.1.0.0/16"].protocol == "bgp" and by_prefix["10.1.0.0/16"].distance == 200
    assert [(n.ip, n.interface) for n in by_prefix["10.1.0.0/16"].nexthops] == [("172.16.34.1", "Ethernet1")]
    connected = by_prefix["10.2.45.0/30"]
    assert connected.protocol == "connected"
    assert [(n.ip, n.interface, n.directly_connected) for n in connected.nexthops] == [
        (None, "Ethernet2", True)]
    assert all(r.selected for r in by_prefix.values())


def test_null0_route_is_a_blackhole_signature_like_frr():
    # EOS : routeType dropRoute, routeAction drop, vias [] -- mais directlyConnected: true, trompeur.
    route = {r.prefix: r for r in EosDriver()._parse_routes(read("r4", "route.json"))}["10.2.0.0/16"]
    assert route.protocol == "static"
    assert len(route.nexthops) == 1
    nh = route.nexthops[0]
    assert (nh.ip, nh.interface, nh.directly_connected) == (None, None, False)
    assert assertions._is_blackhole(route) is True


def test_parse_ospf_neighbors_nominal():
    neighbors = EosDriver()._parse_ospf(read("r4", "ospf_neighbor.json"))
    assert len(neighbors) == 1
    n = neighbors[0]
    assert (n.router_id, n.interface, n.state) == ("10.2.255.5", "Ethernet2", "Full/-")
    assert n.is_full is True


def test_parse_bgp_summary_nominal_asn_is_an_int():
    peers = EosDriver()._parse_bgp_summary(read("r4", "bgp_summary.json"))
    assert len(peers) == 1
    p = peers[0]
    assert (p.neighbor, p.remote_as, p.state, p.pfx_received, p.pfx_sent) == (
        "172.16.34.1", 65001, "Established", 2, 2)
    assert isinstance(p.remote_as, int)


def test_parse_bgp_prefixes_nominal():
    prefixes = {p.prefix: p for p in EosDriver()._parse_bgp_prefixes(read("r4", "bgp_prefixes.json"))}
    assert set(prefixes) == {"10.1.0.0/16", "10.2.0.0/16", "192.168.1.0/24", "192.168.2.0/24"}
    learned = prefixes["10.1.0.0/16"]
    assert (learned.as_path, learned.next_hop, learned.best) == ("65001", "172.16.34.1", True)
    # Origine locale : code d'origine ("i" ou "?") retiré, chaîne vide comme FRR.
    assert prefixes["192.168.2.0/24"].as_path == ""
    assert prefixes["10.2.0.0/16"].as_path == ""


def test_running_config_is_kept_verbatim():
    s = state()
    assert s.running_config == read("r4", "running_config.txt")
    assert "router bgp 65002" in s.running_config and s.driver == "eos" and s.reachable is True


def test_parse_handles_protocols_that_are_not_configured():
    empty = '{"vrfs": {}}'
    assert EosDriver()._parse_bgp_summary(empty) == []
    assert EosDriver()._parse_bgp_prefixes(empty) == []
    assert EosDriver()._parse_ospf(empty) == []
    assert EosDriver()._parse_routes(empty) == []


def test_everything_is_read_from_the_default_vrf_only():
    other = ('{"vrfs": {"MGMT": {"peers": {"10.9.9.9": {"asn": "65009", "peerState": "Established"}}}, '
             '"default": {"peers": {"10.0.0.1": {"asn": "65001", "peerState": "Established"}}}}}')
    assert [p.neighbor for p in EosDriver()._parse_bgp_summary(other)] == ["10.0.0.1"]


# ------------------------------------------------------------------------------------------
# États dégradés réels
# ------------------------------------------------------------------------------------------

def test_degraded_ospf_down_has_no_neighbor_but_keeps_bgp():
    s = state("degraded_ospf_down")
    assert s.ospf_neighbors == []
    assert [p.state for p in s.bgp_peers] == ["Established"]
    assert "10.2.255.5/32" not in {r.prefix for r in s.routes}


def test_degraded_bgp_maxpath_state_is_idle_maxpath():
    peers = state("degraded_bgp_maxpath").bgp_peers
    assert [(p.neighbor, p.state, p.pfx_received) for p in peers] == [("172.16.34.1", "Idle(MaxPath)", 0)]
    assert len(state("degraded_bgp_maxpath").ospf_neighbors) == 1   # OSPF intact


def test_degraded_bgp_connect_state():
    peers = state("degraded_bgp_connect").bgp_peers
    assert [(p.state, p.pfx_received) for p in peers] == [("Connect", 0)]


def test_degraded_interface_shutdown_is_admin_down_and_oper_down():
    by_name = {i.name: i for i in state("degraded_interface_shutdown").interfaces}
    e2 = by_name["Ethernet2"]
    assert (e2.admin_up, e2.oper_up) == (False, False)
    assert by_name["Ethernet1"].admin_up is True and by_name["Ethernet1"].oper_up is True


def test_diff_nominal_vs_nominal_is_empty():
    assert diff.compare({"r4": state()}, {"r4": state()}, management_interfaces=MGMT) == []


def test_diff_detects_ospf_loss_maxpath_connect_and_interface_down():
    nominal = {"r4": state()}

    ospf = diff.compare(nominal, {"r4": state("degraded_ospf_down")}, management_interfaces=MGMT)
    assert any(f.category == "ospf_neighbor" and "10.2.255.5" in f.message
               and f.severity == diff.Severity.CRITIQUE for f in ospf)
    assert diff.verdict(ospf) == ("ÉCHEC", 2)

    for scenario, wanted in (("degraded_bgp_maxpath", "Idle(MaxPath)"), ("degraded_bgp_connect", "Connect")):
        findings = diff.compare(nominal, {"r4": state(scenario)}, management_interfaces=MGMT)
        bgp = [f for f in findings if f.category == "bgp_session"]
        assert bgp and wanted in bgp[0].message and bgp[0].severity == diff.Severity.CRITIQUE

    down = diff.compare(nominal, {"r4": state("degraded_interface_shutdown")}, management_interfaces=MGMT)
    assert any(f.category == "interface" and "Ethernet2" in f.message for f in down)


# ------------------------------------------------------------------------------------------
# Secrets : le hash « type 7 » d'EOS ne doit apparaître dans AUCUN rapport
# ------------------------------------------------------------------------------------------

def test_a_real_config_diff_never_shows_a_type7_hash_in_any_report_format():
    import io
    import json
    import re

    from rich.console import Console

    from netcheck import monitor, report
    before, after = state("r4"), state("degraded_ospf_down")   # clé OSPF correcte puis erronée (réelles)
    hashes = {h for s in (before, after) for h in re.findall(r"md5 7 (\S+)", s.running_config)}
    hashes |= set(re.findall(r"password 7 (\S+)", before.running_config))
    hashes |= {"BfyQeqMEAOYfFIFW", "2TgamS6RUy"}   # morceaux du hash sha512 de l'utilisateur admin
    assert len(hashes) >= 4

    findings = diff.compare({"r4": before}, {"r4": after}, management_interfaces=MGMT)
    config = [f for f in findings if f.category == "config"]
    assert config, "le diff de configuration doit exister pour que ce test soit probant"
    assert any(h in config[0].message for h in hashes), "le constat BRUT contient bien un hash"

    terminal = io.StringIO()
    report.print_terminal(findings, "ÉCHEC", console=Console(file=terminal, width=240))
    outputs = {
        "terminal": terminal.getvalue(),
        "json": json.dumps(report.to_dict(findings, "ÉCHEC"), ensure_ascii=False),
        "html": report.render_html(findings, "ÉCHEC", "avant", "après"),
        "alerte": monitor._clean(config[0].message),
    }
    for fmt, text in outputs.items():
        leaked = [h for h in hashes if h in text]
        assert not leaked, f"FUITE dans le format {fmt} : {leaked}"
    assert "md5 ****" in outputs["json"]


# ------------------------------------------------------------------------------------------
# Management0 filtré comme eth0 côté FRR
# ------------------------------------------------------------------------------------------

def test_management0_and_its_subnet_are_filtered_like_eth0_on_frr():
    filtered = management.filtered(state(), MGMT)
    assert "Management0" not in {i.name for i in filtered.interfaces}
    assert "172.20.22.0/24" not in {r.prefix for r in filtered.routes}
    assert {"Ethernet1", "Ethernet2", "Loopback0"} <= {i.name for i in filtered.interfaces}
    assert "192.168.2.0/24" in {r.prefix for r in filtered.routes}


# ------------------------------------------------------------------------------------------
# assert : mêmes évaluateurs que pour FRR et SR Linux, y compris le trou noir (Phase C)
# ------------------------------------------------------------------------------------------

def _evaluate(assertion_dict, scenario="r4"):
    (assertion,) = assertions.validate_assertions([assertion_dict], Path("x"))
    return assertions.evaluate([assertion], {"r4": state(scenario)}, management_interfaces=MGMT)[0]


def test_assertions_work_on_eos_data():
    assert _evaluate({"id": "a", "description": "d", "device": "r4", "type": "ospf_neighbors",
                      "count": 1}).status == Status.OK
    assert _evaluate({"id": "b", "description": "d", "device": "r4", "type": "bgp_session",
                      "neighbor": "172.16.34.1"}).status == Status.OK
    assert _evaluate({"id": "c", "description": "d", "device": "r4", "type": "interface_up",
                      "interface": "Ethernet2"}).status == Status.OK
    assert _evaluate({"id": "d", "description": "d", "device": "r4", "type": "route_present",
                      "prefix": "192.168.2.0/24", "protocol": "ospf"}).status == Status.OK
    assert _evaluate({"id": "e", "description": "d", "device": "r4", "type": "route_present",
                      "prefix": "10.1.0.0/16", "protocol": "bgp"}).status == Status.OK


def test_assertions_fail_on_the_real_degraded_states():
    assert _evaluate({"id": "a", "description": "d", "device": "r4", "type": "ospf_neighbors", "count": 1},
                     "degraded_ospf_down").status == Status.ECHEC
    assert _evaluate({"id": "b", "description": "d", "device": "r4", "type": "bgp_session",
                      "neighbor": "172.16.34.1"}, "degraded_bgp_maxpath").status == Status.ECHEC
    assert _evaluate({"id": "c", "description": "d", "device": "r4", "type": "interface_up",
                      "interface": "Ethernet2"}, "degraded_interface_shutdown").status == Status.ECHEC


def test_path_through_a_drop_route_is_a_blackhole_echec():
    # 10.2.99.0/24 n'est couvert que par l'agrégat 10.2.0.0/16, route de rejet (dropRoute) :
    # même sémantique que la Phase C -- un trou noir est un ÉCHEC, jamais NON ÉVALUABLE.
    result = _evaluate({"id": "p", "description": "d", "device": "r4", "type": "path",
                        "prefix": "10.2.99.0/24", "via": []})
    assert result.status == Status.ECHEC
    assert "trou noir" in result.detail and "10.2.0.0/16" in result.detail


def test_path_to_a_covered_prefix_is_not_a_blackhole():
    # 192.168.2.0/24 est appris par OSPF, plus spécifique que l'agrégat : pas de trou noir.
    result = _evaluate({"id": "p", "description": "d", "device": "r4", "type": "path",
                        "prefix": "192.168.2.0/24", "via": []})
    assert "trou noir" not in result.detail


# ------------------------------------------------------------------------------------------
# Liste blanche EXACTE de la commande CLI complète, `| json` compris
# ------------------------------------------------------------------------------------------

# Phase B2 : douze chaînes complètes (les six d'origine, dont les routes IPv4 élargies à toutes les VRF,
# et six de plus
# validées une par une avec leur sortie réelle : tests/fixtures/dualstack/ceos/).
ALLOWED = [
    "show interfaces | json", "show ipv6 interface | json", "show vrf | json",
    "show ip route vrf all | json", "show ipv6 route vrf all | json",
    "show ip ospf neighbor | json", "show ospfv3 neighbor | json",
    "show ip bgp summary | json", "show ip bgp | json",
    "show ipv6 bgp summary | json", "show ipv6 bgp | json",
    "show running-config",
]
# Les anciennes chaînes que le driver n'envoie plus : refusées, car la liste exacte ne garde que ce qui part.
RETIRED = ["show ip route | json"]


def test_translate_gives_exactly_the_twelve_whitelisted_commands():
    driver = EosDriver()
    assert sorted(driver.translate(c) for c in driver.REQUIRED_COMMANDS) == sorted(ALLOWED)
    assert driver.ALLOWED_CLI == frozenset(ALLOWED)
    assert len(ALLOWED) == 12


@pytest.mark.parametrize("cli", ALLOWED)
def test_the_twelve_commands_are_accepted(cli):
    EosDriver().check_cli(cli)   # ne lève rien


def _variants(cli: str) -> list[tuple[str, str]]:
    """Les variantes que la v3 refusait pour chaque chaîne, appliquées à CHACUNE des douze (phase B2)."""
    out = [
        ("redirection", f"{cli} > /tmp/sortie"), ("ajout", f"{cli} >> /tmp/sortie"),
        ("tee", f"{cli} | tee /tmp/sortie"), ("second pipe", f"{cli} | grep x"),
        ("espace final", f"{cli} "), ("espace initial", f" {cli}"), ("casse", cli.upper()),
        ("point-virgule", f"{cli}; configure terminal"), ("retour ligne", f"{cli}\nconfigure terminal"),
        ("retour chariot", f"{cli}\rconfigure terminal"), ("esperluette", f"{cli} & reload"),
        ("substitution", f"{cli} $(reload)"),
    ]
    if " | " in cli:
        out += [("sans espaces autour du pipe", cli.replace(" | ", "|")),
                ("double espace", cli.replace(" | ", " |  ")),
                ("tee sans espace", cli.replace(" | ", "|tee /x|"))]
    if "vrf all" in cli:
        out += [("sans vrf all", cli.replace(" vrf all", "")),
                ("une seule VRF", cli.replace("vrf all", "vrf DEMO"))]
    return out


@pytest.mark.parametrize(("label", "cli"), [(f"{base} :: {label}", v) for base in ALLOWED
                                            for label, v in _variants(base)])
def test_every_variant_of_each_new_command_is_refused(label, cli):
    with pytest.raises(PermissionError):
        EosDriver().check_cli(cli)


@pytest.mark.parametrize("cli", RETIRED)
def test_a_retired_command_is_refused(cli):
    with pytest.raises(PermissionError):
        EosDriver().check_cli(cli)


@pytest.mark.parametrize(("label", "cli"), [
    ("redirection", "show ip route | json > /tmp/sortie"),
    ("redirection vers flash", "show ip route | json > flash:route.txt"),
    ("ajout (append)", "show ip route | json >> /tmp/sortie"),
    ("tee", "show ip route | json | tee /tmp/sortie"),
    ("tee sans espace", "show ip route | json |tee /tmp/sortie"),
    ("second pipe", "show ip route | json | grep 10."),
    ("second pipe include", "show ip bgp summary | json | include Established"),
    ("pipe sur la running-config", "show running-config | json"),
    ("pipe section", "show running-config | section bgp"),
    ("sans espaces autour du pipe", "show ip route|json"),
    ("espace final", "show ip route | json "),
    ("espace initial", " show ip route | json"),
    ("double espace", "show ip route |  json"),
    ("casse", "SHOW IP ROUTE | JSON"),
    ("point-virgule", "show ip route | json; configure terminal"),
    ("retour ligne", "show ip route | json\nconfigure terminal"),
    ("retour chariot", "show ip route | json\rconfigure terminal"),
    ("esperluette", "show ip route | json & configure terminal"),
    ("substitution", "show ip route | json $(reload)"),
    ("commande de configuration", "configure terminal"),
    ("écriture", "write memory"),
    ("copie", "copy running-config flash:backup"),
    ("rechargement", "reload"),
    ("enable via send_command", "enable"),
    ("show non listé", "show version | json"),
    ("show ip route avec filtre", "show ip route 10.0.0.0/8 | json"),
    ("vide", ""),
])
def test_anything_but_the_exact_twelve_commands_is_refused(label, cli):
    with pytest.raises(PermissionError):
        EosDriver().check_cli(cli)


def test_unknown_logical_command_cannot_be_translated():
    with pytest.raises(PermissionError, match="inconnue"):
        EosDriver().translate("configure terminal")


class _InjectingDriver(EosDriver):
    """Driver qui tente de faire partir une commande piégée à la place de la 2e commande."""
    def __init__(self, evil):
        self._evil = evil

    def translate(self, command):
        return self._evil if command == "show ip route json" else super().translate(command)


@pytest.mark.parametrize("evil", [
    "show ip route | json > /tmp/x", "show ip route | json >> /tmp/x",
    "show ip route | json | tee /tmp/x", "show ip route | json | grep x",
])
def test_collect_refuses_an_injected_command_before_connecting(monkeypatch, evil):
    connect = MagicMock(side_effect=AssertionError("ConnectHandler ne doit jamais être appelé"))
    monkeypatch.setattr(collector, "ConnectHandler", connect)
    router = {"device_type": "arista_eos", "host": "203.0.113.9", "username": "u", "password": "p",
              "name": "r4", "driver": "eos"}
    with pytest.raises(PermissionError):
        collector.collect(router, _InjectingDriver(evil))
    connect.assert_not_called()


def test_the_logical_whitelist_of_the_collector_is_unchanged_by_the_eos_driver():
    assert set(EosDriver().REQUIRED_COMMANDS) <= collector.ALLOWED_COMMANDS
    # Phase B2 : six noms logiques de plus (IPv6, VRF), les neuf d'avant inchangés.
    assert collector.ALLOWED_COMMANDS == {
        "show interface json", "show ip route json", "show ip ospf neighbor json",
        "show bgp ipv4 unicast summary json", "show bgp ipv4 unicast json", "show running-config",
        "show ospf running-config", "show system authentication", "show system banner",
        "show ipv6 interface json", "show vrf json", "show ipv6 route json", "show ipv6 ospf neighbor json",
        "show bgp ipv6 unicast summary json", "show bgp ipv6 unicast json",
    }


# ------------------------------------------------------------------------------------------
# enable() : la méthode Netmiko, avant toute commande, jamais via send_command
# ------------------------------------------------------------------------------------------

def _fake_connection():
    """Fausse session Netmiko qui répond, pour chaque commande EOS réelle, par la sortie réelle
    capturée sur le lab (tests/fixtures/ceos/r4/)."""
    conn = MagicMock()
    raw = json.loads((DUALSTACK / "r4.json").read_text(encoding="utf-8"))["commands"]
    by_cli = {EosDriver().translate(c): raw[c] for c in EosDriver.REQUIRED_COMMANDS}
    conn.send_command.side_effect = lambda cli, **_kw: by_cli[cli]
    return conn


def test_collect_calls_netmiko_enable_before_any_command_and_never_sends_it(monkeypatch):
    conn = _fake_connection()
    monkeypatch.setattr(collector, "ConnectHandler", MagicMock(return_value=conn))
    router = {"device_type": "arista_eos", "host": "172.20.22.14", "username": "admin",
              "password": "admin", "name": "r4", "driver": "eos"}
    result = collector.collect(router)

    assert result.driver == "eos" and len(result.bgp_peers) == 2   # IPv4 + IPv6 (phase B2)
    conn.enable.assert_called_once_with()
    names = [c[0] for c in conn.method_calls]
    assert names.index("enable") < names.index("send_command"), "enable() doit précéder toute commande"
    sent = [c.args[0] for c in conn.send_command.call_args_list]
    assert sorted(sent) == sorted(ALLOWED)
    assert not [s for s in sent if s.split()[0] == "enable"], "jamais enable via send_command"
    assert call.disconnect() in conn.method_calls


@pytest.mark.parametrize("driver_cls", [FrrDriver, SrlinuxDriver])
def test_frr_and_srlinux_never_call_enable(driver_cls):
    assert driver_cls.NEEDS_ENABLE is False
    assert driver_cls.ALLOWED_CLI is None   # comportement historique inchangé


def test_privileged_mode_refusal_is_reported_clearly():
    with pytest.raises(RuntimeError, match="refusé"):
        EosDriver().clean_output("% Invalid input (privileged mode required)")
    assert EosDriver().clean_output('{"vrfs": {}}') == '{"vrfs": {}}'


# ------------------------------------------------------------------------------------------
# Registre et inventaire
# ------------------------------------------------------------------------------------------

def test_eos_is_registered_and_resolved_from_the_inventory_field():
    assert collector.DRIVER_REGISTRY["eos"] is EosDriver
    assert isinstance(collector._resolve_driver({"name": "r4", "driver": "eos"}), EosDriver)


def test_inventory_ceos_declares_the_eos_driver_and_both_management_interfaces(monkeypatch):
    from netcheck import inventory
    for var in ("NETCHECK_USER", "NETCHECK_PASS", "LAB_USER", "LAB_PASS", "NETCHECK_EOS_USER",
                "NETCHECK_EOS_PASS"):
        monkeypatch.delenv(var, raising=False)
    inv = inventory.load(path=Path(__file__).resolve().parent.parent / "automation" / "inventory-ceos.yml")
    assert set(inv.routers) == {"r1", "r2", "r3", "r4", "r5"}
    r4 = inv.routers["r4"]
    assert (r4["driver"], r4["device_type"], r4["host"]) == ("eos", "arista_eos", "172.20.22.14")
    assert all(inv.routers[r].get("driver", "frr") == "frr" for r in ("r1", "r2", "r3", "r5"))
    assert set(inv.management_interfaces) == {"eth0", "Management0"}


def test_eos_credentials_are_overridable_per_driver_without_touching_frr(monkeypatch):
    from netcheck import inventory
    monkeypatch.setenv("NETCHECK_EOS_USER", "autre")
    monkeypatch.setenv("NETCHECK_EOS_PASS", "autre-mdp")
    inv = inventory.load(path=Path(__file__).resolve().parent.parent / "automation" / "inventory-ceos.yml")
    assert inv.routers["r4"]["username"] == "autre" and inv.routers["r4"]["password"] == "autre-mdp"
    assert inv.routers["r1"]["username"] != "autre"
