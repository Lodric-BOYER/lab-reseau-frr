"""Règles de configuration EOS dans le driver (SPEC_v4, Phase A3c).

Les comportements d'EOS sur lesquels reposent ces tests ont été vérifiés sur cEOS 4.34.8M en chargeant
de VRAIS fichiers dans une session de configuration abandonnée (`configure session`, `copy file: ...
session-config`, `show session-config diffs`, `abort`) :
  - l'indentation est ignorée : `neighbor X remote-as N` en colonne 0 s'applique à `router bgp` ;
  - un `!` en colonne 0 est un commentaire : il ne ferme aucun bloc ;
  - la même ligne après `exit` est rejetée (« Invalid input ») ;
  - une bannière (`banner login` ou `banner motd`) est du texte libre jusqu'à `EOF`, conservé tel quel.
"""
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import Rule

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "ceos"
STARTUP = (REPO / "tests" / "golden" / "inputs" / "eos_r4.startup-config").read_text(encoding="utf-8")
KINDS = ("eos_ospf_authentication_required", "eos_bgp_neighbor_password_required",
         "eos_bgp_neighbor_ttl_security_required", "eos_bgp_neighbor_maximum_routes_required",
         "eos_management_api_disabled")


def rule(kind: str) -> Rule:
    return Rule(id=kind, description="d", severity="haute", applies_to="all", kind=kind)


def device(text: str) -> DeviceState:
    return DeviceState(name="r4", host="-", timestamp="", reachable=True, running_config=text, driver="eos")


def details(text: str, kind: str) -> list[str]:
    return [v.detail for v in compliance.check_one(rule(kind), device(text))]


def parse(text: str):
    return DRIVER_REGISTRY["eos"]().parse_config(text)


def audit(text: str):
    rules = [rule(k) for k in KINDS]
    return compliance.evaluate_config(rules, {"r4": device(text)})


# ------------------------------------------------------------------------------------------
# Lecture des vrais fichiers
# ------------------------------------------------------------------------------------------

REAL = [*sorted(FIXTURES.glob("*/running_config.txt")),
        REPO / "tests" / "golden" / "inputs" / "eos_r4.startup-config"]


@pytest.mark.parametrize("path", REAL, ids=lambda p: p.parent.name if p.suffix == ".txt" else p.name)
def test_real_eos_configurations_give_no_warning(path):
    """Les sorties relevées en direct sont toujours indentées, avec des bannières absentes ou en `EOF` :
    aucune ligne n'est signalée (vérifié aussi sur le r4 relevé en direct du lab cEOS, Phase A3)."""
    cfg = parse(path.read_text(encoding="utf-8"))
    assert cfg.warnings == []
    assert sum(cfg.counts.values()) == cfg.lines_total


def test_the_eos_blocks_are_split_by_indentation_and_a_comment_never_changes_them():
    text = ("hostname r4\n!\ninterface Ethernet1\n   description a\n   no switchport\n!\n"
            "interface Ethernet2\n   mtu 1500\n")
    cfg = parse(text)
    names = [" ".join(n.words[1:]) for n in cfg.top("interface", "*")]
    assert names == ["Ethernet1", "Ethernet2"]
    ethernet1, ethernet2 = cfg.top("interface", "*")
    assert [c.text for c in ethernet1.children] == ["description a", "no switchport"]
    assert [c.text for c in ethernet2.children] == ["mtu 1500"]


# ------------------------------------------------------------------------------------------
# Le `!` en colonne 0 ne ferme aucun bloc (vérifié sur cEOS)
# ------------------------------------------------------------------------------------------

BGP_NO_PASSWORD = ("router bgp 65002\n   neighbor 172.16.34.1 remote-as 65001\n"
                   "   neighbor 172.16.34.1 ttl maximum-hops 1\n   neighbor 172.16.34.1 maximum-routes 10\n")


def test_a_bang_in_column_zero_does_not_end_the_block_so_following_lines_are_still_read():
    """v0.3.0 terminait le bloc au premier `!` : les lignes indentées qui suivent étaient perdues, et un
    voisin sans mot de passe n'était plus vu. EOS, lui, les applique à `router bgp`."""
    with_bang = BGP_NO_PASSWORD.replace("router bgp 65002\n", "router bgp 65002\n!\n")
    assert len(details(with_bang, "eos_bgp_neighbor_password_required")) == 1


# ------------------------------------------------------------------------------------------
# EOS ignore l'indentation : une sous-commande au premier niveau est une ligne NON conservée
# ------------------------------------------------------------------------------------------

def test_an_unindented_router_bgp_subcommand_is_flagged_not_silently_ignored():
    config = BGP_NO_PASSWORD.replace("   neighbor 172.16.34.1 maximum-routes 10\n",
                                     "neighbor 172.16.34.1 maximum-routes 10\n")
    result = audit(config)
    assert [(w.warning.line, w.kept) for w in result.config_warnings] == [(4, False)]
    assert "sous-commande de « router bgp » au premier niveau" in result.config_warnings[0].warning.reason
    # La ligne n'est pas lue : l'audit ne peut pas dire « conforme », même sans autre violation prouvée.
    assert compliance.verdict(result.violations, result.config_warnings)[1] >= 1


def test_an_unindented_interface_subcommand_is_flagged():
    config = ("interface Ethernet2\n   ip address 10.2.45.1/30\n   ip ospf area 0.0.0.0\n"
              "ip ospf authentication message-digest\n!\nrouter ospf 1\n   router-id 1.1.1.1\n")
    result = audit(config)
    assert [w.warning.line for w in result.unread_lines] == [4]
    assert compliance.status_label(result.violations, result.config_warnings) in {"ANALYSE INCOMPLÈTE",
                                                                                   "NON CONFORME"}


def test_real_root_commands_are_never_flagged():
    cfg = parse("no aaa root\nusername admin privilege 15 role network-admin secret sha512 x\nhostname r4\n"
                "ip routing\nip route 10.2.0.0/16 Null0\nip prefix-list P seq 10 permit 10.0.0.0/8\n"
                "route-map RM permit 10\n   match ip address prefix-list P\n!\nend\n")
    assert cfg.warnings == []


# ------------------------------------------------------------------------------------------
# Bannières : du texte libre jusqu'à EOF (vérifié sur cEOS, `login` et `motd`)
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["login", "motd"])
def test_banner_text_is_free_text_not_configuration(kind):
    """v0.3.0 lisait une ligne de bannière qui ressemble à de la configuration comme de la
    configuration (ici, une fausse interface Ethernet9 sans authentification)."""
    config = (f"banner {kind}\ninterface Ethernet9\n   ip ospf area 0\nEOF\n"
              "interface Ethernet2\n   ip ospf area 0.0.0.0\n   ip ospf authentication message-digest\n"
              "   ip ospf message-digest-key 1 md5 7 abc\n")
    assert details(config, "eos_ospf_authentication_required") == []
    cfg = parse(config)
    assert cfg.warnings == []
    assert [" ".join(n.words[1:]) for n in cfg.top("interface", "*")] == ["Ethernet2"]


# ------------------------------------------------------------------------------------------
# Espaces multiples
# ------------------------------------------------------------------------------------------

def test_extra_spaces_are_not_a_missing_limit():
    config = BGP_NO_PASSWORD.replace("   neighbor 172.16.34.1 maximum-routes 10",
                                     "   neighbor  172.16.34.1  maximum-routes  10")
    assert details(config, "eos_bgp_neighbor_maximum_routes_required") == []     # v0.3.0 : « sans limite »


# ------------------------------------------------------------------------------------------
# Le jeu complet sur la configuration réelle durcie
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", KINDS)
def test_the_hardened_real_config_is_compliant(kind):
    assert details(STARTUP, kind) == []


def test_every_eos_kind_is_implemented_only_by_the_eos_driver():
    for kind in KINDS:
        assert compliance.implementers(kind) == ["eos"]
