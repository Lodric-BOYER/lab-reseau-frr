"""Phase B4 : FRR, IPv4 : seuls les `permit` d'une prefix-list autorisent un préfixe, comme déjà en IPv6
(B3). La v0.3.0 comptait aussi les `deny` IPv4 : `deny 0.0.0.0/0` (le bon filtre) était signalé comme une
autorisation. Configurations réelles des labs (tests/fixtures/live_dualstack/) ; chaque test dit ce qu'il
modifie.
"""
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.model import DeviceState

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RULES = compliance.load_rule_files([ROOT / "netcheck/rules/security.yml"])
NODEF = "ebgp-pas-de-route-par-defaut"
NOOWN = "ebgp-pas-de-reinjection-de-prefixes-locaux"

DEFAULT_V4 = "autorise 0.0.0.0/0 : route par défaut acceptable depuis l'extérieur"
DEFAULT_V6 = "autorise ::/0 : route par défaut acceptable depuis l'extérieur"
REINJECTION = "que ce routeur annonce déjà lui-même : risque de réinjection"


def read(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


def run(driver: str, text: str, rule: str | None = None, device: str = "r4"):
    state = DeviceState(name=device, host="-", timestamp="", reachable=True, driver=driver,
                        running_config=text)
    result = compliance.evaluate_config(RULES, {device: state}, {"eth0", "Management0"}, offline=True)
    return [v for v in result.violations if rule is None or v.rule.id == rule]


def once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


def subjects(found) -> list[str]:
    return [v.subject for v in found]


# ------------------------------------------------------------------------------------------
# 1. FRR, IPv4 : seuls les `permit` comptent
# ------------------------------------------------------------------------------------------

FRR_R3 = read("live_dualstack", "frr_r3.txt")
FRR_IN = "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n"


def frr_in(entry: str) -> str:
    return once(FRR_R3, FRR_IN, FRR_IN + f"ip prefix-list PL-EBGP-IN seq 30 {entry}\n")


@pytest.mark.parametrize("entry", ["deny 0.0.0.0/0", "deny 0.0.0.0/0 le 32", "deny 0.0.0.0/0 ge 1 le 7"])
def test_frr_a_deny_of_the_ipv4_default_route_is_not_an_authorisation(entry):
    # La v0.3.0 signalait ces trois lignes, qui sont précisément le bon filtre.
    assert run("frr", frr_in(entry), NODEF, "r3") == []


@pytest.mark.parametrize("entry", ["deny 10.1.0.0/16", "deny 192.168.1.0/24 le 32"])
def test_frr_a_deny_of_our_own_ipv4_prefix_is_not_a_reinjection(entry):
    assert run("frr", frr_in(entry), NOOWN, "r3") == []


def test_frr_a_permit_is_still_reported_next_to_a_deny():
    text = once(FRR_R3, FRR_IN, FRR_IN + "ip prefix-list PL-EBGP-IN seq 5 deny 0.0.0.0/0 le 32\n"
                "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n"
                "ip prefix-list PL-EBGP-IN seq 40 permit 10.1.0.0/16\n")
    found = run("frr", text, NODEF, "r3")
    assert [(v.subject, v.detail.endswith(DEFAULT_V4)) for v in found] == [("172.16.34.2", True)]
    assert subjects(run("frr", text, NOOWN, "r3")) == ["172.16.34.2"]


def test_frr_the_ipv4_permit_variants_are_still_reported():
    for entry in ("permit 0.0.0.0/0", "permit 0.0.0.0/0 le 32"):
        assert subjects(run("frr", frr_in(entry), NODEF, "r3")) == ["172.16.34.2"], entry
    assert subjects(run("frr", frr_in("permit 10.1.0.0/16"), NOOWN, "r3")) == ["172.16.34.2"]


def test_frr_a_prefix_list_entry_with_a_malformed_seq_is_not_read():
    # FRR refuse une telle ligne : elle ne peut pas figurer dans une vraie configuration.
    assert run("frr", frr_in("permit 0.0.0.0/0").replace("seq 30", "seq abc"), NODEF, "r3") == []
