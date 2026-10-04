"""Phase B3 : les trois silences IPv6 des règles sont fermés, avec des mutations de VRAIES configurations.

Avant B3, les règles étaient silencieuses sur : l'authentification OSPFv3 retirée, `::/0` autorisé en
entrée d'un voisin eBGP, un préfixe IPv6 local autorisé en entrée. Les configurations sont celles relevées
en direct sur les labs en double pile (tests/fixtures/live_dualstack/) ; chaque mutation dit ce qu'elle
change, et la configuration nominale, elle, ne donne aucune violation (sauf le défaut réel et documenté du
lien r4-r5).
"""
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.model import DeviceState

ROOT = Path(__file__).resolve().parent.parent
FX = Path(__file__).resolve().parent / "fixtures" / "live_dualstack"
RULES = compliance.load_rule_files([ROOT / "netcheck/rules/security.yml",
                                     ROOT / "netcheck/rules/security-ipv6.yml"])

FRR6 = "ospf6-authentification"
EOS6 = "eos-ospf6-authentification-ipsec"
SRL6 = "srlinux-ospf6-authentification-keychain"
SRL2 = "srlinux-ospf-authentification-keychain"
NODEF = "ebgp-pas-de-route-par-defaut"
NOOWN = "ebgp-pas-de-reinjection-de-prefixes-locaux"
OSPF6 = (FRR6, EOS6, SRL6)


def cfg(name: str) -> str:
    return (FX / name).read_text(encoding="utf-8")


def run(driver: str, text: str, device: str = "r3"):
    state = DeviceState(name=device, host="-", timestamp="", reachable=True, driver=driver,
                        running_config=text)
    return compliance.evaluate_config(RULES, {device: state}, {"eth0", "mgmt0", "Management0"}, offline=True)


def violations(driver: str, text: str, device: str = "r3", rule: str | None = None):
    found = run(driver, text, device).violations
    return [v for v in found if rule is None or v.rule.id == rule]


def once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


def subjects(found) -> list[str | None]:
    return [v.subject for v in found]


# ------------------------------------------------------------------------------------------
# 1. Authentification OSPFv3 : FRR
# ------------------------------------------------------------------------------------------

AUTH_R1_ETH1 = " ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key lab-ospf-v3r1r2"


@pytest.mark.parametrize("name", ["frr_r1.txt", "frr_r2.txt", "frr_r3.txt"])
def test_frr_authenticated_routers_have_no_violation_at_all(name):
    assert run("frr", cfg(name), "r3").violations == []


@pytest.mark.parametrize(("name", "device", "interface"),
                         [("frr_r4.txt", "r4", "eth2"), ("frr_r5.txt", "r5", "eth1")])
def test_the_real_unauthenticated_r4_r5_link_is_reported_with_its_interface(name, device, interface):
    found = violations("frr", cfg(name), device)
    assert [(v.rule.id, v.subject) for v in found] == [(FRR6, interface)]
    assert found[0].detail == (f"interface {interface} : adjacence OSPFv3 active sans authentification "
                               f"(ipv6 ospf6 authentication)")


def test_removing_the_ospfv3_authentication_of_an_interface_is_detected():
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1 + "\n", "")
    found = violations("frr", text, "r1")
    assert [(v.rule.id, v.subject) for v in found] == [(FRR6, "eth1")]


def test_an_authentication_without_a_key_is_not_an_authentication():
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1, " ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256")
    assert subjects(violations("frr", text, "r1")) == ["eth1"]


def test_a_keychain_reference_is_an_authentication():
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1, " ipv6 ospf6 authentication keychain KC-OSPF6")
    assert violations("frr", text, "r1") == []


def test_authentication_null_is_not_an_authentication():
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1, " ipv6 ospf6 authentication null")
    assert subjects(violations("frr", text, "r1")) == ["eth1"]


def test_ipv4_authentication_does_not_satisfy_the_ipv6_rule():
    # eth1 de r1 porte aussi l'authentification OSPFv2 : elle ne couvre pas l'OSPFv3, les deux sont
    # indépendantes.
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1 + "\n", "")
    assert "ip ospf authentication message-digest" in text
    assert subjects(violations("frr", text, "r1", FRR6)) == ["eth1"]
    # Et l'inverse : retirer l'authentification OSPFv2 ne dit rien de l'OSPFv3.
    v2_lines = " ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 lab-ospf-r1r2\n"
    text = once(cfg("frr_r1.txt"), v2_lines,
                "")
    assert violations("frr", text, "r1", FRR6) == []


def test_a_passive_ospfv3_interface_needs_no_authentication():
    text = once(cfg("frr_r4.txt"), " ipv6 ospf6 network point-to-point\n",
                " ipv6 ospf6 network point-to-point\n ipv6 ospf6 passive\n")
    assert violations("frr", text, "r4") == []


def test_an_interface_without_ospfv3_needs_no_authentication():
    text = once(cfg("frr_r4.txt"), " ipv6 address 2001:db8:2:45::2/127\n ipv6 ospf6 area 0\n",
                " ipv6 address 2001:db8:2:45::2/127\n")
    assert violations("frr", text, "r4") == []


def test_ospfv3_subcommands_at_the_first_level_are_flagged_not_silently_misread():
    # FRR lit selon le CONTEXTE, pas l'indentation (vérifié par `vtysh -C` : refusées après `exit`, acceptées
    # juste après `interface`). Une ligne non indentée est signalée, jamais lue comme « sans
    # authentification ».
    text = once(cfg("frr_r1.txt"), AUTH_R1_ETH1, AUTH_R1_ETH1.strip())
    result = run("frr", text, "r1")
    assert any("sous-commande de « interface » au premier niveau" in w.warning.reason
               for w in result.config_warnings)
    text = once(cfg("frr_r1.txt"), " ospf6 router-id 10.1.255.1", "ospf6 router-id 10.1.255.1")
    assert any("router ospf6" in w.warning.reason for w in run("frr", text, "r1").config_warnings)


# ------------------------------------------------------------------------------------------
# 1 bis. Authentification OSPFv3 : EOS (IPsec) et SR Linux (keychain)
# ------------------------------------------------------------------------------------------

EOS_P2P = "   ospfv3 network point-to-point\n"
EOS_IPSEC = "   ospfv3 authentication ipsec spi 256 sha1 7 3FF8f4FhFGqBqYeIx\n"


def test_eos_real_unauthenticated_link_is_reported_and_passive_interfaces_are_not():
    found = violations("eos", cfg("eos_r4.txt"), "r4", EOS6)
    # Ethernet1 et Loopback0 portent `ospfv3 passive-interface` : passives, hors sujet.
    assert [v.subject for v in found] == ["Ethernet2"]
    assert found[0].detail == ("interface Ethernet2 : adjacence OSPFv3 active sans authentification "
                               "(ospfv3 authentication ipsec)")


IPSEC_FORMS = [EOS_IPSEC, "   ospfv3 authentication ipsec spi 256 md5 7 3FF8f4FhFGqBqYeIx\n",
               "   ospfv3 authentication ipsec spi 256 sha1 passphrase 7 3FF8f4FhFGqBqYeIx\n"]


@pytest.mark.parametrize("line", IPSEC_FORMS)
def test_eos_ipsec_authentication_closes_the_violation(line):
    text = once(cfg("eos_r4.txt"), EOS_P2P, EOS_P2P + line)
    assert violations("eos", text, "r4", EOS6) == []


@pytest.mark.parametrize("line", ["   ospfv3 authentication ipsec spi 256 sha1\n",
                                  "   ospfv3 authentication ipsec spi abc sha1 7 3FF8f4FhFGqBqYeIx\n",
                                  "   ospfv3 authentication ipsec spi 256 sha512 7 3FF8f4FhFGqBqYeIx\n"])
def test_eos_authentication_without_a_key_or_with_a_bad_form_is_not_an_authentication(line):
    text = once(cfg("eos_r4.txt"), EOS_P2P, EOS_P2P + line)
    assert [v.subject for v in violations("eos", text, "r4", EOS6)] == ["Ethernet2"]


def test_eos_passive_is_written_two_ways_and_both_are_passive():
    # Forme du fichier de démarrage.
    text = once(cfg("eos_r4.txt"), EOS_P2P, EOS_P2P + "   ospfv3 passive\n")
    assert violations("eos", text, "r4", EOS6) == []
    text = once(cfg("eos_r4.txt"), EOS_P2P, EOS_P2P + "   ospfv3 passive-interface\n")        # running-config
    assert violations("eos", text, "r4", EOS6) == []


def test_eos_ospfv2_authentication_does_not_satisfy_ospfv3():
    assert "ip ospf authentication message-digest" in cfg("eos_r4.txt")
    assert subjects(violations("eos", cfg("eos_r4.txt"), "r4", EOS6)) == ["Ethernet2"]


V3_IFACE = ("            interface ethernet-1/1.0 {\n                interface-type point-to-point\n"
            "            }\n")


def test_srlinux_real_ospfv3_instance_is_reported_on_its_interface():
    found = violations("srlinux", cfg("srl_r5.txt"), "r5")
    assert [(v.rule.id, v.subject) for v in found] == [(SRL6, "ethernet-1/1.0")]
    assert found[0].detail == ("interface OSPFv3 ethernet-1/1.0 active (non passive) sans authentification "
                               "(aucune keychain référencée)")


def test_srlinux_a_keychain_on_the_ospfv3_interface_closes_the_violation():
    text = once(cfg("srl_r5.txt"), V3_IFACE, V3_IFACE.replace(
        "            }\n", "                authentication {\n                    keychain kc-ospf-r4r5\n"
                           "                }\n            }\n"))
    assert violations("srlinux", text, "r5") == []


def test_srlinux_unknown_or_wrong_type_keychain_is_reported():
    block = ("                authentication {\n                    keychain %s\n                }\n")
    close = "            }\n"
    unknown = once(cfg("srl_r5.txt"), V3_IFACE, V3_IFACE.replace(close, block % "kc-absente" + close))
    found = violations("srlinux", unknown, "r5")
    assert [v.detail for v in found] == [
        "interface OSPFv3 ethernet-1/1.0 référence la keychain 'kc-absente', "
        "introuvable sous /system authentication"]
    wrong = once(cfg("srl_r5.txt"), "        type ospf\n", "        type isis\n")
    wrong = once(wrong, V3_IFACE, V3_IFACE.replace(close, block % "kc-ospf-r4r5" + close))
    assert "qui n'est pas de type ospf" in violations("srlinux", wrong, "r5")[0].detail


def test_srlinux_ospfv2_rules_no_longer_read_the_ospfv3_instance():
    # La v0.3.0 fusionnait les interfaces de toutes les instances par leur nom : une keychain posée sur
    # l'interface de l'instance OSPFv3 masquait son absence dans l'instance OSPFv2. Chaque version se juge
    # à part.
    v2_auth = ("                authentication {\n                    keychain kc-ospf-r4r5\n"
               "                }\n")
    text = once(cfg("srl_r5.txt"), v2_auth, "")
    # La mutation ne touche que l'instance OSPFv3.
    head, marker, tail = text.partition("    instance v3 {")
    v3_with_keychain = once(tail, V3_IFACE, V3_IFACE.replace("            }\n", v2_auth + "            }\n"))
    with_v3_keychain = head + marker + v3_with_keychain
    found = violations("srlinux", with_v3_keychain, "r5", SRL2)
    assert [v.subject for v in found] == ["ethernet-1/1.0"]
    assert violations("srlinux", with_v3_keychain, "r5", SRL6) == []
    # Et une instance OSPFv3 n'est jamais reprochée à la règle OSPFv2 (aucune keychain, aucune violation v2).
    assert violations("srlinux", cfg("srl_r5.txt"), "r5", SRL2) == []


def test_srlinux_set_syntax_gives_the_same_verdict_as_the_braces():
    set_text = (ROOT / "configs-multivendor/r5/config.cli").read_text(encoding="utf-8")
    found = violations("srlinux", set_text, "r5")
    assert [(v.rule.id, v.subject) for v in found] == [(SRL6, "ethernet-1/1.0")]


def test_srlinux_an_instance_without_version_is_read_as_ospfv2():
    text = once(cfg("srl_r5.txt"), "        version ospf-v2\n", "")
    assert violations("srlinux", text, "r5", SRL2) == []   # toujours v2 : conforme
    assert [v.subject for v in violations("srlinux", text, "r5", SRL6)] \
        == ["ethernet-1/1.0"]


# ------------------------------------------------------------------------------------------
# 2. ::/0 autorisé en entrée
# ------------------------------------------------------------------------------------------

PL6_IN = "ipv6 prefix-list PL6-EBGP-IN seq 20 permit 2001:db8:a2::/64\n"


def add_in(entry: str) -> str:
    return once(cfg("frr_r3.txt"), PL6_IN, PL6_IN + f"ipv6 prefix-list PL6-EBGP-IN seq 30 {entry}\n")


def test_nominal_ipv6_input_policy_is_compliant_for_default_and_own_prefixes():
    assert violations("frr", cfg("frr_r3.txt"), "r3", NODEF) == []
    assert violations("frr", cfg("frr_r3.txt"), "r3", NOOWN) == []


@pytest.mark.parametrize("entry", ["permit ::/0", "permit ::/0 le 128", "permit ::/0 ge 1 le 64",
                                   "permit 0::/0", "permit 0:0:0:0:0:0:0:0/0"])
def test_ipv6_default_route_allowed_inbound_is_reported_whatever_its_spelling(entry):
    found = violations("frr", add_in(entry), "r3", NODEF)
    assert [v.subject for v in found] == ["2001:db8:34::3"]
    assert found[0].detail == ("prefix-list 'PL6-EBGP-IN' (politique d'entrée du voisin eBGP 2001:db8:34::3) "
                               "autorise ::/0 : route par défaut acceptable depuis l'extérieur")


def test_a_deny_of_the_ipv6_default_route_is_not_an_authorisation():
    assert violations("frr", add_in("deny ::/0"), "r3", NODEF) == []


def test_ipv6_default_route_is_found_on_the_other_router_too():
    text = once(cfg("frr_r4.txt"), "ipv6 prefix-list PL6-EBGP-IN seq 20 permit 2001:db8:a1::/64\n",
                "ipv6 prefix-list PL6-EBGP-IN seq 20 permit 2001:db8:a1::/64\n"
                "ipv6 prefix-list PL6-EBGP-IN seq 30 permit ::/0\n")
    assert subjects(violations("frr", text, "r4", NODEF)) == ["2001:db8:34::2"]


def test_the_ipv4_default_route_check_is_unchanged_and_independent():
    text = once(cfg("frr_r3.txt"), "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n",
                "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n"
                "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n")
    found = violations("frr", text, "r3", NODEF)
    assert [(v.subject, "autorise 0.0.0.0/0" in v.detail) for v in found] == [("172.16.34.2", True)]
    # Une `::/0` dans une liste IPv4 n'existe pas, et 0.0.0.0/0 dans l'IPv6 non plus : chaque famille a sa
    # valeur.
    assert violations("frr", add_in("permit 0.0.0.0/0"), "r3", NODEF) == []


# ------------------------------------------------------------------------------------------
# 3. Préfixe local autorisé en entrée
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("entry", ["permit 2001:db8:1::/48", "permit 2001:db8:1:0::/48",
                                   "permit 2001:db8:a1::/64", "permit 2001:DB8:A1:0::/64"])
def test_a_local_ipv6_prefix_allowed_inbound_is_reported_whatever_its_spelling(entry):
    found = violations("frr", add_in(entry), "r3", NOOWN)
    assert [v.subject for v in found] == ["2001:db8:34::3"]
    assert "que ce routeur annonce déjà lui-même : risque de réinjection" in found[0].detail
    assert "voisin eBGP 2001:db8:34::3" in found[0].detail


def test_a_prefix_the_router_does_not_announce_is_not_a_reinjection():
    assert violations("frr", add_in("permit 2001:db8:2:77::/64"), "r3",
                      NOOWN) == []
    # Le préfixe d'un autre routeur de l'AS (r4 annonce 2001:db8:2::/48) n'est pas « local » à r3.
    assert violations("frr", add_in("permit 2001:db8:2::/48"), "r3", NOOWN) == []


def test_a_deny_of_a_local_ipv6_prefix_is_not_an_authorisation():
    assert violations("frr", add_in("deny 2001:db8:1::/48"), "r3", NOOWN) == []


def test_the_own_prefix_must_be_announced_to_count():
    # Sans `network 2001:db8:1::/48`, ce routeur n'annonce plus ce préfixe : l'autoriser en entrée n'est
    # plus une réinjection de ses propres préfixes.
    text = once(add_in("permit 2001:db8:1::/48"), "  network 2001:db8:1::/48\n", "")
    assert violations("frr", text, "r3", NOOWN) == []


def test_the_rule_descriptions_name_ipv6():
    by_id = {r.id: r for r in RULES}
    assert "::/0" in by_id[NODEF].description
    assert "IPv6" in by_id[NOOWN].description


# ------------------------------------------------------------------------------------------
# Fichiers de règles
# ------------------------------------------------------------------------------------------

def test_ospfv3_rules_live_in_their_own_file_so_the_v030_files_keep_their_ids():
    v6 = compliance.load_rules(ROOT / "netcheck/rules/security-ipv6.yml")
    assert sorted(r.id for r in v6) == sorted(OSPF6)
    v3_ids = {r.id for r in compliance.load_rules(ROOT / "netcheck/rules/security.yml")}
    assert not {r.id for r in v6} & v3_ids
    assert all(r.severity == "haute" for r in v6)          # jamais « critique » : dérogeables


def test_the_same_rule_id_in_two_files_is_refused(tmp_path):
    copy = tmp_path / "again.yml"
    copy.write_text((ROOT / "netcheck/rules/security-ipv6.yml").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="id de règle en double"):
        compliance.load_rule_files([ROOT / "netcheck/rules/security-ipv6.yml", copy])
