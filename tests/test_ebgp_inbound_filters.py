"""Phase B4 : « pas de route par défaut en entrée » et « pas de réinjection de nos préfixes en entrée ».

1. FRR, IPv4 : seuls les `permit` d'une prefix-list autorisent un préfixe, comme déjà en IPv6 (B3). La v0.3.0
   comptait aussi les `deny` IPv4 : `deny 0.0.0.0/0` (le bon filtre) était signalé comme une autorisation.
2. EOS : les deux règles lisaient FRR seulement (silence depuis la v0.3.0). Elles lisent maintenant les
route-maps
   et prefix-lists d'EOS, IPv4 et IPv6, avec le voisin EFFECTIF (peer groups compris, famille par famille).

Les configurations sont celles relevées en direct sur les labs (tests/fixtures/live_dualstack/, peergroups/) ;
chaque test dit ce qu'il modifie. Syntaxes EOS vérifiées sur cEOS 4.34.8M dans des sessions de configuration
abandonnées : une prefix-list IPv6 s'écrit toujours en sous-mode ; une IPv4 sur une ligne OU en sous-mode ;
`seq N` est facultatif ; un route-map en entrée est posé sous `router bgp` (IPv4) ou `address-family`.
"""
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.drivers.bgp_neighbors import EOS_SYNTAX, BgpView
from netcheck.drivers.registry import DRIVER_REGISTRY
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


# ------------------------------------------------------------------------------------------
# 2. EOS : la configuration réelle de r4
# ------------------------------------------------------------------------------------------

EOS_R4 = read("live_dualstack", "eos_r4.txt")
IN4 = "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.1.0/24\n"
IN6 = "   seq 20 permit 2001:db8:a1::/64\n"
DEFAULT_MESSAGE = "prefix-list 'PL-EBGP-IN' (politique d'entrée du voisin eBGP 172.16.34.1) " + DEFAULT_V4


def eos_in4(entry: str, text: str = EOS_R4) -> str:
    return once(text, IN4, IN4 + f"ip prefix-list PL-EBGP-IN seq 30 {entry}\n")


def eos_in6(entry: str, text: str = EOS_R4) -> str:
    # La liste PL6-EBGP-IN est celle qui se termine par « seq 20 permit 2001:db8:a1::/64 » avant PL6-EBGP-OUT.
    head, tail = text.split("ipv6 prefix-list PL6-EBGP-OUT", 1)
    return once(head, IN6, IN6 + f"   seq 30 {entry}\n") + "ipv6 prefix-list PL6-EBGP-OUT" + tail


@pytest.mark.parametrize("path", [("live_dualstack", "eos_r4.txt"), ("ceos", "r4", "running_config.txt"),
                                  ("peergroups", "eos_s1_group.txt"), ("peergroups", "eos_s2_override.txt"),
                                  ("peergroups", "eos_s6_listen_group.txt")])
def test_eos_the_real_configurations_have_no_default_route_or_reinjection_violation(path):
    assert [v for v in run("eos", read(*path)) if v.rule.id in (NODEF, NOOWN)] == []


def test_eos_the_two_rules_now_apply_to_eos_and_to_frr():
    by_id = {r.id: r for r in RULES}
    for rule_id, kind in ((NODEF, "bgp_neighbor_no_default_route_policy"),
                          (NOOWN, "bgp_neighbor_no_own_prefixes_policy")):
        assert by_id[rule_id].drivers == ["frr", "eos"] and by_id[rule_id].kind == kind
        assert compliance.implementers(kind) == ["eos", "frr"]
        assert by_id[rule_id].severity == "haute"           # jamais « critique » : dérogeable


@pytest.mark.parametrize("entry", ["permit 0.0.0.0/0", "permit 0.0.0.0/0 le 32",
                                   "permit 0.0.0.0/0 ge 8 le 16"])
def test_eos_ipv4_default_route_allowed_inbound_is_reported(entry):
    found = run("eos", eos_in4(entry), NODEF)
    assert [(v.subject, v.detail) for v in found] == [("172.16.34.1", DEFAULT_MESSAGE)]


def test_eos_the_ipv4_entry_may_omit_seq():
    text = once(EOS_R4, IN4, IN4 + "ip prefix-list PL-EBGP-IN permit 0.0.0.0/0\n")
    assert subjects(run("eos", text, NODEF)) == ["172.16.34.1"]


@pytest.mark.parametrize("entry", ["deny 0.0.0.0/0", "deny 0.0.0.0/0 le 32"])
def test_eos_a_deny_of_the_default_route_is_not_an_authorisation(entry):
    assert run("eos", eos_in4(entry), NODEF) == []


@pytest.mark.parametrize("entry", ["permit ::/0", "permit ::/0 le 128", "permit 0::/0",
                                   "permit 0:0:0:0:0:0:0:0/0"])
def test_eos_ipv6_default_route_allowed_inbound_is_reported_whatever_its_spelling(entry):
    found = run("eos", eos_in6(entry), NODEF)
    assert [(v.subject, v.detail) for v in found] == [(
        "2001:db8:34::2", "prefix-list 'PL6-EBGP-IN' (politique d'entrée du voisin eBGP 2001:db8:34::2) "
        + DEFAULT_V6)]


def test_eos_an_ipv6_deny_of_the_default_route_is_not_an_authorisation():
    assert run("eos", eos_in6("deny ::/0"), NODEF) == []


def test_eos_each_family_is_read_in_its_own_namespace():
    # 0.0.0.0/0 dans une liste IPv6, et ::/0 dans une liste IPv4, n'existent pas : chaque famille a sa valeur.
    assert run("eos", eos_in6("permit 0.0.0.0/0"), NODEF) == []
    assert run("eos", eos_in4("permit ::/0"), NODEF) == []


@pytest.mark.parametrize(("entry", "network"), [("permit 10.2.0.0/16", "10.2.0.0/16"),
                                                ("permit 192.168.2.0/24 le 32", "192.168.2.0/24")])
def test_eos_an_own_ipv4_prefix_allowed_inbound_is_a_reinjection(entry, network):
    found = run("eos", eos_in4(entry), NOOWN)
    assert [(v.subject, v.detail) for v in found] == [("172.16.34.1", (
        f"prefix-list 'PL-EBGP-IN' (politique d'entrée du voisin eBGP 172.16.34.1) autorise {network}, "
        + REINJECTION))]


@pytest.mark.parametrize("entry", ["permit 2001:db8:2::/48", "permit 2001:DB8:2:0::/48",
                                   "permit 2001:db8:a2::/64"])
def test_eos_an_own_ipv6_prefix_allowed_inbound_is_a_reinjection(entry):
    found = run("eos", eos_in6(entry), NOOWN)
    assert subjects(found) == ["2001:db8:34::2"] and found[0].detail.endswith(REINJECTION)
    assert "voisin eBGP 2001:db8:34::2" in found[0].detail


def test_eos_a_prefix_we_do_not_announce_and_a_deny_are_not_reinjections():
    assert run("eos", eos_in4("permit 10.9.0.0/16"), NOOWN) == []
    assert run("eos", eos_in4("deny 10.2.0.0/16"), NOOWN) == []
    assert run("eos", eos_in6("deny 2001:db8:2::/48"), NOOWN) == []
    # Le préfixe de l'autre AS (r3 annonce 10.1.0.0/16) n'est pas « local » à r4 : la liste nominale
    # l'autorise déjà.
    assert run("eos", EOS_R4, NOOWN) == []


def test_eos_a_prefix_must_be_announced_to_count():
    text = once(eos_in4("permit 10.2.0.0/16"), "      network 10.2.0.0/16\n", "")
    assert run("eos", text, NOOWN) == []


def test_eos_the_own_prefix_is_read_whether_the_network_is_under_router_bgp_or_an_address_family():
    # Dans la running-config relevée, `network` d'IPv4 est sous `address-family ipv4` ; dans le fichier de
    # démarrage du lab il est directement sous `router bgp`.
    startup = (ROOT / "configs-ceos/r4/startup-config").read_text(encoding="utf-8")
    assert "\n   network 10.2.0.0/16\n" in startup and "\n      network 10.2.0.0/16\n" in EOS_R4
    in_list = "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.1.0/24\n"
    own = in_list + "ip prefix-list PL-EBGP-IN seq 30 permit 10.2.0.0/16\n"
    assert subjects(run("eos", once(startup, in_list, own), NOOWN)) == ["172.16.34.1"]
    assert subjects(run("eos", eos_in4("permit 10.2.0.0/16"), NOOWN)) == ["172.16.34.1"]


# ------------------------------------------------------------------------------------------
# 3. EOS : les deux écritures d'une prefix-list IPv4, et les route-maps
# ------------------------------------------------------------------------------------------

def submode_v4(text: str) -> str:
    """La même configuration avec les listes IPv4 en sous-mode (EOS les réécrit ainsi dès qu'une liste est
    saisie en sous-mode : relevé en session abandonnée)."""
    out, lists = [], {}
    for line in text.splitlines():
        parts = line.split()
        if line.startswith("ip prefix-list ") and len(parts) >= 6 and parts[3] == "seq":
            lists.setdefault(parts[2], []).append("   " + " ".join(parts[3:]))
            continue
        out.append(line)
    block = []
    for name, entries in lists.items():
        block += [f"ip prefix-list {name}", *entries, "!"]
    marker = out.index("ip routing") + 2
    return "\n".join(out[:marker] + block + out[marker:]) + "\n"


def test_eos_the_ipv4_prefix_lists_are_read_in_submode_too():
    text = submode_v4(EOS_R4)
    assert "\nip prefix-list PL-EBGP-IN\n   seq 10 permit 10.1.0.0/16\n" in text
    assert run("eos", text, NODEF) == [] and run("eos", text, NOOWN) == []
    last = "   seq 20 permit 192.168.1.0/24\n"
    flagged = once(text, last, last + "   seq 30 permit 0.0.0.0/0\n")
    assert subjects(run("eos", flagged, NODEF)) == ["172.16.34.1"]
    own = once(text, last, last + "   seq 30 permit 10.2.0.0/16\n")
    assert subjects(run("eos", own, NOOWN)) == ["172.16.34.1"]


def test_eos_a_deny_sequence_of_a_route_map_is_the_classic_way_to_filter_the_default_route():
    # `route-map RM-EBGP-IN deny 5` + une liste qui LISTE la route par défaut : la route est REFUSÉE. Pas
    # une faute.
    deny = ("ip prefix-list PL-DEFAUT seq 10 permit 0.0.0.0/0\nroute-map RM-EBGP-IN deny 5\n"
            "   match ip address prefix-list PL-DEFAUT\n!\n")
    text = once(EOS_R4, "route-map RM-EBGP-IN permit 10\n", deny + "route-map RM-EBGP-IN permit 10\n")
    assert run("eos", text, NODEF) == []
    permit = deny.replace("deny 5", "permit 5")
    assert subjects(run("eos", once(EOS_R4, "route-map RM-EBGP-IN permit 10\n",
                                    permit + "route-map RM-EBGP-IN permit 10\n"), NODEF)) == ["172.16.34.1"]


def test_eos_every_permit_sequence_of_the_route_map_is_read_not_only_the_first():
    second = ("ip prefix-list PL-SECONDE seq 10 permit 0.0.0.0/0\nroute-map RM-EBGP-IN permit 20\n"
              "   match ip address prefix-list PL-SECONDE\n!\n")
    text = once(EOS_R4, "route-map RM-EBGP-OUT permit 10\n", second + "route-map RM-EBGP-OUT permit 10\n")
    found = run("eos", text, NODEF)
    assert [v.detail.split("'")[1] for v in found] == ["PL-SECONDE"]


def test_eos_a_route_map_without_action_is_a_permit():
    text = once(EOS_R4, "route-map RM-EBGP-IN permit 10\n", "route-map RM-EBGP-IN\n")
    match = "   match ip address prefix-list PL-EBGP-IN\n"
    bad = once(text, match, match + "   match ip address prefix-list PL-DEFAUT\n")
    assert run("eos", bad, NODEF) == []                       # PL-DEFAUT n'existe pas : rien à lire
    withlist = bad + "ip prefix-list PL-DEFAUT seq 10 permit 0.0.0.0/0\n"
    assert subjects(run("eos", withlist, NODEF)) == ["172.16.34.1"]


def test_eos_the_same_list_used_twice_is_reported_once_per_neighbor():
    both = EOS_R4.replace(IN4, IN4 + "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n"
                          "ip prefix-list PL-EBGP-IN seq 31 permit 0.0.0.0/0 le 32\n")
    assert len(run("eos", both, NODEF)) == 1


def test_eos_a_neighbor_without_inbound_route_map_has_nothing_to_read():
    text = once(EOS_R4, "   neighbor 172.16.34.1 route-map RM-EBGP-IN in\n", "")
    text = once(text, IN4, IN4 + "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n")
    assert run("eos", text, NODEF) == []       # la règle de politique d'entrée le dit déjà (autre règle)


def test_eos_no_bgp_means_nothing_to_check():
    assert run("eos", "hostname r4\nip routing\n") == []


def test_eos_a_misplaced_seq_line_is_not_read_and_the_audit_says_so():
    # Une ligne `seq` au premier niveau : EOS l'appliquerait à la liste ouverte, l'arbre la verrait nulle
    # part. Elle est signalée (ligne NON lue), jamais ignorée en silence.
    state = DeviceState(name="r4", host="-", timestamp="", reachable=True, driver="eos",
                        running_config="ipv6 prefix-list PL6-EBGP-IN\nseq 10 permit ::/0\n")
    cfg = DRIVER_REGISTRY["eos"]().parse_config(state.running_config)
    assert [w.reason for w in cfg.warnings if not w.kept] == [
        "sous-commande de « ip prefix-list ou ipv6 prefix-list » au premier niveau : EOS l'applique au bloc "
        "ouvert quelle que soit l'indentation, l'analyse ne sait pas lequel"]
    result = compliance.evaluate_config(RULES, {"r4": state}, set(), offline=True)
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 1)


# ------------------------------------------------------------------------------------------
# 4. EOS : le voisin effectif, peer groups compris, famille par famille
# ------------------------------------------------------------------------------------------

S1 = read("peergroups", "eos_s1_group.txt")


def test_eos_peer_group_members_inherit_the_inbound_policy_of_their_group():
    # s1 : PG-TEST (route-map RM-EBGP-IN en entrée) a deux membres, 192.0.2.1 et 192.0.2.2.
    text = once(S1, IN4, IN4 + "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n")
    found = run("eos", text, NODEF)
    assert sorted(subjects(found)) == ["172.16.34.1", "192.0.2.1", "192.0.2.2"]
    labels = {v.subject: v.detail for v in found}
    assert "voisin eBGP 192.0.2.1 (peer group PG-TEST)" in labels["192.0.2.1"]
    assert "voisin eBGP 172.16.34.1)" in labels["172.16.34.1"]
    assert not any("voisin eBGP PG-TEST" in v.detail for v in found)      # le groupe n'est jamais un voisin


def test_eos_a_member_policy_masks_the_policy_of_its_group():
    # 192.0.2.3 reçoit une route-map d'entrée PROPRE (saine) qui masque celle de son groupe (qui, elle, laisse
    # passer la route par défaut) ; 192.0.2.4 garde celle du groupe.
    text = read("peergroups", "eos_s2_override.txt")
    text = once(text, "   neighbor PG-OVR maximum-routes 10\n",
                "   neighbor PG-OVR maximum-routes 10\n   neighbor PG-OVR route-map RM-DEFAUT in\n")
    text = once(text, "   neighbor 192.0.2.3 peer group PG-OVR\n",
                "   neighbor 192.0.2.3 peer group PG-OVR\n   neighbor 192.0.2.3 route-map RM-EBGP-IN in\n")
    text += ("ip prefix-list PL-DEFAUT seq 10 permit 0.0.0.0/0\nroute-map RM-DEFAUT permit 10\n"
             "   match ip address prefix-list PL-DEFAUT\n!\n")
    assert subjects(run("eos", text, NODEF)) == ["192.0.2.4"]


def test_eos_the_override_is_judged_per_address_family():
    # Le groupe a une route-map IPv6 en entrée (sous address-family ipv6) qui laisse passer ::/0 ; le
    # membre n'a de route-map propre que pour l'IPv4. Le membre garde celle du groupe pour l'IPv6 : il est
    # signalé.
    text = once(S1, "   neighbor PG-TEST maximum-routes 10\n", "   neighbor PG-TEST maximum-routes 10\n")
    text = once(text, "   neighbor 192.0.2.1 peer group PG-TEST\n",
                "   neighbor 192.0.2.1 peer group PG-TEST\n   neighbor 192.0.2.1 route-map RM-EBGP-OUT in\n")
    text = once(text, "   neighbor PG-TEST route-map RM-EBGP-IN in\n", "")
    network = "   network 192.168.2.0/24\n"
    text = once(text, network, network + "   !\n   address-family ipv6\n"
                "      neighbor PG-TEST route-map RM6-DEFAUT in\n")
    text += ("ipv6 prefix-list PL6-DEFAUT\n   seq 10 permit ::/0\n!\nroute-map RM6-DEFAUT permit 10\n"
             "   match ipv6 address prefix-list PL6-DEFAUT\n!\n")
    found = run("eos", text, NODEF)
    assert [(v.subject, v.detail.endswith(DEFAULT_V6)) for v in found if v.subject == "192.0.2.1"] == [
        ("192.0.2.1", True)]
    assert "192.0.2.2" in subjects(found)                        # l'autre membre, qui n'a rien de propre


def test_eos_a_dynamic_neighbor_range_inherits_the_policy_of_its_group():
    text = read("peergroups", "eos_s6_listen_group.txt")
    text = once(text, IN4, IN4 + "ip prefix-list PL-EBGP-IN seq 30 permit 0.0.0.0/0\n")
    found = run("eos", text, NODEF)
    assert sorted(subjects(found)) == ["172.16.34.1", "192.0.2.64/26"]
    assert any("plage dynamique, peer group PG-DYN" in v.detail for v in found)


def test_eos_two_permit_sequences_naming_the_same_list_give_one_finding():
    twice = ("route-map RM-EBGP-IN permit 20\n   match ip address prefix-list PL-EBGP-IN\n!\n")
    text = once(eos_in4("permit 0.0.0.0/0"), "route-map RM-EBGP-OUT permit 10\n",
                twice + "route-map RM-EBGP-OUT permit 10\n")
    assert len(run("eos", text, NODEF)) == 1


def view(text: str) -> BgpView:
    cfg = DRIVER_REGISTRY["eos"]().parse_config(text)
    return BgpView(cfg.top("router", "bgp", "*")[0], EOS_SYNTAX)


def route_map_in(rest):
    return len(rest) == 3 and rest[0] == "route-map" and rest[2] == "in"


GROUPED = """router bgp 65002
   neighbor PG peer group
   neighbor PG remote-as 65099
   neighbor PG route-map RM-V4-GROUP in
   neighbor 192.0.2.1 peer group PG
   neighbor 192.0.2.2 peer group PG
   neighbor 192.0.2.2 route-map RM-V4-OWN in
   !
   address-family ipv6
      neighbor PG route-map RM-V6-GROUP in
      neighbor 192.0.2.1 route-map RM-V6-OWN in
"""


def test_lines_by_family_masks_the_group_family_by_family_and_returns_each_line_once():
    bgp = view(GROUPED)
    names = lambda key: [n.words[3] for n in bgp.lines_by_family(key, route_map_in)]  # noqa: E731
    # Un membre sans réglage propre dans une famille garde celui de son groupe dans cette famille.
    assert names("192.0.2.1") == ["RM-V6-OWN", "RM-V4-GROUP"]
    assert names("192.0.2.2") == ["RM-V4-OWN", "RM-V6-GROUP"]
    assert names("PG") == ["RM-V4-GROUP", "RM-V6-GROUP"]
    # `lines`, lui, masque tout le groupe dès que le membre a une ligne : le comportement de FRR est inchangé.
    assert [n.words[3] for n in bgp.lines("192.0.2.1", route_map_in)] == ["RM-V6-OWN"]
    assert names("192.0.2.99") == []


def test_lines_directly_under_router_bgp_are_ipv4_like_an_address_family_ipv4_block():
    text = GROUPED.replace("   !\n   address-family ipv6\n", "   !\n   address-family ipv4\n"
                           "      neighbor 192.0.2.1 route-map RM-V4-IN-AF in\n   address-family ipv6\n")
    assert [n.words[3] for n in view(text).lines_by_family("192.0.2.1", route_map_in)] == [
        "RM-V4-IN-AF", "RM-V6-OWN"]


def test_frr_a_prefix_list_entry_with_a_malformed_seq_is_not_read():
    # FRR refuse une telle ligne : elle ne peut pas figurer dans une vraie configuration.
    assert run("frr", frr_in("permit 0.0.0.0/0").replace("seq 30", "seq abc"), NODEF, "r3") == []


# ------------------------------------------------------------------------------------------
# 1 bis. FRR : toutes les route-maps d'entrée, par famille ; les séquences `deny` ne sont pas des fautes
# ------------------------------------------------------------------------------------------

def frr_with_sequence(action: str, family: str) -> str:
    """r3 avec une séquence de route-map d'entrée (`permit` ou `deny`, séquence 5) qui nomme une liste
    contenant la route par défaut. `deny` + une liste qui la contient est la manière classique de la
    REFUSER."""
    if family == "ip":
        lists = "ip prefix-list PL-DEFAUT seq 10 permit 0.0.0.0/0\n"
        route_map, match = "RM-EBGP-IN", "match ip address prefix-list PL-DEFAUT"
    else:
        lists = "ipv6 prefix-list PL6-DEFAUT seq 10 permit ::/0\n"
        route_map, match = "RM6-EBGP-IN", "match ipv6 address prefix-list PL6-DEFAUT"
    anchor = f"route-map {route_map} permit 10\n"
    return once(FRR_R3, anchor, f"{lists}route-map {route_map} {action} 5\n {match}\nexit\n" + anchor)


@pytest.mark.parametrize(("family", "neighbor"), [("ip", "172.16.34.2"), ("ipv6", "2001:db8:34::3")])
def test_frr_a_deny_sequence_of_a_route_map_is_not_a_violation(family, neighbor):
    assert run("frr", frr_with_sequence("deny", family), NODEF, "r3") == []
    # La même séquence en `permit` laisse passer la route par défaut : signalée, sur le bon voisin.
    assert subjects(run("frr", frr_with_sequence("permit", family), NODEF, "r3")) == [neighbor]


def test_frr_a_deny_sequence_naming_our_own_prefix_is_not_a_reinjection():
    anchor = "route-map RM-EBGP-IN permit 10\n"
    deny = ("ip prefix-list PL-NOUS seq 10 permit 10.1.0.0/16\nroute-map RM-EBGP-IN deny 5\n"
            " match ip address prefix-list PL-NOUS\nexit\n")
    text = once(FRR_R3, anchor, deny + anchor)
    assert run("frr", text, NOOWN, "r3") == []
    assert subjects(run("frr", text.replace("deny 5", "permit 5"), NOOWN, "r3")) == ["172.16.34.2"]


def frr_two_families() -> str:
    """Un MÊME voisin actif dans deux familles, avec un route-map d'entrée par famille : celui de l'IPv4
    est sain, celui de l'IPv6 laisse passer `::/0` et un de nos préfixes. (Syntaxe contrôlée par `vtysh
    -C`.)"""
    out = once(FRR_R3, "  neighbor 2001:db8:34::3 route-map RM6-EBGP-OUT out\n",
               "  neighbor 2001:db8:34::3 route-map RM6-EBGP-OUT out\n  neighbor 172.16.34.2 activate\n"
               "  neighbor 172.16.34.2 route-map RM6-DANGER in\n")
    return out + ("ipv6 prefix-list PL6-DANGER seq 10 permit ::/0\n"
                  "ipv6 prefix-list PL6-DANGER seq 20 permit 2001:db8:1::/48\n"
                  "route-map RM6-DANGER permit 10\n match ipv6 address prefix-list PL6-DANGER\nexit\n")


def test_frr_every_inbound_route_map_of_a_neighbor_is_read_not_only_the_first():
    text = frr_two_families()
    # La v0.3.0 et B3 ne lisaient que le premier (celui de l'IPv4, sain) : la politique dangereuse passait.
    found = run("frr", text, NODEF, "r3")
    assert [(v.subject, v.detail.endswith(DEFAULT_V6)) for v in found] == [("172.16.34.2", True)]
    assert "prefix-list 'PL6-DANGER'" in found[0].detail
    own = run("frr", text, NOOWN, "r3")
    assert [(v.subject, "autorise 2001:db8:1::/48" in v.detail) for v in own] == [("172.16.34.2", True)]


def frr_group_per_family() -> str:
    """s1 (peer group PG-TEST, route-map d'entrée IPv4 sain) : le groupe a en plus un route-map d'entrée
    IPv6 qui laisse passer `::/0`, et le membre 192.0.2.1 un route-map d'entrée IPv4 PROPRE. Le membre
    garde celui de son groupe pour l'IPv6. (Syntaxe contrôlée par `vtysh -C`.)"""
    text = read("peergroups", "frr_s1_group.txt")
    last = "  neighbor 172.16.34.2 route-map RM-EBGP-OUT out\n"
    text = once(text, last, last + "  neighbor 192.0.2.1 route-map RM-EBGP-IN in\n"
                " exit-address-family\n !\n address-family ipv6 unicast\n  neighbor PG-TEST activate\n"
                "  neighbor PG-TEST route-map RM6-DEFAUT in\n")
    return text + ("ipv6 prefix-list PL6-DEFAUT seq 10 permit ::/0\nroute-map RM6-DEFAUT permit 10\n"
                   " match ipv6 address prefix-list PL6-DEFAUT\nexit\n")


def test_frr_a_member_policy_masks_its_group_only_in_its_own_family():
    found = run("frr", frr_group_per_family(), NODEF, "r3")
    assert sorted(subjects(found)) == ["192.0.2.1", "192.0.2.2"]
    assert all(v.detail.endswith(DEFAULT_V6) and "(peer group PG-TEST)" in v.detail for v in found)


def test_frr_a_member_policy_still_masks_the_group_policy_of_the_same_family():
    # Le membre 192.0.2.2 reçoit un route-map IPv6 PROPRE et sain : il masque celui du groupe, qui laisse
    # passer ::/0.
    text = frr_group_per_family()
    text = once(text, "  neighbor PG-TEST route-map RM6-DEFAUT in\n",
                "  neighbor PG-TEST route-map RM6-DEFAUT in\n  neighbor 192.0.2.2 route-map RM6-SAIN in\n")
    text += "ipv6 prefix-list PL6-SAIN seq 10 permit 2001:db8:2::/48\nroute-map RM6-SAIN permit 10\n" \
            " match ipv6 address prefix-list PL6-SAIN\nexit\n"
    assert subjects(run("frr", text, NODEF, "r3")) == ["192.0.2.1"]
