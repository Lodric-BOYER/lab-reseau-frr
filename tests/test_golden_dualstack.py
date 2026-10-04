"""Phase B3 : les réponses GELÉES des cas double pile sont celles que l'on attend, écrites à la main.

Ces cas (`dualstack:*`, `lab:dualstack-*`) sont une capacité nouvelle : aucune réponse de la v0.3.0 à
préserver, leur réponse vient du code de B3 (`golden.py add --current-code`, `record-new`). Ce fichier
compare la réponse gelée à ce qu'un humain en attend d'après les configurations RÉELLES des labs, sans
relire le moteur : aucune violation sauf le lien r4-r5 en OSPFv3, supprimer l'authentification d'une
interface la fait apparaître, une route par défaut IPv6 ajoutée à la politique d'entrée est signalée.
"""
import hashlib
import json
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parent / "golden"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "live_dualstack"
DUALSTACK = [f"dualstack:frr-r{i}" for i in range(1, 6)] + ["dualstack:eos-r4", "dualstack:srlinux-r5"]
FILES = {"dualstack:frr-r1": "frr_r1.txt", "dualstack:frr-r2": "frr_r2.txt", "dualstack:frr-r3": "frr_r3.txt",
         "dualstack:frr-r4": "frr_r4.txt", "dualstack:frr-r5": "frr_r5.txt", "dualstack:eos-r4": "eos_r4.txt",
         "dualstack:srlinux-r5": "srl_r5.txt"}

# Les seules violations attendues : le lien r4-r5 en OSPFv3, une règle par constructeur (gravité, règle,
# équipement, détail, catégorie). Écrites à la main.
LINK = {
    "dualstack:frr-r4": ["haute", "ospf6-authentification", "r4",
                         "interface eth2 : adjacence OSPFv3 active sans authentification "
                         "(ipv6 ospf6 authentication)",
                         "ospf"],
    "dualstack:frr-r5": ["haute", "ospf6-authentification", "r5",
                         "interface eth1 : adjacence OSPFv3 active sans authentification "
                         "(ipv6 ospf6 authentication)",
                         "ospf"],
    "dualstack:eos-r4": ["haute", "eos-ospf6-authentification-ipsec", "r4",
                         "interface Ethernet2 : adjacence OSPFv3 active sans authentification "
                         "(ospfv3 authentication ipsec)", "ospf"],
    "dualstack:srlinux-r5": ["haute", "srlinux-ospf6-authentification-keychain", "r5",
                             "interface OSPFv3 ethernet-1/1.0 active (non passive) sans authentification "
                             "(aucune keychain référencée)", "ospf"],
}


def gel(rules: str) -> dict:
    return json.loads((GOLDEN / f"compliance_{rules}.json").read_text(encoding="utf-8"))["cases"]


def key_of(index: int, line: str) -> str:
    return f"{index + 1}:{hashlib.sha1(line.strip().encode('utf-8')).hexdigest()[:8]}"


def mutant(rules: str, case: str, key: str) -> dict:
    """La réponse d'une mutation : celle de la base, complétée des seuls champs gelés comme différents."""
    entry = gel(rules)[case]
    return {**entry["base"], **entry.get("mutants_changed", {}).get(key, {})}


@pytest.mark.parametrize("rules", ["default", "security"])
@pytest.mark.parametrize("case", DUALSTACK)
def test_the_v030_rule_files_find_nothing_to_say_about_the_dualstack_configs(rules, case):
    base = gel(rules)[case]["base"]
    assert (base["compliant"], base["code"], base["violations"]) == (True, 0, [])


@pytest.mark.parametrize("case", DUALSTACK)
def test_ospfv3_rules_report_only_the_r4_r5_link(case):
    base = gel("security-ipv6")[case]["base"]
    if case in LINK:
        assert base["violations"] == [LINK[case]] and (base["compliant"], base["code"]) == (False, 2)
    else:
        assert (base["compliant"], base["code"], base["violations"]) == (True, 0, [])


def test_the_labs_have_exactly_the_link_violations_and_nothing_else():
    cases = gel("security-ipv6")
    frr = cases["lab:dualstack-frr"]["base"]
    assert [(v[1], v[2]) for v in frr["violations"]] == [("ospf6-authentification", "r4"),
                                                         ("ospf6-authentification", "r5")]
    mixed = cases["lab:dualstack-multivendor"]["base"]
    assert sorted((v[1], v[2]) for v in mixed["violations"]) == [
        ("ospf6-authentification", "r4"), ("srlinux-ospf6-authentification-keychain", "r5")]
    ceos = cases["lab:dualstack-ceos"]["base"]
    assert sorted((v[1], v[2]) for v in ceos["violations"]) == [("eos-ospf6-authentification-ipsec", "r4"),
                                                                ("ospf6-authentification", "r5")]
    for lab in ("lab:dualstack-frr", "lab:dualstack-multivendor", "lab:dualstack-ceos"):
        for rules in ("default", "security"):
            assert gel(rules)[lab]["base"]["violations"] == []
        assert cases[lab]["base"]["code"] == 2


@pytest.mark.parametrize("case", ["dualstack:frr-r1", "dualstack:frr-r2", "dualstack:frr-r3"])
def test_deleting_an_ospfv3_authentication_line_brings_the_violation_back(case):
    lines = (FIXTURES / FILES[case]).read_text(encoding="utf-8").splitlines()
    checked = 0
    interface = None
    for i, line in enumerate(lines):
        if line.startswith("interface "):
            interface = line.split()[1]
        if "ipv6 ospf6 authentication" in line:
            answer = mutant("security-ipv6", case, key_of(i, line))
            assert [(v[1], v[3].split(" :")[0]) for v in answer["violations"]] == [
                ("ospf6-authentification", f"interface {interface}")], (case, line)
            checked += 1
    assert checked >= 1


def test_making_a_passive_interface_active_requires_its_authentication():
    case = "dualstack:frr-r1"
    lines = (FIXTURES / FILES[case]).read_text(encoding="utf-8").splitlines()
    interface, found = None, 0
    for i, line in enumerate(lines):
        if line.startswith("interface "):
            interface = line.split()[1]
        if line.strip() == "ipv6 ospf6 passive":
            answer = mutant("security-ipv6", case, key_of(i, line))
            shown = [v[3].split(" :")[0] for v in answer["violations"]]
            assert shown == [f"interface {interface}"], interface
            found += 1
    assert found == 2        # lo et le LAN : passifs, donc exemptés tant qu'ils le restent


def test_removing_the_ospfv3_area_of_the_real_unauthenticated_interface_removes_the_violation():
    case = "dualstack:frr-r4"
    lines = (FIXTURES / FILES[case]).read_text(encoding="utf-8").splitlines()
    interface, hits = None, []
    for i, line in enumerate(lines):
        if line.startswith("interface "):
            interface = line.split()[1]
        if line.strip() == "ipv6 ospf6 area 0" and interface == "eth2":
            hits.append(mutant("security-ipv6", case, key_of(i, line)))
    assert len(hits) == 1 and hits[0]["violations"] == [] and hits[0]["compliant"] is True


@pytest.mark.parametrize("case", ["dualstack:frr-r3", "dualstack:frr-r4"])
def test_an_ipv6_default_route_added_to_the_input_prefix_list_is_reported(case):
    changed = gel("security")[case]["mutants_changed"]
    probes = {k: v for k, v in changed.items() if k.startswith("probe:ipv6-prefix-list-default")}
    assert len(probes) == 4                     # deux variantes (sans / avec `le 128`) x deux listes IPv6
    neighbor = "2001:db8:34::3" if case.endswith("r3") else "2001:db8:34::2"
    for key, answer in probes.items():
        details = [v[3] for v in answer["violations"] if v[1] == "ebgp-pas-de-route-par-defaut"]
        entering = "PL6-EBGP-IN" in "".join(v[3] for v in answer["violations"])
        # Seule la liste d'ENTRÉE est une violation ; la liste de sortie, ajoutée de la même façon, n'en
        # est pas une.
        assert bool(details) == entering, key
        for detail in details:
            assert neighbor in detail and "autorise ::/0" in detail


def test_the_ipv6_probes_change_an_answer_only_where_a_rule_reads_ipv6_prefix_lists():
    # Seule security.yml a une règle qui lit les listes (route par défaut en entrée) : dans default.yml,
    # aucune sonde IPv6 ne change de réponse ; dans security.yml, seulement pour les deux routeurs eBGP FRR.
    for case, entry in gel("default").items():
        probes = [k for k in entry.get("mutants_changed", {}) if k.startswith("probe:ipv6-prefix-list")]
        assert not probes, case
    for case, entry in gel("security").items():
        has = any(k.startswith("probe:ipv6-prefix-list") for k in entry.get("mutants_changed", {}))
        assert has == (case in ("dualstack:frr-r3", "dualstack:frr-r4")), case


# ------------------------------------------------------------------------------------------
# Phase B4 : deux configurations RÉELLES de r4 (cEOS) relevées pendant le scénario d'intégration C6
# ------------------------------------------------------------------------------------------

LISTS = "dualstack:eos-r4-inbound-lists"
GROUP = "dualstack:eos-r4-inbound-peergroup"
NODEF = "ebgp-pas-de-route-par-defaut"
NOOWN = "ebgp-pas-de-reinjection-de-prefixes-locaux"


def found(rules: str, case: str) -> list[tuple[str, str]]:
    """(règle, détail) de chaque violation gelée de la base du cas."""
    return sorted((v[1], v[3]) for v in gel(rules)[case]["base"]["violations"])


def rule_ids(answer: dict) -> list[str]:
    return sorted(v[1] for v in answer["violations"])


def default_message(prefix_list: str, neighbor: str, network: str) -> str:
    return (f"prefix-list '{prefix_list}' (politique d'entrée du voisin eBGP {neighbor}) "
            f"autorise {network} : route par défaut acceptable depuis l'extérieur")


def reinjection_message(prefix_list: str, neighbor: str, network: str) -> str:
    return (f"prefix-list '{prefix_list}' (politique d'entrée du voisin eBGP {neighbor}) autorise {network}, "
            "que ce routeur annonce déjà lui-même : risque de réinjection")


def test_the_real_eos_configuration_with_dangerous_input_lists_has_exactly_four_violations():
    # Écrit d'après la configuration injectée : PL-EBGP-IN autorise 0.0.0.0/0 et 10.2.0.0/16 (que r4 annonce),
    # PL6-EBGP-IN autorise ::/0 et 2001:db8:2::/48 (que r4 annonce) : une violation par règle et par famille.
    expected = sorted([
        (NODEF, default_message("PL-EBGP-IN", "172.16.34.1", "0.0.0.0/0")),
        (NODEF, default_message("PL6-EBGP-IN", "2001:db8:34::2", "::/0")),
        (NOOWN, reinjection_message("PL-EBGP-IN", "172.16.34.1", "10.2.0.0/16")),
        (NOOWN, reinjection_message("PL6-EBGP-IN", "2001:db8:34::2", "2001:db8:2::/48")),
    ])
    assert found("security", LISTS) == expected
    assert gel("security")[LISTS]["base"]["code"] == 2


def test_the_real_eos_peer_group_member_is_reported_with_its_group():
    # Le membre fictif 192.0.2.77 hérite de la route-map d'entrée de PG-TEST (qui autorise 0.0.0.0/0 et
    # 192.168.2.0/24, que r4 annonce) : les deux règles de politique d'entrée le signalent, avec son
    # groupe. Il n'a ni mot de passe, ni GTSM, ni limite de routes : les trois autres règles eBGP aussi.
    # Rien d'autre.
    member = "192.0.2.77 (peer group PG-TEST)"
    expected = sorted([
        (NODEF, default_message("PL-TEST-IN", member, "0.0.0.0/0")),
        (NOOWN, reinjection_message("PL-TEST-IN", member, "192.168.2.0/24")),
        ("eos-ebgp-authentification-tcp-md5",
         f"voisin eBGP {member} sans authentification TCP-MD5 (mot de passe)"),
        ("eos-ebgp-gtsm-ttl-maximum-hops", f"voisin eBGP {member} sans GTSM (ttl maximum-hops)"),
        ("eos-ebgp-maximum-routes", f"voisin eBGP {member} sans limite maximum-routes"),
    ])
    assert found("security", GROUP) == expected


@pytest.mark.parametrize("case", [LISTS, GROUP])
def test_the_other_rule_files_only_see_the_known_link_on_the_real_eos_inbound_cases(case):
    assert gel("default")[case]["base"]["violations"] == []
    ipv6_rules = [v[1] for v in gel("security-ipv6")[case]["base"]["violations"]]
    assert ipv6_rules == ["eos-ospf6-authentification-ipsec"]


@pytest.mark.parametrize(("needle", "removed", "kept"), [
    ("ip prefix-list PL-EBGP-IN seq 90 permit 0.0.0.0/0 le 32", (NODEF, "172.16.34.1"), 3),
    ("ip prefix-list PL-EBGP-IN seq 91 permit 10.2.0.0/16", (NOOWN, "172.16.34.1"), 3),
    ("   seq 90 permit ::/0 le 128", (NODEF, "2001:db8:34::2"), 3),
    ("   seq 91 permit 2001:db8:2::/48", (NOOWN, "2001:db8:34::2"), 3),
])
def test_removing_one_dangerous_entry_removes_exactly_its_violation(needle, removed, kept):
    lines = (FIXTURES / "eos_r4_inbound_lists.txt").read_text(encoding="utf-8").split("\n")
    index = lines.index(needle)
    answer = mutant("security", LISTS, key_of(index, lines[index]))
    assert len(answer["violations"]) == kept
    assert not [v for v in answer["violations"] if v[1] == removed[0] and removed[1] in v[3]]


def test_removing_the_route_map_of_the_peer_group_removes_the_policy_violations_of_the_member():
    lines = (FIXTURES / "eos_r4_inbound_peergroup.txt").read_text(encoding="utf-8").split("\n")
    index = lines.index("   neighbor PG-TEST route-map RM-TEST-IN in")
    answer = mutant("security", GROUP, key_of(index, lines[index]))
    assert rule_ids(answer) == ["eos-ebgp-authentification-tcp-md5", "eos-ebgp-gtsm-ttl-maximum-hops",
                                "eos-ebgp-maximum-routes"]
