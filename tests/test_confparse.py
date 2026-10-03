"""Tests de confparse (SPEC_v4, Phase A, étape A2).

Trois familles : (1) des configurations RÉELLES (fixtures, configurations de démarrage des labs,
sortie « info from running » du r5 durci) qui doivent se lire sans le moindre avertissement ;
(2) chaque forme douteuse, qui doit être SIGNALÉE (jamais ignorée en silence), avec des entrées
synthétiques clairement identifiées comme telles ; (3) des propriétés : chaque ligne de la source
tombe dans exactement une classe, quelles que soient les mutations, et le module ne contient aucun
mot-clé constructeur.
"""
import ast
import re
from pathlib import Path

import pytest

from netcheck import confparse as cp

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
INPUTS = REPO / "tests" / "golden" / "inputs"

# Syntaxe par indentation : FRR (running-config et fichier de démarrage) et EOS.
INDENT_SOURCES = [
    *(FIXTURES / r / "running_config.txt" for r in ("r1", "r3", "r4")),
    *sorted(INPUTS.glob("frr_*.conf")),
    *sorted((FIXTURES / "ceos").glob("*/running_config.txt")),
    INPUTS / "eos_r4.startup-config",
]
# SR Linux « info from running » : sortie relative au chemin demandé (cf. driver srlinux).
SRL_SECTIONS = {
    "running_config.txt": (),
    "ospf_running_config.txt": ("network-instance", "default", "protocols", "ospf"),
    "system_authentication.txt": ("system", "authentication"),
    "system_banner.txt": ("system", "banner"),
}
SRL_FILES = [(d, name, prefix) for d in ("r5", "r5_hardened") for name, prefix in SRL_SECTIONS.items()]
SET_FILE = REPO / "configs-multivendor" / "r5" / "config.cli"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def srlinux(dirname: str, name: str, prefix) -> cp.ParsedConfig:
    return cp.parse_braces(read(FIXTURES / dirname / name), prefix=prefix)


def assert_every_line_counted(parsed: cp.ParsedConfig) -> None:
    assert sum(parsed.counts.values()) == parsed.lines_total, (parsed.counts, parsed.lines_total)
    assert parsed.counts["skipped"] == len(parsed.unclassified())


# ------------------------------------------------------------------------------------------
# (1) Configurations réelles : aucune ligne douteuse
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", INDENT_SOURCES, ids=lambda p: "/".join(p.parts[-3:]))
def test_real_indented_configs_parse_without_any_warning(path):
    parsed = cp.parse_indented(read(path))
    assert parsed.warnings == [], [str(w) for w in parsed.warnings]
    assert parsed.counts["node"] > 20
    assert_every_line_counted(parsed)


@pytest.mark.parametrize(("dirname", "name", "prefix"), SRL_FILES, ids=lambda v: str(v))
def test_real_srlinux_sections_parse_without_any_warning(dirname, name, prefix):
    parsed = srlinux(dirname, name, prefix)
    assert parsed.warnings == []
    assert_every_line_counted(parsed)


def test_real_set_file_parses_without_any_warning():
    parsed = cp.parse_set(read(SET_FILE))
    assert parsed.warnings == []
    assert parsed.counts["node"] == 31 and parsed.lines_total == 31
    assert_every_line_counted(parsed)


# ------------------------------------------------------------------------------------------
# Structure lue sur des données réelles
# ------------------------------------------------------------------------------------------

def test_frr_blocks_and_nested_address_family():
    parsed = cp.parse_indented(read(INPUTS / "frr_r3.conf"))
    (bgp,) = parsed.top("router", "bgp", "*")
    assert bgp.words == ("router", "bgp", "65001")
    (family,) = bgp.children_matching("address-family", "ipv4", "unicast")
    limits = family.children_matching("neighbor", "172.16.34.2", "maximum-prefix")
    assert [c.text for c in limits] == ["neighbor 172.16.34.2 maximum-prefix 10"]
    # Les lignes de niveau « neighbor » sont des enfants directs de router bgp, pas de la famille.
    assert bgp.children_matching("neighbor", "172.16.34.2", "ttl-security")
    assert not family.children_matching("neighbor", "172.16.34.2", "ttl-security")
    assert limits[0].path() == ("router", "bgp", "65001", "address-family", "ipv4", "unicast",
                                "neighbor", "172.16.34.2", "maximum-prefix", "10")


def test_eos_comment_inside_a_block_does_not_change_the_structure():
    """`   !` apparaît DANS « router multicast » : un commentaire ne referme ni n'ouvre rien."""
    parsed = cp.parse_indented(read(FIXTURES / "ceos" / "r4" / "running_config.txt"))
    (multicast,) = parsed.top("router", "multicast")
    assert [c.words for c in multicast.children] == [("ipv4",), ("ipv6",)]
    assert [c.words for c in multicast.children[0].children] == [("software-forwarding", "kernel")]
    (ospf,) = parsed.top("router", "ospf", "*")
    assert ospf.children_matching("passive-interface", "Ethernet1")


def test_flat_view_of_an_indented_config_selects_by_pattern():
    parsed = cp.parse_indented(read(FIXTURES / "ceos" / "r4" / "running_config.txt"))
    auth = parsed.select("interface", "*", "ip", "ospf", "authentication")
    assert [f.path[1] for f in auth] == ["Ethernet2"]
    # Un motif peut être une expression régulière (correspondance complète du mot).
    loops = parsed.select("interface", re.compile(r"Loopback\d+"), "ip", "address")
    assert [f.path[-1] for f in loops] == ["10.2.255.4/32"]


def test_srlinux_flat_view_with_prefix_empty_block_and_quoted_string():
    cfg = srlinux("r5_hardened", "running_config.txt", ())
    assert ("interface", "ethernet-1/1", "subinterface", "0", "ipv4", "address", "10.2.45.2/30") in {
        f.path for f in cfg.flat}, "un bloc vide `address X {}` est une ligne feuille"
    ospf = srlinux("r5_hardened", "ospf_running_config.txt", SRL_SECTIONS["ospf_running_config.txt"])
    keychain = ospf.select("network-instance", "default", "protocols", "ospf", "instance", "*", "area", "*",
                           "interface", "*", "authentication", "keychain", "kc-ospf-r4r5")
    assert len(keychain) == 1
    banner = srlinux("r5_hardened", "system_banner.txt", ("system", "banner")).flat
    assert len(banner) == 1 and banner[0].path[:3] == ("system", "banner", "login-banner")
    assert banner[0].path[3].startswith("Acces reserve") and '"' not in banner[0].path[3]


def test_set_and_braces_give_the_same_paths_on_the_real_r5():
    """Le fichier de démarrage (`set /`) et la configuration relevée sur le lab (accolades) décrivent
    le même équipement : chaque ligne `set` doit se retrouver à l'identique dans la sortie à accolades,
    aux quatre exceptions près, TOUTES expliquées (aucune n'est un défaut de l'analyse)."""
    running = set()
    for name, prefix in SRL_SECTIONS.items():
        running |= {f.path for f in srlinux("r5_hardened", name, prefix).flat}
    missing = [f for f in cp.parse_set(read(SET_FILE)).flat if f.path not in running]
    explained = [f for f in missing if f.path[:3] == ("network-instance", "default", "interface")]
    # (a) la branche « network-instance default interface » n'est pas collectée par le driver.
    assert len(explained) == 3
    # (b) la clé OSPF : en clair dans le fichier, obscurcie par la plateforme dans la configuration
    #     relevée -- même chemin, seule la valeur change.
    (key,) = [f for f in missing if f not in explained]
    assert key.path[-2] == "authentication-key" and key.path[-1] == "lab-ospf-r4r5"
    obscured = [p for p in running if p[:-1] == key.path[:-1]]
    assert len(obscured) == 1 and obscured[0][-1].startswith("$aes1$")


# ------------------------------------------------------------------------------------------
# (2) Formes douteuses : toujours signalées (entrées SYNTHÉTIQUES, non observées sur les labs)
# ------------------------------------------------------------------------------------------

def reasons(parsed: cp.ParsedConfig) -> list[tuple[int, bool, str]]:
    return [(w.line, w.kept, w.reason.split(" :")[0]) for w in parsed.warnings]


def test_indented_partial_dedent_is_flagged_and_attached_to_the_nearest_block():
    parsed = cp.parse_indented("a\n   b\n      c\n    d\n")
    assert reasons(parsed) == [(4, True, "dédentation partielle")]
    (a,) = parsed.top("a")
    (b,) = a.children
    assert [c.words for c in b.children] == [("c",), ("d",)]   # d rattaché à b, pas perdu
    assert_every_line_counted(parsed)


def test_indented_tab_leading_indent_and_unclosed_quote_and_braces_are_flagged():
    assert reasons(cp.parse_indented("a\n\tb\n")) == [
        (2, True, "tabulation dans l'indentation (comptée pour 8 colonnes)")]
    assert reasons(cp.parse_indented("  a\nb\n")) == [(1, True, "ligne indentée sans bloc parent")]
    assert reasons(cp.parse_indented('description "non fermé\n')) == [(1, True, "guillemet non fermé")]
    flagged = cp.parse_indented("interface x {\n}\n")
    assert [w.line for w in flagged.warnings] == [1, 2] and all(w.kept for w in flagged.warnings)


def test_indented_raw_block_keeps_free_text_unparsed():
    """Forme synthétique : aucune bannière multi-lignes n'existe dans les configurations réelles du
    dépôt. Le driver déclare où commence et finit le texte libre ; sans cette déclaration, ses lignes
    seraient lues comme des commandes (et un « ! » ou « { » dans le texte ne gênerait pas ici)."""
    text = "banner login\n   Texte libre ! avec { accolade\n   deuxième ligne\nEOF\nhostname r1\n"
    parsed = cp.parse_indented(text, raw_blocks=((r"banner login", r"EOF"),))
    assert parsed.warnings == []
    assert parsed.counts == {"blank": 0, "comment": 0, "node": 2, "close": 0, "raw": 3, "skipped": 0}
    (banner,) = parsed.top("banner", "login")
    assert len(banner.raw) == 2 and banner.children == []
    assert [f.path for f in parsed.flat] == [("banner", "login"), ("hostname", "r1")]
    unterminated = cp.parse_indented("banner login\n   texte\n", raw_blocks=((r"banner login", r"EOF"),))
    assert reasons(unterminated) == [(1, True, "bloc brut jamais terminé")]
    assert_every_line_counted(unterminated)


def test_braces_unrecognised_forms_are_skipped_and_reported():
    text = "\n".join([
        "a {",                      # 1 ouvre
        "    b 1",                  # 2 feuille
        "    c { }",                # 3 `{ }` sur une ligne : forme non observée
        "    d { e",                # 4 accolade au milieu
        '    f "non fermé',         # 5 guillemet
        "}",                        # 6 referme a
        "}",                        # 7 sans bloc ouvert
        'g "a { b }"',              # 8 accolades entre guillemets : une simple chaîne, valide
        "h {",                      # 9 jamais refermé
    ])
    parsed = cp.parse_braces(text)
    assert reasons(parsed) == [
        (3, False, "accolade dans une position non reconnue"),
        (4, False, "accolade dans une position non reconnue"),
        (5, False, "guillemet non fermé"),
        (7, False, "accolade fermante sans bloc ouvert"),
        (9, True, "bloc ouvert jamais fermé"),
    ]
    assert parsed.counts["skipped"] == 4 and len(parsed.unclassified()) == 4
    assert [f.path for f in parsed.flat] == [("a", "b", "1"), ("g", "a { b }"), ("h",)]
    assert_every_line_counted(parsed)


def test_braces_prefix_and_comments():
    text = "# --- marqueur ---\nkeychain k {\n    type ospf\n}\n"
    parsed = cp.parse_braces(text, prefix=("system", "authentication"))
    assert parsed.warnings == [] and parsed.counts["comment"] == 1
    assert [f.path for f in parsed.flat] == [("system", "authentication", "keychain", "k", "type", "ospf")]


def test_set_lines_that_are_not_converted_are_all_reported():
    text = "\n".join([
        "# commentaire",                              # 1
        "",                                           # 2 vide
        "set / a b c",                                # 3 converti
        "set /d e",                                   # 4 converti (chemin collé)
        'set / f description "deux mots"',            # 5 converti, chaîne = un seul mot
        "delete / a b",                               # 6 autre commande
        "commit now",                                 # 7 autre commande
        "set a b",                                    # 8 chemin relatif
        "set /",                                      # 9 chemin vide
        'set / g "non fermé',                         # 10 guillemet
    ])
    parsed = cp.parse_set(text)
    assert [f.path for f in parsed.flat] == [("a", "b", "c"), ("d", "e"), ("f", "description", "deux mots")]
    assert reasons(parsed) == [
        (6, False, "commande autre que « set / »"),
        (7, False, "commande autre que « set / »"),
        (8, False, "commande set sans chemin absolu (contexte de navigation inconnu)"),
        (9, False, "chemin vide après « set / »"),
        (10, False, "guillemet non fermé"),
    ]
    assert parsed.counts == {"blank": 1, "comment": 1, "node": 3, "close": 0, "raw": 0, "skipped": 5}
    assert_every_line_counted(parsed)


def test_a_warning_never_carries_a_secret():
    parsed = cp.parse_set("set neighbor 10.0.0.1 password lab-bgp-r3r4\n")
    (warning,) = parsed.warnings
    assert "lab-bgp-r3r4" not in str(warning) and "****" in warning.text
    long = cp.parse_set("commit " + "x" * 300)
    assert len(long.warnings[0].text) <= 103


def test_dispatcher_and_unknown_syntax():
    assert cp.parse("a\n b\n", "indent").syntax == "indent"
    assert cp.parse("a {\n}\n", "braces", prefix=("p",)).flat[0].path == ("p", "a")
    with pytest.raises(ValueError, match="syntaxe de configuration inconnue"):
        cp.parse("a", "junos")


def test_pattern_matching_wildcards_and_prefixes():
    parsed = cp.parse_indented("router bgp 65001\n neighbor 10.0.0.1 remote-as 65002\n")
    (bgp,) = parsed.top("router", "bgp", "*")
    assert bgp.children_matching("neighbor", "*", "remote-as")
    assert not bgp.children_matching("neighbor", "*", "remote-as", "1")
    assert not bgp.children_matching("neighbor", "10.9.9.9")
    assert parsed.top("router") == [bgp] and parsed.top("router", "ospf") == []


# ------------------------------------------------------------------------------------------
# (3) Propriétés
# ------------------------------------------------------------------------------------------

_GARBAGE = ["}", "{", '"', "\t x", "  }", "x {", "set", "} {", "a { b", 'q "z']


def _mutations(text: str):
    lines = text.splitlines()
    for i in range(len(lines)):
        yield "\n".join(lines[:i] + lines[i + 1:])                       # suppression
        yield "\n".join(lines[:i + 1] + [lines[i]] + lines[i + 1:])      # duplication
        yield "\n".join(lines[:i] + [" " + lines[i]] + lines[i + 1:])    # indentation perturbée
        for junk in _GARBAGE:
            yield "\n".join(lines[:i + 1] + [junk] + lines[i + 1:])      # ligne parasite


def _all_real_inputs():
    for path in INDENT_SOURCES:
        yield "indent", read(path), {}
    for dirname, name, prefix in SRL_FILES:
        yield "braces", read(FIXTURES / dirname / name), {"prefix": prefix}
    yield "set", read(SET_FILE), {}


def test_every_source_line_lands_in_exactly_one_class_under_mutation():
    """Aucune exception et aucune ligne perdue, même sur des entrées corrompues : la somme des
    classes vaut toujours le nombre de lignes, et les lignes « skipped » sont toutes signalées."""
    checked = 0
    for syntax, text, options in _all_real_inputs():
        for mutated in _mutations(text):
            parsed = cp.parse(mutated, syntax, **options)
            assert_every_line_counted(parsed)
            assert all(1 <= w.line <= parsed.lines_total for w in parsed.warnings)
            checked += 1
    assert checked > 10000


def test_confparse_contains_no_vendor_keyword():
    """Neutralité : aucune chaîne du code (hors docstrings) ne nomme un protocole, une interface, un
    voisin ou un secret. Ce qui est propre à un équipement est passé en paramètre par son driver."""
    tree = ast.parse((REPO / "netcheck" / "confparse.py").read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    forbidden = re.compile(
        r"neighbor|route-map|prefix-list|bgp|ospf|router|interface|keychain|password|secret|banner|"
        r"ttl|remote-as|maximum|vrf|frr|srlinux|eos|arista|nokia|cisco", re.IGNORECASE)
    offenders = [n.value for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
                 and forbidden.search(n.value)]
    assert offenders == []
