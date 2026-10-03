"""Règles de configuration SR Linux dans le driver (SPEC_v4, Phase A3b).

Trois choses à prouver : (1) les deux syntaxes de SR Linux, les accolades de « info from running » et
les lignes `set /` du fichier de démarrage, donnent le MÊME verdict ; (2) les règles vérifient la
présence et la référence d'une keychain, jamais la forme de la clé (en clair dans `config.cli`,
`$aes1$` sur l'équipement) ; (3) `parse_config` lit le texte du driver sans rien perdre ni décaler.
"""
import json
from pathlib import Path

import pytest

from netcheck import compliance, confparse
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import Rule

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
HARDENED = json.loads((FIXTURES / "r5_hardened" / "state.json").read_text(encoding="utf-8"))["running_config"]
SET_FILE = (REPO / "configs-multivendor" / "r5" / "config.cli").read_text(encoding="utf-8")
KINDS = ("srlinux_interface_mtu_margin", "srlinux_ospf_interface_type_point_to_point",
         "srlinux_ospf_authentication_required")


def rule(kind: str, **params) -> Rule:
    return Rule(id=kind, description="d", severity="haute", applies_to="all", kind=kind, params=params)


def device(text: str) -> DeviceState:
    return DeviceState(name="r5", host="-", timestamp="", reachable=True, running_config=text,
                       driver="srlinux")


def details(text: str, kind: str = "srlinux_ospf_authentication_required") -> list[str]:
    return [v.detail for v in compliance.check_one(rule(kind), device(text))]


KEYCHAIN_REFERENCE = ("                authentication {\n                    keychain kc-ospf-r4r5\n"
                      "                }\n")
assert KEYCHAIN_REFERENCE in HARDENED
AES_KEY = next(w for w in HARDENED.split() if w.startswith("$aes1$"))


# ------------------------------------------------------------------------------------------
# (1) Deux syntaxes, un verdict
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", KINDS)
def test_the_hardened_r5_is_compliant_in_both_syntaxes(kind):
    assert compliance.check_one(rule(kind), device(HARDENED)) == []     # accolades, clé en $aes1$
    assert compliance.check_one(rule(kind), device(SET_FILE)) == []     # fichier set, clé EN CLAIR


# Chaque variante : (nom, transformation de la forme à accolades, transformation de la forme set,
# détail attendu ou None si aucun constat).
VARIANTS = {
    "aucune référence de keychain": (
        lambda t: t.replace(KEYCHAIN_REFERENCE, ""),
        lambda t: "".join(line for line in t.splitlines(keepends=True)
                          if "authentication keychain" not in line),
        "sans authentification (aucune keychain référencée)"),
    "keychain référencée mais inexistante": (
        lambda t: t.replace("keychain kc-ospf-r4r5 {", "keychain autre {"),
        lambda t: t.replace("system authentication keychain kc-ospf-r4r5",
                            "system authentication keychain autre"),
        "introuvable sous /system authentication"),
    "keychain d'un autre type que ospf": (
        lambda t: t.replace("type ospf", "type isis"),
        lambda t: t.replace("type ospf", "type isis"),
        "qui n'est pas de type ospf"),
    "la forme de la clé change (clair <-> $aes1$)": (
        lambda t: t.replace(AES_KEY, "lab-ospf-r4r5"),
        lambda t: t.replace("lab-ospf-r4r5", "$aes1$AAAAAAAAAAA=$BBBBBBBBBBBBBBBBBBBBBB=="),
        None),
}


@pytest.mark.parametrize("name", VARIANTS)
def test_both_syntaxes_give_the_same_verdict_for_every_variant(name):
    brace, flat, expected = VARIANTS[name]
    from_braces = details(brace(HARDENED))
    from_set = details(flat(SET_FILE))
    assert from_braces == from_set, (from_braces, from_set)
    if expected is None:
        assert from_braces == []
    else:
        assert len(from_braces) == 1 and expected in from_braces[0]


def test_the_key_value_is_never_read_in_any_form():
    """Clair, `$aes1$`, vide ou absente : la règle ne lit pas la clé, seulement la keychain."""
    for value in ("lab-ospf-r4r5", AES_KEY, "x"):
        assert details(HARDENED.replace(AES_KEY, value)) == []
    without_key = HARDENED.replace(f"            authentication-key {AES_KEY}\n", "")
    # Comme la v0.3.0 : aucune clé n'est exigée DANS la keychain (amélioration prévue, phase E).
    assert without_key != HARDENED and details(without_key) == []


# ------------------------------------------------------------------------------------------
# (3) parse_config : trois formes, mêmes chemins, numéros de ligne du texte entier
# ------------------------------------------------------------------------------------------

def parse(text: str) -> confparse.ParsedConfig:
    return DRIVER_REGISTRY["srlinux"]().parse_config(text)


@pytest.mark.parametrize("dirname", ["r5", "r5_hardened"])
def test_real_srlinux_output_has_no_warning_and_every_line_is_counted(dirname):
    text = (FIXTURES / dirname / "running_config.txt").read_text(encoding="utf-8")   # section interface seule
    assert parse(text).warnings == []
    assert parse(HARDENED if dirname == "r5_hardened" else text).warnings == []
    cfg = parse(HARDENED)
    assert sum(cfg.counts.values()) == cfg.lines_total == len(HARDENED.splitlines())
    assert cfg.counts["comment"] == 4                       # les quatre marqueurs de section


def test_set_file_is_recognised_and_gives_paths_in_the_same_space_as_the_braces():
    cfg_set, cfg_braces = parse(SET_FILE), parse(HARDENED)
    assert cfg_set.syntax == "set" and cfg_braces.syntax == "braces" and cfg_set.warnings == []
    wanted = ("network-instance", "default", "protocols", "ospf", "instance", "main", "area", "0.0.0.0",
              "interface", "ethernet-1/1.0", "interface-type", "point-to-point")
    assert wanted in {f.path for f in cfg_set.flat} and wanted in {f.path for f in cfg_braces.flat}


def test_line_numbers_are_those_of_the_whole_text():
    cfg = parse(HARDENED)
    lines = HARDENED.splitlines()
    reference = cfg.select("network-instance", "default", "protocols", "ospf", "instance", "*", "area", "*",
                           "interface", "*", "authentication", "keychain", "*")
    assert len(reference) == 1
    assert lines[reference[0].line - 1].strip() == "keychain kc-ospf-r4r5"
    banner = cfg.select("system", "banner", "login-banner", "*")[0]
    assert lines[banner.line - 1].strip().startswith("login-banner ")


def test_an_unknown_section_is_read_under_a_marked_path_and_never_silently():
    text = "# --- interface ---\ninterface a {\n}\n# --- section d'un futur driver ---\nx y {\n z 1\n}\n"
    cfg = parse(text)
    assert [(w.line, w.kept) for w in cfg.warnings] == [(4, False)]
    assert ("?", "section d'un futur driver", "x", "y", "z", "1") in {f.path for f in cfg.flat}
    assert sum(cfg.counts.values()) == cfg.lines_total == 7


def test_unsectioned_braces_are_read_like_a_single_section():
    cfg = parse("interface ethernet-1/1 {\n    mtu 1514\n}\n")
    assert cfg.syntax == "braces"
    assert [f.path for f in cfg.flat] == [("interface", "ethernet-1/1", "mtu", "1514")]


def test_combine_shifts_line_numbers_and_adds_the_counts():
    a = confparse.parse_braces("a {\n b 1\n}\n")
    b = confparse.parse_braces("c d\n}\n", prefix=("p",))
    merged = confparse.combine([(a, 1), (b, 5)], lines_total=8, counts={"comment": 2})
    assert [(f.path, f.line) for f in merged.flat] == [(("a", "b", "1"), 3), (("p", "c", "d"), 6)]
    assert [(w.line, w.kept) for w in merged.warnings] == [(7, False)]
    assert merged.counts == {"blank": 0, "comment": 2, "node": 3, "close": 1, "raw": 0, "skipped": 1}
    assert merged.top("a") == []        # pas d'arbre après assemblage


# ------------------------------------------------------------------------------------------
# Écarts VOULUS avec la v0.3.0 (configurations aux accolades corrompues ; en attente de validation)
# ------------------------------------------------------------------------------------------

def test_an_unclosed_block_no_longer_hides_a_neighbour_interface_passive_flag():
    """v0.3.0 : un `}` supprimé faisait lire le `passive true` de l'interface SUIVANTE comme celui de
    ethernet-1/1.0, qui n'était alors plus signalée (faux négatif). Le nouveau lit la structure : seule
    la ligne lue sous le bon bloc compte."""
    unhardened = (FIXTURES / "r5" / "ospf_running_config.txt").read_text(encoding="utf-8")
    broken = unhardened.replace("                interface-type point-to-point\n            }\n",
                                "                interface-type point-to-point\n", 1)
    assert broken != unhardened
    text = "# --- network-instance default protocols ospf ---\n" + broken
    messages = details(text)
    assert len(messages) == 1 and "ethernet-1/1.0" in messages[0]
    # Et c'est signalé : la ligne est lue (la violation est trouvée) mais le verdict ne peut pas être
    # « conforme ».
    unclosed = [w for w in parse(text).warnings if "jamais fermé" in w.reason]
    assert unclosed and all(w.kept and w.blocks_verdict for w in unclosed)


def test_a_keychain_line_outside_authentication_is_not_an_authentication():
    """v0.3.0 acceptait une ligne `keychain X` n'importe où dans le bloc de l'interface. Le schéma vérifié
    sur l'équipement est `authentication { keychain X }` : sans l'enveloppe, la configuration est
    corrompue (accolade orpheline, signalée) et l'interface n'est pas authentifiée."""
    broken = HARDENED.replace("                authentication {\n", "", 1)
    messages = details(broken)
    assert len(messages) == 1 and "aucune keychain référencée" in messages[0]
    assert [w.reason for w in parse(broken).unclassified()] == ["accolade fermante sans bloc ouvert"]
