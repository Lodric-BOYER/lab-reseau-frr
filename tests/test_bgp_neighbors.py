"""Peer groups BGP, FRR et EOS (SPEC_v4, Phase A4) : la vue « voisin effectif ».

Les neuf configurations de tests/fixtures/peergroups/ sont des relevés EN DIRECT (r3 FRR 10.2.1, r4 cEOS
4.34.8M), avec des voisins fictifs sur 192.0.2.0/24 ; le README de ce dossier dit comment elles ont été
obtenues. Les variantes ci-dessous en sont dérivées ligne à ligne pour prouver que chaque cas n'est pas vide.

Ce que la v0.3.0 répondait sur ces relevés (mesuré avec son code, SPEC_v4 A4) : un groupe lu comme un voisin
(fausse violation sur un groupe sans membre), des membres jamais vus (faux « conforme » silencieux),
`remote-as external` ignoré. Les tests ci-dessous disent ce que le moteur répond maintenant.
"""
import re
from pathlib import Path

import pytest

from netcheck import compliance
from netcheck.drivers.bgp_neighbors import FRR_SYNTAX, BgpView
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import Rule

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "peergroups"

FRR_KINDS = ("bgp_neighbor_inbound_policy", "bgp_neighbor_outbound_policy", "bgp_neighbor_password_required",
             "bgp_neighbor_maximum_prefix_required", "bgp_neighbor_ttl_security_required",
             "bgp_neighbor_no_default_route_policy", "bgp_neighbor_no_own_prefixes_policy")
EOS_KINDS = ("eos_bgp_neighbor_password_required", "eos_bgp_neighbor_ttl_security_required",
             "eos_bgp_neighbor_maximum_routes_required")


def text(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text(encoding="utf-8")


def flagged(config: str, driver: str, kind: str) -> list[str]:
    """Les voisins (IP, ou réseau d'une plage) que cette règle signale, triés (l'ordre est testé à part)."""
    return sorted(re.match(r"voisin eBGP (\S+)", d).group(1) for d in details(config, driver, kind))


def details(config: str, driver: str, kind: str) -> list[str]:
    rule = Rule(id=kind, description="d", severity="haute", applies_to="all", kind=kind)
    state = DeviceState(name="r", host="-", timestamp="", reachable=True, running_config=config,
                        driver=driver)
    return [v.detail for v in compliance.check_one(rule, state)]


def drop(config: str, *prefixes: str) -> str:
    """La configuration sans la ligne qui commence par chacun de ces débuts (indentation ignorée) : une
    seule ligne doit correspondre. On donne le début sans la valeur (mot de passe), jamais la ligne
    entière."""
    out = config.splitlines()
    for prefix in prefixes:
        kept = [x for x in out if not x.strip().startswith(prefix)]
        assert len(out) - len(kept) == 1, f"{len(out) - len(kept)} ligne(s) pour {prefix!r}"
        out = kept
    return "\n".join(out) + "\n"


def replace(config: str, old: str, new: str) -> str:
    assert config.count(old) == 1, old
    return config.replace(old, new)


# ------------------------------------------------------------------------------------------
# Les relevés en direct : ce qui est signalé, voisin par voisin
# ------------------------------------------------------------------------------------------

_NONE = {kind: [] for kind in FRR_KINDS}
FRR_EXPECTED = {
    # S1 : le groupe porte tout, les deux membres en héritent : conforme, et ce n'est plus un faux
    # « conforme » par hasard (voir test_group_settings_are_really_inherited).
    "frr_s1_group": _NONE,
    # S2 : mot de passe, GTSM et limite surchargés sur les membres : conforme ; le groupe n'a pas de
    # route-map.
    "frr_s2_override": {**_NONE, "bgp_neighbor_inbound_policy": ["192.0.2.3", "192.0.2.4"],
                        "bgp_neighbor_outbound_policy": ["192.0.2.3", "192.0.2.4"]},
    # S3 : un groupe sans mot de passe : le MEMBRE est signalé, pas le groupe.
    "frr_s3_open_group": {**_NONE, **{k: ["192.0.2.5"] for k in FRR_KINDS[:5]}},
    # S4 : `remote-as external` voit 192.0.2.6 et le membre 192.0.2.8 (groupe external) ; `internal`
    # (192.0.2.7) est un voisin iBGP : jamais signalé. Avant, aucun des trois n'était vu.
    "frr_s4_external": {**_NONE, **{k: ["192.0.2.6", "192.0.2.8"] for k in FRR_KINDS[:5]}},
    # S5 : un groupe sans membre n'est pas un voisin : ni voisin fantôme ni violation.
    "frr_s5_orphan_group": _NONE,
    # S6 : plage dynamique dont le groupe porte tout : elle en hérite, rien n'est signalé.
    "frr_s6_listen_group": _NONE,
    # S7 : plage dynamique dont le groupe n'a pas de mot de passe : la PLAGE est signalée (avant : jamais
    # vue).
    "frr_s7_listen_open_group": {**_NONE, **{k: ["192.0.2.64/26"] for k in FRR_KINDS[:5]}},
}
EOS_NONE = {kind: [] for kind in EOS_KINDS}
EOS_EXPECTED = {
    "eos_s1_group": EOS_NONE,
    "eos_s2_override": EOS_NONE,
    "eos_s3_open_group": {kind: ["192.0.2.5"] for kind in EOS_KINDS},
    "eos_s5_orphan_group": EOS_NONE,
    "eos_s6_listen_group": EOS_NONE,
    "eos_s7_listen_open_group": {kind: ["192.0.2.64/26"] for kind in EOS_KINDS},
}


@pytest.mark.parametrize("name", sorted(FRR_EXPECTED))
def test_frr_live_captures(name):
    got = {kind: flagged(text(name), "frr", kind) for kind in FRR_KINDS}
    assert got == FRR_EXPECTED[name]


@pytest.mark.parametrize("name", sorted(EOS_EXPECTED))
def test_eos_live_captures(name):
    got = {kind: flagged(text(name), "eos", kind) for kind in EOS_KINDS}
    assert got == EOS_EXPECTED[name]


@pytest.mark.parametrize("name", sorted([*FRR_EXPECTED, *EOS_EXPECTED]))
def test_a_group_is_never_evaluated_for_itself(name):
    """Aucune règle ne nomme un groupe comme un voisin (c'était la fausse violation de la v0.3.0)."""
    driver = name.split("_")[0]
    for kind in FRR_KINDS if driver == "frr" else EOS_KINDS:
        assert not [d for d in details(text(name), driver, kind) if "eBGP PG-" in d]


@pytest.mark.parametrize("name", sorted([*FRR_EXPECTED, *EOS_EXPECTED]))
def test_live_captures_give_no_parser_warning(name):
    driver = name.split("_")[0]
    cfg = DRIVER_REGISTRY[driver]().parse_config(text(name))
    assert cfg.warnings == []
    assert sum(cfg.counts.values()) == cfg.lines_total


def test_a_member_is_named_with_its_group_in_the_finding():
    assert details(text("frr_s3_open_group"), "frr", "bgp_neighbor_password_required") == [
        "voisin eBGP 192.0.2.5 (peer group PG-OPEN) sans authentification TCP-MD5 (mot de passe)"]
    assert details(text("eos_s3_open_group"), "eos", "eos_bgp_neighbor_maximum_routes_required") == [
        "voisin eBGP 192.0.2.5 (peer group PG-OPEN) sans limite maximum-routes"]
    # Une plage dynamique relevée en direct : nommée avec son réseau et son groupe.
    assert details(text("frr_s7_listen_open_group"), "frr", "bgp_neighbor_password_required") == [
        "voisin eBGP 192.0.2.64/26 (plage dynamique, peer group PG-DYNOPEN) "
        "sans authentification TCP-MD5 (mot de passe)"]
    assert details(text("eos_s7_listen_open_group"), "eos", "eos_bgp_neighbor_ttl_security_required") == [
        "voisin eBGP 192.0.2.64/26 (plage dynamique, peer group PG-DYNOPEN) sans GTSM (ttl maximum-hops)"]


def test_a_neighbor_outside_any_group_keeps_the_v030_message():
    """Le message d'un voisin isolé n'a pas changé d'un mot (le gel le compare sur les vraies configs)."""
    config = drop(text("frr_s1_group"), "neighbor 172.16.34.2 password")
    assert details(config, "frr", "bgp_neighbor_password_required") == [
        "voisin eBGP 172.16.34.2 sans authentification TCP-MD5 (mot de passe)"]


# ------------------------------------------------------------------------------------------
# Variantes : chaque cas prouve qu'il n'est pas vide
# ------------------------------------------------------------------------------------------

def test_group_settings_are_really_inherited():
    """S1 est conforme PARCE QUE les membres héritent : sans le mot de passe du groupe, les deux membres, et
    seulement eux, sont signalés. Idem pour le GTSM et la limite, sur FRR comme sur EOS."""
    frr = text("frr_s1_group")
    cases = [("neighbor PG-TEST password", "bgp_neighbor_password_required"),
             ("neighbor PG-TEST ttl-security hops", "bgp_neighbor_ttl_security_required"),
             ("neighbor PG-TEST maximum-prefix", "bgp_neighbor_maximum_prefix_required"),
             ("neighbor PG-TEST route-map RM-EBGP-IN in", "bgp_neighbor_inbound_policy"),
             ("neighbor PG-TEST route-map RM-EBGP-OUT out", "bgp_neighbor_outbound_policy")]
    for line, kind in cases:
        assert flagged(drop(frr, line), "frr", kind) == ["192.0.2.1", "192.0.2.2"], line
    eos = text("eos_s1_group")
    cases = [("neighbor PG-TEST password", "eos_bgp_neighbor_password_required"),
             ("neighbor PG-TEST ttl maximum-hops", "eos_bgp_neighbor_ttl_security_required"),
             ("neighbor PG-TEST maximum-routes", "eos_bgp_neighbor_maximum_routes_required")]
    for line, kind in cases:
        assert flagged(drop(eos, line), "eos", kind) == ["192.0.2.1", "192.0.2.2"], line


def test_an_override_on_the_member_masks_the_group():
    # FRR S2 : sans la surcharge du membre, il retombe sur le mot de passe du groupe : toujours conforme.
    frr = text("frr_s2_override")
    assert flagged(drop(frr, "neighbor 192.0.2.3 password"), "frr", "bgp_neighbor_password_required") == []
    # ... et sans la surcharge NI le groupe, les deux membres sont signalés.
    both = drop(frr, "neighbor 192.0.2.3 password", "neighbor PG-OVR password")
    assert flagged(both, "frr", "bgp_neighbor_password_required") == ["192.0.2.3", "192.0.2.4"]
    # EOS : `maximum-routes 0` (illimité) posé sur le membre masque la limite de 10 du groupe.
    eos = replace(text("eos_s2_override"), "neighbor 192.0.2.4 maximum-routes 20",
                  "neighbor 192.0.2.4 maximum-routes 0")
    assert details(eos, "eos", "eos_bgp_neighbor_maximum_routes_required") == [
        "voisin eBGP 192.0.2.4 (peer group PG-OVR) : maximum-routes 0 (illimité) n'est pas une limite"]
    # FRR : la ligne du membre est jugée seule, comme celle d'un voisin isolé (la règle exige une limite
    # `maximum-prefix N` sans option : `warning-only` n'en est pas une) ; elle ne se « complète » pas avec
    # la limite valide du groupe.
    warn = replace(text("frr_s1_group"), "  neighbor 172.16.34.2 maximum-prefix 10\n",
                   "  neighbor 172.16.34.2 maximum-prefix 10\n"
                   "  neighbor 192.0.2.1 maximum-prefix 10 warning-only\n")
    assert flagged(warn, "frr", "bgp_neighbor_maximum_prefix_required") == ["192.0.2.1"]
    # FRR : une politique propre au membre masque celle du groupe.
    frr1 = replace(text("frr_s1_group"), " neighbor 172.16.34.2 maximum-prefix 10\n",
                   " neighbor 172.16.34.2 maximum-prefix 10\n  neighbor 192.0.2.1 route-map RM-AUTRE in\n")
    assert _route_map_in(frr1, "192.0.2.1") == "RM-AUTRE"
    assert _route_map_in(frr1, "192.0.2.2") == "RM-EBGP-IN"


def _route_map_in(config: str, ip: str) -> str | None:
    from netcheck.drivers import frr_rules
    cfg = DRIVER_REGISTRY["frr"]().parse_config(config)
    return frr_rules._route_map_in_name(frr_rules._bgp(cfg), ip)


def test_membership_does_not_depend_on_the_order_of_the_lines():
    """Les membres déclarés AVANT le groupe sont lus de la même façon (rien n'impose l'ordre dans un
    fichier écrit à la main)."""
    config = text("frr_s3_open_group")
    member = " neighbor 192.0.2.5 peer-group PG-OPEN"
    assert member in config
    moved = replace(drop(config, member.strip()), " neighbor PG-OPEN peer-group\n",
                    member + "\n neighbor PG-OPEN peer-group\n")
    assert flagged(moved, "frr", "bgp_neighbor_password_required") == ["192.0.2.5"]


def test_a_group_whose_as_is_the_local_as_makes_ibgp_members():
    """Un groupe iBGP : ses membres ne sont pas des voisins eBGP, rien n'est exigé d'eux."""
    config = replace(text("frr_s3_open_group"), "neighbor PG-OPEN remote-as 65099",
                     "neighbor PG-OPEN remote-as 65001")
    assert all(flagged(config, "frr", kind) == [] for kind in FRR_KINDS)
    config = replace(text("eos_s3_open_group"), "neighbor PG-OPEN remote-as 65099",
                     "neighbor PG-OPEN remote-as 65002")
    assert all(flagged(config, "eos", kind) == [] for kind in EOS_KINDS)


def test_a_member_without_any_known_as_opens_no_session_and_is_not_evaluated():
    config = replace(text("frr_s3_open_group"), " neighbor PG-OPEN remote-as 65099\n", "")
    assert all(flagged(config, "frr", kind) == [] for kind in FRR_KINDS)


def test_a_member_with_its_own_remote_as_uses_it():
    """Un membre qui porte son propre `remote-as` (iBGP) l'emporte sur celui de son groupe (eBGP)."""
    config = replace(text("frr_s3_open_group"), " neighbor 192.0.2.5 peer-group PG-OPEN\n",
                     " neighbor 192.0.2.5 peer-group PG-OPEN\n neighbor 192.0.2.5 remote-as 65001\n")
    assert flagged(config, "frr", "bgp_neighbor_password_required") == []


def test_remote_as_external_and_internal_are_frr_only():
    """FRR : `external` désigne un voisin eBGP, `internal` un voisin iBGP. EOS répond `% Invalid input` aux
    deux (relevé sur cEOS 4.34.8M) : ce n'est pas un AS, la ligne ne désigne aucun voisin."""
    frr = text("frr_s4_external")
    assert "neighbor 192.0.2.6 remote-as external" in frr and "neighbor 192.0.2.7 remote-as internal" in frr
    assert flagged(frr, "frr", "bgp_neighbor_password_required") == ["192.0.2.6", "192.0.2.8"]
    eos = replace(text("eos_s1_group"), "   neighbor 172.16.34.1 remote-as 65001\n",
                  "   neighbor 172.16.34.1 remote-as 65001\n   neighbor 192.0.2.9 remote-as external\n")
    assert flagged(eos, "eos", "eos_bgp_neighbor_password_required") == []


def test_dynamic_neighbor_ranges_are_neighbors_inheriting_from_their_group():
    """`bgp listen range` crée des sessions sans ligne `neighbor <ip>` : la plage est un voisin eBGP virtuel,
    évalué avec les réglages de son groupe. Relevé en direct (S6, S7) : FRR écrit `bgp listen range <réseau>
    peer-group <groupe>` ; EOS exige `remote-as` sur la ligne même (`% Incomplete command` sinon, constaté)
    et déclare `bgp listen limit` obsolète. Ces variantes dérivent des relevés pour d'autres réseaux."""
    frr = replace(text("frr_s3_open_group"), " neighbor 192.0.2.5 peer-group PG-OPEN\n",
                  " neighbor 192.0.2.5 peer-group PG-OPEN\n"
                  " bgp listen range 198.51.100.0/24 peer-group PG-OPEN\n")
    assert flagged(frr, "frr", "bgp_neighbor_password_required") == ["192.0.2.5", "198.51.100.0/24"]
    assert [d for d in details(frr, "frr", "bgp_neighbor_password_required") if "198.51" in d] == [
        "voisin eBGP 198.51.100.0/24 (plage dynamique, peer group PG-OPEN) "
        "sans authentification TCP-MD5 (mot de passe)"]
    # Un groupe complet : la plage hérite de tout, rien n'est signalé.
    complete = replace(text("frr_s1_group"), " neighbor 192.0.2.2 peer-group PG-TEST\n",
                       " neighbor 192.0.2.2 peer-group PG-TEST\n"
                       " bgp listen range 198.51.100.0/24 peer-group PG-TEST\n")
    assert all(flagged(complete, "frr", kind) == [] for kind in FRR_KINDS)
    # EOS : le `remote-as` de la ligne de la plage (EOS l'exige) fait foi ; le groupe S5 a un mot de
    # passe mais ni GTSM ni limite. Une plage iBGP (même AS que le routeur) n'est pas un voisin eBGP.
    eos = replace(text("eos_s5_orphan_group"), "   neighbor PG-ORPHAN remote-as 65099\n",
                  "   neighbor PG-ORPHAN remote-as 65099\n"
                  "   bgp listen range 198.51.100.0/24 peer-group PG-ORPHAN remote-as 65099\n")
    assert flagged(eos, "eos", "eos_bgp_neighbor_password_required") == []
    assert flagged(eos, "eos", "eos_bgp_neighbor_ttl_security_required") == ["198.51.100.0/24"]
    ibgp = eos.replace("peer-group PG-ORPHAN remote-as 65099\n", "peer-group PG-ORPHAN remote-as 65002\n")
    assert flagged(ibgp, "eos", "eos_bgp_neighbor_ttl_security_required") == []


def test_the_view_reads_neighbors_in_the_order_of_the_configuration():
    cfg = DRIVER_REGISTRY["frr"]().parse_config(text("frr_s4_external"))
    view = BgpView(cfg.top("router", "bgp", "*")[0], FRR_SYNTAX)
    # Ordre de la configuration : le membre (ligne `peer-group`), le voisin réel, puis `external`.
    assert view.ebgp == ["192.0.2.8", "172.16.34.2", "192.0.2.6"]
    assert view.label("192.0.2.8") == "192.0.2.8 (peer group PG-EXTERN)"
    assert view.label("172.16.34.2") == "172.16.34.2"
    # Un voisin isolé (hors groupe) est lu exactement comme avant : une entrée par `remote-as` d'un autre AS.
    cfg = DRIVER_REGISTRY["frr"]().parse_config(text("frr_s5_orphan_group"))
    assert BgpView(cfg.top("router", "bgp", "*")[0], FRR_SYNTAX).ebgp == ["172.16.34.2"]


def test_end_to_end_through_the_engine_with_the_real_rules():
    """Le chemin complet : règles réelles, moteur, constats ; l'ordre et le libellé sont ceux des rapports."""
    rules = compliance.load_rules(REPO / "netcheck" / "rules" / "security.yml")
    state = DeviceState(name="r3", host="-", timestamp="", reachable=True, driver="frr",
                        running_config=text("frr_s3_open_group"))
    result = compliance.evaluate_config(rules, {"r3": state})
    flagged_rules = {v.rule.id: v.detail for v in result.violations}
    assert flagged_rules["ebgp-authentification-tcp-md5"] == (
        "voisin eBGP 192.0.2.5 (peer group PG-OPEN) sans authentification TCP-MD5 (mot de passe)")
    assert result.config_warnings == []
