"""Hors ligne = direct, sur les règles de configuration, pour les trois labs (SPEC_v4, Phase A5).

Le fichier de démarrage (écrit à la main : `configs/`, `configs-multivendor/`, `configs-ceos/`) et la
configuration en cours d'exécution (formatée par l'équipement, relevée sur un lab démarré à froid :
`tests/fixtures/live_dualstack/`, relevés en double pile) n'ont pas la même forme. Les règles de
configuration doivent pourtant répondre pareil, constat par constat, que le lab soit conforme ou dégradé.
Les règles qui lisent le MODÈLE (interfaces) sont exclues de la comparaison : hors ligne, elles sont non
évaluables (`test_config_dir.py`), et les fixtures n'ont de toute façon pas de modèle.
"""
from pathlib import Path

import pytest

from netcheck import compliance, configdir
from netcheck.model import DeviceState

REPO = Path(__file__).resolve().parent.parent
LIVE = REPO / "tests" / "fixtures" / "live_dualstack"
RULES = {name: compliance.load_rules(REPO / "netcheck" / "rules" / f"{name}.yml")
         for name in ("default", "security")}
STATE_KINDS = {"ospf_passive_on_interfaces", "interface_description_required"}
R5_LIVE = (LIVE / "srl_r5.txt").read_text(encoding="utf-8")
INVENTORIES = {
    "frr": ("inventory.yml", ["configs"], {}),
    "mixte": ("inventory-multivendor.yml", ["configs", "configs-multivendor"], {"r5": "srlinux"}),
    "ceos": ("inventory-ceos.yml", ["configs", "configs-ceos"], {"r4": "eos"}),
}


def live_state(name: str, driver: str, text: str) -> DeviceState:
    return DeviceState(name=name, host="-", timestamp="", reachable=True, running_config=text, driver=driver)


def live_lab(lab: str) -> dict[str, DeviceState]:
    devices = {r: live_state(r, "frr", (LIVE / f"frr_{r}.txt").read_text(encoding="utf-8"))
               for r in ("r1", "r2", "r3", "r4", "r5")}
    if lab == "mixte":
        devices["r5"] = live_state("r5", "srlinux", R5_LIVE)
    if lab == "ceos":
        devices["r4"] = live_state("r4", "eos", (LIVE / "eos_r4.txt").read_text(encoding="utf-8"))
    return devices


def offline_lab(lab: str, edit=None, tmp_path: Path | None = None) -> dict[str, DeviceState]:
    """Les fichiers de démarrage du lab, lus par `configdir` (éventuellement après une modification)."""
    inventory, dirs, drivers = INVENTORIES[lab]
    import yaml
    inv = yaml.safe_load((REPO / "automation" / inventory).read_text(encoding="utf-8"))["routers"]
    names = {n: (a or {}).get("driver", "frr") for n, a in inv.items()}
    loaded = configdir.load([REPO / d for d in dirs], names)
    assert not [w for w in loaded.warnings if w.blocks_verdict]
    return loaded.devices


def findings(devices: dict[str, DeviceState], rules_name: str) -> list[tuple[str, str, str]]:
    rules = [r for r in RULES[rules_name]
             if r.kind not in STATE_KINDS]
    result = compliance.evaluate_config(rules, devices)
    return sorted((v.rule.id, v.device, v.detail) for v in result.violations)


@pytest.mark.parametrize("rules_name", sorted(RULES))
@pytest.mark.parametrize("lab", sorted(INVENTORIES))
def test_a_compliant_lab_gives_the_same_answer_offline_and_live(lab, rules_name):
    offline, live = offline_lab(lab), live_lab(lab)
    assert sorted(offline) == sorted(live) == ["r1", "r2", "r3", "r4", "r5"]
    assert [offline[n].driver for n in sorted(offline)] == [live[n].driver for n in sorted(live)]
    assert findings(offline, rules_name) == findings(live, rules_name) == []


def drop(device: DeviceState, needle: str) -> DeviceState:
    """Le même défaut injecté dans la configuration : toutes les lignes qui contiennent `needle` (une au
    moins)."""
    lines = device.running_config.splitlines(keepends=True)
    kept = [x for x in lines if needle not in x]
    assert len(kept) < len(lines), (device.name, needle)
    return DeviceState(**{**device.__dict__, "running_config": "".join(kept)})


# Défauts qui doivent produire LE MÊME constat hors ligne et en direct : (lab, équipement, texte retiré,
# kind).
# Le texte retiré se retrouve dans le fichier de démarrage ET dans la configuration en cours d'exécution.
DEGRADATIONS = [
    ("frr", "r3", "neighbor 172.16.34.2 password", "bgp_neighbor_password_required"),
    ("frr", "r3", "neighbor 172.16.34.2 ttl-security", "bgp_neighbor_ttl_security_required"),
    ("frr", "r3", "neighbor 172.16.34.2 maximum-prefix", "bgp_neighbor_maximum_prefix_required"),
    ("frr", "r3", "neighbor 2001:db8:34::3 password", "bgp_neighbor_password_required"),
    ("frr", "r3", "neighbor 2001:db8:34::3 ttl-security", "bgp_neighbor_ttl_security_required"),
    ("frr", "r3", "neighbor 2001:db8:34::3 maximum-prefix", "bgp_neighbor_maximum_prefix_required"),
    ("frr", "r1", "ip ospf authentication", "ospf_authentication_required"),
    ("ceos", "r4", "neighbor 172.16.34.1 maximum-routes", "eos_bgp_neighbor_maximum_routes_required"),
    ("ceos", "r4", "neighbor 172.16.34.1 ttl maximum-hops", "eos_bgp_neighbor_ttl_security_required"),
    ("ceos", "r4", "neighbor 172.16.34.1 password", "eos_bgp_neighbor_password_required"),
    ("ceos", "r4", "neighbor 2001:db8:34::2 password", "eos_bgp_neighbor_password_required"),
    ("ceos", "r4", "neighbor 2001:db8:34::2 maximum-routes", "eos_bgp_neighbor_maximum_routes_required"),
    ("mixte", "r5", "login-banner", "srlinux_login_banner_present"),
]


@pytest.mark.parametrize("lab, device, needle, kind", DEGRADATIONS,
                         ids=[f"{d[3]}@{d[1]}" for d in DEGRADATIONS])
def test_the_same_defect_gives_the_same_finding_offline_and_live(lab, device, needle, kind):
    offline, live = offline_lab(lab), live_lab(lab)
    for devices in (offline, live):
        devices[device] = drop(devices[device], needle)
    off, liv = findings(offline, "security"), findings(live, "security")
    assert off == liv and off, (off, liv)           # non vide : le défaut est bien vu, des deux côtés
    expected = {r.id for r in RULES["security"] if r.kind == kind}
    assert {f[0] for f in off} == expected and {f[1] for f in off} == {device}
