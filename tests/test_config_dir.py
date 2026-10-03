"""`netcheck check --config-dir` (SPEC_v4, Phase A5) : audit de fichiers de configuration, sans équipement.

Ce que ces tests tiennent : les deux dispositions de dossier, le driver (inventaire ou `--driver`), RIEN
d'ignoré en silence (un fichier non lu bloque le verdict, un fichier hors disposition est une
information), les règles qui lisent le modèle « non évaluables » hors ligne et dites telles dans les trois
sorties, la lecture seule.
L'équivalence avec le direct sur les trois labs est dans test_config_dir_equivalence.py.
"""
import hashlib
import json
from pathlib import Path

import pytest

from netcheck import cli, compliance, configdir
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.ruletypes import CAUSE_DRIVER, CAUSE_NO_MODEL, Rule

REPO = Path(__file__).resolve().parent.parent
RULES = {name: REPO / "netcheck" / "rules" / f"{name}.yml" for name in ("default", "security")}
FRR = (REPO / "configs" / "r3" / "frr.conf").read_text(encoding="utf-8")
EOS = (REPO / "configs-ceos" / "r4" / "startup-config").read_text(encoding="utf-8")
INVENTORY = {"r1": "frr", "r3": "frr", "r4": "eos", "r5": "srlinux"}


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def reasons(loaded):
    return {w.device: (w.warning.reason, w.blocks_verdict) for w in loaded.warnings}


# ------------------------------------------------------------------------------------------
# Lecture des dossiers
# ------------------------------------------------------------------------------------------

def test_both_layouts_and_the_driver_comes_from_the_inventory(tmp_path):
    write(tmp_path / "r1.conf", FRR)             # un fichier par équipement
    write(tmp_path / "r3" / "frr.conf", FRR)     # un sous-dossier par équipement
    write(tmp_path / "r4.cfg", EOS)
    loaded = configdir.load([tmp_path], INVENTORY)
    assert sorted(loaded.devices) == ["r1", "r3", "r4"] and loaded.warnings == []
    assert {n: d.driver for n, d in loaded.devices.items()} == {"r1": "frr", "r3": "frr", "r4": "eos"}
    assert loaded.devices["r4"].running_config == EOS and loaded.devices["r4"].reachable
    assert loaded.sources["r3"].path == str(tmp_path / "r3" / "frr.conf")


def test_driver_option_overrides_the_inventory_and_an_unknown_driver_is_refused(tmp_path):
    write(tmp_path / "r4.cfg", FRR)
    assert configdir.load([tmp_path], INVENTORY, forced_driver="frr").devices["r4"].driver == "frr"
    with pytest.raises(configdir.ConfigDirError, match="driver inconnu"):
        configdir.load([tmp_path], INVENTORY, forced_driver="nope")


def test_a_device_unknown_to_the_inventory_is_not_audited_and_blocks_the_verdict(tmp_path):
    write(tmp_path / "r1.conf", FRR)
    write(tmp_path / "r99.conf", FRR)
    loaded = configdir.load([tmp_path], INVENTORY)
    assert sorted(loaded.devices) == ["r1"]
    reason, blocking = reasons(loaded)["r99"]
    assert blocking and "non audité" in reason and "--driver" in reason
    # Avec --driver, tout fichier de la disposition est une configuration.
    assert sorted(configdir.load([tmp_path], INVENTORY, forced_driver="frr").devices) == ["r1", "r99"]


def test_a_folder_with_several_files_takes_the_one_the_driver_names(tmp_path):
    for name in DRIVER_REGISTRY:
        names = DRIVER_REGISTRY[name].CONFIG_FILENAMES
        assert names, f"le driver {name} doit nommer son fichier de configuration"
    write(tmp_path / "r3" / "frr.conf", FRR)
    write(tmp_path / "r3" / "notes.txt", "pas une configuration")
    loaded = configdir.load([tmp_path], INVENTORY)
    assert loaded.devices["r3"].running_config == FRR and loaded.warnings == []
    # Aucun nom attendu parmi plusieurs fichiers : on ne devine pas, l'équipement n'est pas audité.
    write(tmp_path / "r1" / "a.txt", FRR)
    write(tmp_path / "r1" / "b.txt", FRR)
    loaded = configdir.load([tmp_path], INVENTORY)
    assert "r1" not in loaded.devices
    reason, blocking = reasons(loaded)["r1"]
    assert blocking and "2 fichiers" in reason and "frr.conf" in reason


def test_entries_outside_the_layout_are_listed_as_information_never_dropped_silently(tmp_path):
    write(tmp_path / "r1.conf", FRR)
    write(tmp_path / "daemons", "bgpd=yes\n")
    write(tmp_path / ".gitkeep", "")
    write(tmp_path / "README.md", "# configs\n")
    write(tmp_path / "intent.yml", "a: 1\n")
    loaded = configdir.load([tmp_path], INVENTORY)
    assert sorted(loaded.devices) == ["r1"]
    assert sorted(reasons(loaded)) == [".gitkeep", "README.md", "daemons", "intent.yml"]
    assert not any(w.blocks_verdict for w in loaded.warnings)      # information : aucun effet sur le verdict
    assert all(w.warning.line == 0 and w.kept for w in loaded.warnings)


def test_unreadable_files_are_not_audited(tmp_path, monkeypatch):
    write(tmp_path / "r1.conf", "")
    (tmp_path / "r3.conf").write_bytes(b"hostname r3\n\xff\xfe\n")
    write(tmp_path / "r4.cfg", EOS)
    monkeypatch.setattr(configdir, "MAX_BYTES", 100)
    loaded = configdir.load([tmp_path], INVENTORY)
    assert loaded.devices == {}
    got = reasons(loaded)
    assert "vide" in got["r1"][0] and "UTF-8" in got["r3"][0] and "plus de" in got["r4"][0]
    assert all(blocking for _, blocking in got.values())


def test_two_definitions_of_a_device_in_one_folder_are_refused(tmp_path):
    write(tmp_path / "r1.conf", FRR)
    write(tmp_path / "r1" / "frr.conf", FRR)
    with pytest.raises(configdir.ConfigDirError, match="défini deux fois"):
        configdir.load([tmp_path], INVENTORY)


def test_a_later_folder_replaces_a_device_of_an_earlier_one_and_says_so(tmp_path):
    write(tmp_path / "a" / "r1.conf", "hostname a\n")
    write(tmp_path / "b" / "r1.conf", "hostname b\n")
    loaded = configdir.load([tmp_path / "a", tmp_path / "b"], INVENTORY)
    assert loaded.devices["r1"].running_config == "hostname b\n"
    reason, blocking = reasons(loaded)["r1"]
    assert "remplacé" in reason and not blocking


def test_a_missing_folder_is_an_error(tmp_path):
    write(tmp_path / "file", "x")
    for bad in (tmp_path / "absent", tmp_path / "file"):
        with pytest.raises(configdir.ConfigDirError, match="pas un dossier"):
            configdir.load([bad], INVENTORY)


def test_reading_never_modifies_anything(tmp_path):
    write(tmp_path / "r1.conf", FRR)
    write(tmp_path / "r4" / "startup-config", EOS)
    write(tmp_path / "daemons", "x\n")
    before = tree_hash(tmp_path)
    configdir.load([tmp_path], INVENTORY)
    assert tree_hash(tmp_path) == before


# ------------------------------------------------------------------------------------------
# Le moteur : les règles qui lisent le modèle sont non évaluables hors ligne
# ------------------------------------------------------------------------------------------

def states():
    return {"r3": DeviceState(name="r3", host="-", timestamp="", reachable=True, running_config=FRR,
                              driver="frr"),
            "r4": DeviceState(name="r4", host="-", timestamp="", reachable=True, running_config=EOS,
                              driver="eos")}


def test_rules_that_read_the_model_are_not_evaluable_offline_with_their_own_cause():
    rules = compliance.load_rules(RULES["default"])
    offline = compliance.evaluate_config(rules, states(), offline=True)
    no_model = {(n.rule.id, n.device) for n in offline.not_applicable if n.cause == CAUSE_NO_MODEL}
    assert no_model == {("lan-en-ospf-passif", "r3"), ("interface-avec-description", "r3"),
                        ("interface-avec-description", "r4")}
    assert all("modèle" in n.reason for n in offline.not_applicable if n.cause == CAUSE_NO_MODEL)
    # Le reste est inchangé : mêmes causes « hors sujet » qu'en ligne, mêmes violations.
    online = compliance.evaluate_config(rules, states())
    assert {(n.rule.id, n.device) for n in online.not_applicable} == (
        {(n.rule.id, n.device) for n in offline.not_applicable} - no_model)
    assert all(n.cause == CAUSE_DRIVER for n in online.not_applicable)
    assert [(v.rule.id, v.detail) for v in offline.violations] == [
        (v.rule.id, v.detail) for v in online.violations]


def test_security_rules_read_only_the_configuration_so_nothing_is_lost_offline():
    rules = compliance.load_rules(RULES["security"])
    offline = compliance.evaluate_config(rules, states(), offline=True)
    assert not [n for n in offline.not_applicable if n.cause == CAUSE_NO_MODEL]


# ------------------------------------------------------------------------------------------
# La ligne de commande, de bout en bout
# ------------------------------------------------------------------------------------------

def run(argv, tmp_path, capsys, rules="default"):
    out_json, out_html = tmp_path / "out.json", tmp_path / "out.html"
    code = cli.main(["check", "--rules", str(RULES[rules]), "--json", str(out_json), "--html", str(out_html),
                     *argv])
    data = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else None
    html = out_html.read_text(encoding="utf-8") if out_html.exists() else ""
    captured = capsys.readouterr()
    # Le terminal replie les cellules d'un tableau à 80 colonnes : on compare le texte à espaces normalisés.
    return code, data, html, captured._replace(out=" ".join(captured.out.split()))


@pytest.mark.parametrize("dirs, inventory", [
    (["configs"], "inventory.yml"),
    (["configs", "configs-multivendor"], "inventory-multivendor.yml"),
    (["configs", "configs-ceos"], "inventory-ceos.yml"),
], ids=["frr", "mixte", "ceos"])
@pytest.mark.parametrize("rules", ["default", "security"])
def test_the_three_labs_are_compliant_offline_and_the_report_says_what_it_could_not_evaluate(
        dirs, inventory, rules, tmp_path, capsys):
    argv = [x for d in dirs for x in ("--config-dir", str(REPO / d))]
    argv += ["-i", str(REPO / "automation" / inventory)]
    code, data, html, out = run(argv, tmp_path, capsys, rules)
    assert code == 0 and data["status"] == "CONFORME" and data["violations"] == []
    assert sorted(data["source"]["devices"]) == ["r1", "r2", "r3", "r4", "r5"]
    no_model = {n["rule_id"] for n in data["not_applicable"] if n["cause"] == "no_model"}
    state_rules = {"lan-en-ospf-passif", "interface-avec-description"}
    assert no_model == (set() if rules == "security" else state_rules)
    assert data["summary"]["not_applicable_no_model"] == sum(n["cause"] == "no_model"
                                                              for n in data["not_applicable"])
    # `daemons` (sans extension) est listé, pas ignoré en silence ; et rien ne bloque le verdict.
    assert "daemons" in {w["device"] for w in data["config_analysis"]}
    assert not any(w["blocks_verdict"] for w in data["config_analysis"])
    # Les trois sorties disent « hors ligne » ; celles qui ont des règles non évaluables le disent aussi.
    assert "Mode hors ligne" in out.out and "Mode hors ligne" in html
    assert "source" in data and "ANALYSE INCOMPLÈTE" not in out.out
    if no_model:
        assert "ÉTAT REQUIS (hors ligne)" in out.out and "ÉTAT REQUIS (hors ligne)" in html
        assert "non évaluable(s) hors ligne" in out.out and "non évaluable(s) hors ligne" in html


def test_a_mixed_lab_reads_r5_as_sr_linux_from_the_later_folder(tmp_path, capsys):
    inventory = str(REPO / "automation" / "inventory-multivendor.yml")
    code, data, _, _ = run(["--config-dir", str(REPO / "configs"), "--config-dir",
                            str(REPO / "configs-multivendor"), "-i", inventory], tmp_path, capsys, "security")
    assert code == 0 and data["source"]["devices"]["r5"]["driver"] == "srlinux"
    assert data["source"]["devices"]["r5"]["file"].endswith("configs-multivendor/r5/config.cli")


def test_a_file_that_was_not_audited_blocks_the_verdict_like_an_unread_line(tmp_path, capsys):
    cfg = tmp_path / "cfg"
    write(cfg / "r1.conf", FRR)
    write(cfg / "r99.conf", FRR)            # inconnu de l'inventaire
    code, data, html, out = run(["--config-dir", str(cfg)], tmp_path, capsys, "security")
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE" and data["compliant"] is False
    assert data["summary"]["config_files_not_audited"] == 1 and data["summary"]["config_lines_unread"] == 0
    assert "NON AUDITÉ" in out.out and "1 fichier(s) non audité(s)" in out.out
    assert "NON AUDITÉ" in html and "fichier(s) non audité(s)" in html
    assert "NON CONFORME" not in out.out


def test_a_real_violation_still_shows_as_non_compliant_and_secrets_stay_masked(tmp_path, capsys):
    bad = FRR.replace("hostname r3", "hostname r3\npassword lab-bgp-r3r4", 1)
    assert bad != FRR
    cfg = tmp_path / "cfg"
    write(cfg / "r3.conf", bad)
    write(cfg / "r99.conf", FRR)
    code, data, html, out = run(["--config-dir", str(cfg)], tmp_path, capsys, "default")
    assert code == 2 and data["status"] == "NON CONFORME"
    assert any(v["rule_id"] == "pas-de-mot-de-passe-en-clair" for v in data["violations"])
    for text in (json.dumps(data), html, out.out):
        assert "lab-bgp-r3r4" not in text


def test_usage_errors_are_refused_with_code_3_and_nothing_is_audited(tmp_path, capsys):
    write(tmp_path / "r1.conf", FRR)
    empty = tmp_path / "empty"
    empty.mkdir()
    base = ["check", "--rules", str(RULES["default"])]
    assert cli.main([*base, "--config-dir", str(tmp_path), "--snapshot", "x"]) == 3
    assert cli.main([*base, "--driver", "frr"]) == 3
    assert cli.main([*base, "--config-dir", str(tmp_path / "absent")]) == 3
    assert cli.main([*base, "--config-dir", str(empty)]) == 3                  # rien lu : jamais « conforme »
    err = capsys.readouterr().err
    assert "s'excluent" in err and "--driver n'a de sens" in err and "pas un dossier" in err
    assert "rien n'a été audité" in err


def test_driver_option_works_without_an_inventory_file(tmp_path, capsys):
    cfg = tmp_path / "cfg"
    write(cfg / "edge1.conf", FRR)
    missing = tmp_path / "no-inventory.yml"
    argv = ["--config-dir", str(cfg), "--driver", "frr", "-i", str(missing)]
    code, data, _, _ = run(argv, tmp_path, capsys, "security")
    assert code == 0 and data["source"]["devices"]["edge1"]["driver"] == "frr"
    # Sans inventaire ni --driver, aucun driver ne se déduit : refus clair.
    assert cli.main(["check", "--config-dir", str(cfg), "-i", str(missing)]) == 3
    assert "donnez --driver" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------
# Bannière SR Linux : un évaluateur sur les chemins, la même réponse dans les deux syntaxes
# ------------------------------------------------------------------------------------------

BANNER_RULE = Rule(id="b", description="d", severity="basse", applies_to="all", drivers=["srlinux"],
                   kind="srlinux_login_banner_present")


def srlinux(text):
    return DeviceState(name="r5", host="-", timestamp="", reachable=True, running_config=text,
                       driver="srlinux")


def test_the_srlinux_banner_is_read_on_the_path_in_both_syntaxes():
    set_form = (REPO / "configs-multivendor" / "r5" / "config.cli").read_text(encoding="utf-8")
    braces = json.loads((REPO / "tests" / "fixtures" / "r5_hardened" / "state.json").read_text(
        encoding="utf-8"))["running_config"]
    assert "set / system banner login-banner" in set_form and "    login-banner " in braces
    for text in (set_form, braces):
        assert compliance.check_one(BANNER_RULE, srlinux(text)) == []
        without = "\n".join(line for line in text.splitlines() if "login-banner" not in line) + "\n"
        detail = [v.detail for v in compliance.check_one(BANNER_RULE, srlinux(without))]
        assert detail == ["aucune ligne ne correspond à /^\\s*login-banner\\s/"]


def test_the_srlinux_banner_rule_no_longer_reads_text():
    rules = compliance.load_rules(RULES["security"])
    rule = next(r for r in rules if r.id == "srlinux-banniere-de-connexion")
    assert rule.kind == "srlinux_login_banner_present" and "pattern" not in rule.params
    # Un mot « login-banner » dans une description n'est pas une bannière.
    fake = 'set / system description "login-banner"\n'
    assert len(compliance.check_one(rule, srlinux(fake))) == 1
