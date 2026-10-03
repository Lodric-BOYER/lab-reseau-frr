"""`golden.py add --current-code` (SPEC_v4, A4) : ajout d'une capacité nouvelle au gel, avec ses deux refus.

Le gel ne doit jamais bouger sans qu'on l'ait voulu : l'ajout refuse d'écraser un cas existant et refuse de
tourner sur un code non commité (la réponse gelée doit venir d'un code qui existe dans l'historique).
Ces tests travaillent sur une COPIE du gel, jamais sur tests/golden/.
"""
import json
import shutil

import golden
import pytest

from netcheck import compliance


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    for rules_name in golden.RULE_FILES:
        shutil.copy(golden.golden_path(rules_name), tmp_path / golden.golden_path(rules_name).name)
    monkeypatch.setattr(golden, "GOLDEN_DIR", tmp_path)
    monkeypatch.setattr(golden, "_netcheck_dirty", lambda: "")
    return tmp_path


def read(rules_name):
    return json.loads(golden.golden_path(rules_name).read_text(encoding="utf-8"))


def snapshot_bytes():
    return {r: golden.golden_path(r).read_bytes() for r in golden.RULE_FILES}


EOS_CONFIG = ("router bgp 65002\n   neighbor PG peer group\n   neighbor PG remote-as 65099\n"
              "   neighbor 192.0.2.1 peer group PG\n")


def scene():
    return {"scenario:test-new": {"r4": golden._config_text("r4", "eos", EOS_CONFIG)}}


def test_current_code_adds_the_new_case_and_leaves_every_other_byte_alone(sandbox, monkeypatch):
    monkeypatch.setattr(golden, "scenarios", scene)
    before = {r: read(r) for r in golden.RULE_FILES}
    golden.add_cases(["scenario:test-new"], "capacité nouvelle", current_code=True)
    for rules_name, old in before.items():
        new = read(rules_name)
        assert all(new["cases"][k] == v for k, v in old["cases"].items())
        assert set(new["cases"]) - set(old["cases"]) == {"scenario:test-new"}
        addition = new["meta"]["additions"][-1]
        assert addition["cases"] == ["scenario:test-new"] and addition["current_code"] is True
        assert addition["code_commit"] == golden._code_commit()
        # La réponse gelée est celle du moteur courant, par le chemin des vrais rapports.
        rules = compliance.load_rules(golden.RULE_FILES[rules_name])
        assert new["cases"]["scenario:test-new"]["base"] == golden.record(rules, scene()["scenario:test-new"])
        assert {k: v for k, v in new["meta"].items() if k != "additions"} == {
            k: v for k, v in old["meta"].items() if k != "additions"}


def test_current_code_never_overwrites_a_frozen_case(sandbox):
    frozen = snapshot_bytes()
    with pytest.raises(SystemExit, match="jamais écrasés"):
        golden.add_cases(["fixture:frr-r3"], "x", current_code=True)
    assert snapshot_bytes() == frozen


def test_current_code_refuses_uncommitted_code(sandbox, monkeypatch):
    monkeypatch.setattr(golden, "_netcheck_dirty", lambda: " M netcheck/compliance.py")
    monkeypatch.setattr(golden, "scenarios", scene)
    frozen = snapshot_bytes()
    with pytest.raises(SystemExit, match="non commitées"):
        golden.add_cases(["scenario:test-new"], "x", current_code=True)
    assert snapshot_bytes() == frozen


def test_nothing_is_written_when_one_of_the_files_refuses(sandbox, monkeypatch):
    """Un cas déjà gelé dans UN des deux fichiers seulement : aucun des deux n'est modifié."""
    path = golden.golden_path("security")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["cases"]["scenario:test-new"] = {"base": {}}
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(golden, "scenarios", scene)
    frozen = snapshot_bytes()
    with pytest.raises(SystemExit, match="jamais écrasés"):
        golden.add_cases(["scenario:test-new"], "x", current_code=True)
    assert snapshot_bytes() == frozen


def test_the_two_evaluation_modes_exclude_each_other(sandbox):
    with pytest.raises(SystemExit, match="s'excluent"):
        golden.add_cases(["scenario:x"], "x", reference_commit="b56a775", current_code=True)
