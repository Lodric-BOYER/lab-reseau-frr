"""`golden.py reference compare|record` : une référence LOCALE absente donne un message clair et le code 3.

Les références (reports/reference_v030/) et les snapshots v4a-ref-* sont locaux, hors Git. Avant ce correctif,
un fichier manquant faisait planter `compare` sur une FileNotFoundError obscure. Maintenant : message
« référence locale absente : … ; générer avec : … », code 3, aucune comparaison partielle présentée comme un
succès, et `record` n'écrase plus les références existantes sans `--overwrite`.
"""

import json

import golden
import pytest


@pytest.fixture
def refs(tmp_path, monkeypatch):
    monkeypatch.setattr(golden, "REFERENCE_DIR", tmp_path / "reference_v030")
    return tmp_path / "reference_v030"


def _fake_records(monkeypatch):
    rec = {"compliant": True, "code": 0, "violations": [], "not_applicable": []}
    monkeypatch.setattr(
        golden,
        "reference_records",
        lambda: {f"{snap}__{rules}": dict(rec) for snap in golden.REFERENCES for rules in golden.RULE_FILES},
    )
    monkeypatch.setattr(golden, "_normalized", lambda r: r)
    return rec


def _fill(refs, monkeypatch, skip=()):
    rec = _fake_records(monkeypatch)
    refs.mkdir(parents=True)
    for snap in golden.REFERENCES:
        for rules in golden.RULE_FILES:
            name = f"{snap}__{rules}"
            if name not in skip:
                (refs / f"{name}.json").write_text(json.dumps(rec), encoding="utf-8")
    return rec


def test_compare_with_no_reference_at_all_says_so_and_exits_3(refs, monkeypatch, capsys):
    _fake_records(monkeypatch)
    assert golden.main(["reference", "compare"]) == 3
    err = capsys.readouterr().err
    assert (
        "référence locale absente" in err
        and "générer avec : python tests/tools/golden.py reference record" in err
    )
    assert "pas un succès" in err


def test_compare_names_the_missing_file_and_does_not_compare_the_others(refs, monkeypatch, capsys):
    _fill(refs, monkeypatch, skip={"v4a-ref-frr__security-ipv6"})
    assert golden.main(["reference", "compare"]) == 3
    captured = capsys.readouterr()
    assert (
        "v4a-ref-frr__security-ipv6.json" in captured.err
        and "v4a-ref-mixte__security-ipv6" not in captured.err
    )
    assert "identique" not in captured.out and "DIFFÉRENT" not in captured.out  # aucune comparaison partielle


def test_compare_with_every_reference_present_still_works(refs, monkeypatch, capsys):
    _fill(refs, monkeypatch)
    assert golden.main(["reference", "compare"]) == 0
    assert capsys.readouterr().out.count("identique") == len(golden.REFERENCES) * len(golden.RULE_FILES)


def test_a_real_difference_is_still_exit_1_not_3(refs, monkeypatch, capsys):
    _fill(refs, monkeypatch)
    first = next(iter(refs.glob("*.json")))
    first.write_text(json.dumps({"compliant": False}), encoding="utf-8")
    assert golden.main(["reference", "compare"]) == 1
    assert "DIFFÉRENT" in capsys.readouterr().out


def test_a_missing_real_snapshot_is_the_same_clear_message_and_code(refs, monkeypatch, capsys):
    _fill(refs, monkeypatch)

    def absent():
        raise FileNotFoundError("snapshot 'v4a-ref-frr' introuvable")

    monkeypatch.setattr(golden, "reference_records", absent)
    assert golden.main(["reference", "compare"]) == 3
    err = capsys.readouterr().err
    assert "référence locale absente" in err and "v4a-ref-frr" in err and "Aucune comparaison" in err


def test_record_never_overwrites_an_existing_reference_by_default(refs, monkeypatch, capsys):
    _fill(refs, monkeypatch, skip={"v4a-ref-frr__security-ipv6"})
    keep = refs / "v4a-ref-frr__default.json"
    keep.write_text('{"baseline": "v0.3.0"}', encoding="utf-8")
    assert golden.main(["reference", "record"]) == 0
    assert json.loads(keep.read_text(encoding="utf-8")) == {"baseline": "v0.3.0"}
    assert (refs / "v4a-ref-frr__security-ipv6.json").is_file()
    assert "conservée" in capsys.readouterr().out
    assert golden.missing_references() == []


def test_record_overwrite_is_explicit(refs, monkeypatch):
    _fill(refs, monkeypatch)
    keep = refs / "v4a-ref-frr__default.json"
    keep.write_text('{"baseline": "v0.3.0"}', encoding="utf-8")
    assert golden.main(["reference", "record", "--overwrite"]) == 0
    assert "baseline" not in json.loads(keep.read_text(encoding="utf-8"))
