"""Tests des changements attendus (`--expect`, Phase D1, SPEC_v3 §7) :
  - chargement sûr (yaml.safe_load) et chaque garde-fou anti-masquage ;
  - détecteur de motif trop large : vrais positifs et vrais négatifs ;
  - application aux constats : PRÉVU, changement absent, plafond de gravité, count, `after` ;
  - bout en bout via la CLI (`diff --expect`) sur des snapshots écrits dans un dossier temporaire.
"""
from pathlib import Path

import pytest

from netcheck import cli, diff, expect, snapshot
from netcheck.assertions import Status
from netcheck.diff import Finding, Severity
from netcheck.model import DeviceState, Interface, NextHop, OspfNeighbor, Route


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "expect.yml"
    p.write_text(text, encoding="utf-8")
    return p


def _criterion(**kw) -> str:
    """Un critère YAML minimal et valide, surchargé par kw (valeur None = clé retirée)."""
    fields = {"id": "c1", "description": "d", "device": "r1", "category": "next_hop"}
    fields.update(kw)
    lines = [f"    {k}: {v!r}" if isinstance(v, str) else f"    {k}: {v}"
             for k, v in fields.items() if v is not None]
    return "findings:\n  - " + "\n".join(lines).lstrip()


def F(severity, category, device, message="m") -> Finding:  # noqa: N802 (raccourci de test)
    return Finding(severity, category, device, message)


# ------------------------------------------------------------------------------------------
# Détecteur de motif trop large (demandé explicitement)
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("pattern", [r".*", r".+", r".", r"^", r"[\s\S]*", r"\S+", r"(?i).*"])
def test_too_broad_true_positives(pattern):
    assert expect.is_too_broad(pattern) is True


@pytest.mark.parametrize("pattern", [
    r"10\.1\.23\.0/30", r"ip ospf cost 100", r"voisin OSPF perdu", r"^\+ ip ospf cost", r"next-hop modifié",
])
def test_too_broad_true_negatives(pattern):
    assert expect.is_too_broad(pattern) is False


def test_too_broad_invalid_regex_raises_re_error():
    import re
    with pytest.raises(re.error):
        expect.is_too_broad("(")


# ------------------------------------------------------------------------------------------
# Chargement et garde-fous
# ------------------------------------------------------------------------------------------

def test_valid_file_loads(tmp_path):
    text = (
        "findings:\n"
        "  - id: c1\n    description: d\n    device: r1\n    category: next_hop\n"
        "    pattern: '10\\.1\\.23\\.0/30'\n    severity: critique\n    count: 2\n"
        "after:\n"
        "  - id: a1\n    description: d\n    device: r1\n    type: ospf_neighbors\n    count: 2\n"
    )
    e = expect.load_expect(_write(tmp_path, text))
    assert e.findings[0].severity == Severity.CRITIQUE and e.findings[0].count == 2
    assert e.findings[0].pattern == r"10\.1\.23\.0/30"
    assert e.after[0].type == "ospf_neighbors"


def test_default_severity_is_attention(tmp_path):
    e = expect.load_expect(_write(tmp_path, _criterion()))
    assert e.findings[0].severity == Severity.ATTENTION


def test_malicious_python_tag_is_refused(tmp_path):
    text = ("findings:\n  - id: evil\n    description: x\n    device: r1\n"
            "    category: !!python/object/apply:os.system [\"echo pwned\"]\n")
    with pytest.raises(ValueError):
        expect.load_expect(_write(tmp_path, text))


@pytest.mark.parametrize("missing", ["id", "description", "device", "category"])
def test_each_required_field_is_enforced(tmp_path, missing):
    with pytest.raises(ValueError, match=missing):
        expect.load_expect(_write(tmp_path, _criterion(**{missing: None})))


@pytest.mark.parametrize("device", ["all", "''"])
def test_device_must_be_a_precise_name(tmp_path, device):
    text = _criterion(device=None) + f"\n    device: {device}\n"
    with pytest.raises(ValueError, match="device"):
        expect.load_expect(_write(tmp_path, text))


def test_device_list_is_refused(tmp_path):
    text = _criterion(device=None) + "\n    device: [r1, r2]\n"
    with pytest.raises(ValueError, match="device"):
        expect.load_expect(_write(tmp_path, text))


def test_unknown_category_is_refused(tmp_path):
    with pytest.raises(ValueError, match="category"):
        expect.load_expect(_write(tmp_path, _criterion(category="next_hops")))


def test_synthetic_categories_cannot_be_targeted(tmp_path):
    with pytest.raises(ValueError, match="category"):
        expect.load_expect(_write(tmp_path, _criterion(category=expect.CATEGORY_MISSING)))


def test_unknown_key_is_refused(tmp_path):
    with pytest.raises(ValueError, match="severtiy"):
        expect.load_expect(_write(tmp_path, _criterion(severtiy="critique")))


def test_unknown_top_level_key_is_refused(tmp_path):
    with pytest.raises(ValueError, match="premier niveau"):
        expect.load_expect(_write(tmp_path, _criterion() + "\nfindngs: []\n"))


@pytest.mark.parametrize("pattern", [".*", ".+", ".", "^"])
def test_too_broad_pattern_is_refused_at_load(tmp_path, pattern):
    with pytest.raises(ValueError, match="trop large"):
        expect.load_expect(_write(tmp_path, _criterion(pattern=pattern)))


def test_invalid_regex_is_refused_at_load(tmp_path):
    with pytest.raises(ValueError, match="regex"):
        expect.load_expect(_write(tmp_path, _criterion(pattern="(")))


def test_unknown_severity_is_refused(tmp_path):
    with pytest.raises(ValueError, match="severity"):
        expect.load_expect(_write(tmp_path, _criterion(severity="grave")))


@pytest.mark.parametrize("count", ["0", "-1", "'x'", "true", "1.5"])
def test_invalid_count_is_refused(tmp_path, count):
    text = _criterion() + f"\n    count: {count}\n"
    with pytest.raises(ValueError, match="count"):
        expect.load_expect(_write(tmp_path, text))


def test_empty_file_and_empty_sections_are_refused(tmp_path):
    for text in ("", "findings: []\nafter: []\n", "{}\n"):
        with pytest.raises(ValueError):
            expect.load_expect(_write(tmp_path, text))


def test_duplicate_id_across_findings_and_after_is_refused(tmp_path):
    text = (_criterion(id="same") + "\nafter:\n"
            "  - id: same\n    description: d\n    device: r1\n    type: interface_up\n    interface: eth1\n")
    with pytest.raises(ValueError, match="same"):
        expect.load_expect(_write(tmp_path, text))


def test_after_assertion_missing_param_is_refused_at_load_not_at_evaluation(tmp_path):
    # Critique pour guard : jamais découvert APRÈS avoir exécuté le script de changement.
    text = "after:\n  - id: a1\n    description: d\n    device: r1\n    type: bgp_session\n"
    with pytest.raises(ValueError, match="neighbor"):
        expect.load_expect(_write(tmp_path, text))


def test_after_path_invalid_mode_is_refused_at_load(tmp_path):
    text = ("after:\n  - id: a1\n    description: d\n    device: r1\n    type: path\n"
            "    prefix: 10.0.0.0/8\n    via: [r2]\n    mode: some\n")
    with pytest.raises(ValueError, match="mode"):
        expect.load_expect(_write(tmp_path, text))


def test_after_only_file_is_valid(tmp_path):
    text = ("after:\n  - id: a1\n    description: d\n    device: r1\n"
            "    type: interface_up\n    interface: eth1\n")
    e = expect.load_expect(_write(tmp_path, text))
    assert e.findings == [] and len(e.after) == 1


def test_reference_expect_files_load():
    # Les deux fichiers de tests/expect/ sont ceux de l'intégration (scénario D1) : ils doivent
    # passer TOUS les garde-fous, y compris le détecteur de motif trop large.
    expect_dir = Path(__file__).resolve().parent / "expect"
    full = expect.load_expect(expect_dir / "ospf-cost-r1.yml")
    assert [c.id for c in full.findings] == [
        "r1-bascule-next-hop", "r1-metriques", "r1-config", "r2-perd-le-chemin-via-r1"]
    assert all(c.count is not None for c in full.findings)
    assert {a.type for a in full.after} == {"ospf_neighbors", "path"}
    incomplete = expect.load_expect(expect_dir / "ospf-cost-r1-sans-r2.yml")
    assert {c.device for c in incomplete.findings} == {"r1"} and incomplete.after == []


def test_finding_categories_cover_everything_compare_can_emit():
    # Garde contre une catégorie ajoutée à diff.py sans l'ajouter à FINDING_CATEGORIES.
    source = (Path(diff.__file__)).read_text(encoding="utf-8")
    import re
    emitted = set(re.findall(r'Finding\(Severity\.\w+, "(\w+)"', source))
    assert emitted and emitted <= diff.FINDING_CATEGORIES


# ------------------------------------------------------------------------------------------
# apply() : PRÉVU, absent, plafond de gravité, count, after
# ------------------------------------------------------------------------------------------

def _exp(tmp_path, *criteria_yaml: str, after: str = "") -> expect.Expectation:
    body = "findings:\n" + "".join(criteria_yaml) if criteria_yaml else ""
    return expect.load_expect(_write(tmp_path, body + after))


def _c(id_="c1", device="r1", category="next_hop", **extra) -> str:
    lines = [f"  - id: {id_}", "    description: d", f"    device: {device}", f"    category: {category}"]
    lines += [f"    {k}: {v}" for k, v in extra.items()]
    return "\n".join(lines) + "\n"


def test_matching_finding_becomes_planned_and_verdict_ignores_it(tmp_path):
    e = _exp(tmp_path, _c())
    out, _ = expect.apply([F(Severity.ATTENTION, "next_hop", "r1")], e, {})
    assert out[0].expected_by == "c1"
    assert diff.verdict(out) == ("OK", 0)


def test_non_matching_device_or_category_stays_unplanned(tmp_path):
    e = _exp(tmp_path, _c())
    unrelated = [F(Severity.ATTENTION, "next_hop", "r2"), F(Severity.ATTENTION, "metric", "r1")]
    out, _ = expect.apply(unrelated, e, {})
    assert all(f.expected_by is None for f in out if f.category != expect.CATEGORY_MISSING)
    assert diff.verdict(out) == ("ATTENTION", 1)


def test_criterion_without_matching_finding_adds_attention_missing(tmp_path):
    e = _exp(tmp_path, _c())
    out, _ = expect.apply([], e, {})
    assert len(out) == 1
    assert out[0].category == expect.CATEGORY_MISSING and out[0].severity == Severity.ATTENTION
    assert "changement attendu absent" in out[0].message and "c1" in out[0].message
    assert diff.verdict(out) == ("ATTENTION", 1)


def test_critique_finding_is_not_planned_without_explicit_severity(tmp_path):
    e = _exp(tmp_path, _c(category="interface"))
    out, _ = expect.apply([F(Severity.CRITIQUE, "interface", "r1")], e, {})
    assert out[0].expected_by is None
    assert diff.verdict(out)[1] == 2


def test_critique_finding_is_planned_with_explicit_severity_critique(tmp_path):
    e = _exp(tmp_path, _c(category="interface", severity="critique"))
    out, _ = expect.apply([F(Severity.CRITIQUE, "interface", "r1")], e, {})
    assert out[0].expected_by == "c1"
    assert diff.verdict(out) == ("OK", 0)


def test_severity_is_a_ceiling_info_is_covered_by_attention_criterion(tmp_path):
    e = _exp(tmp_path, _c(category="config"))
    out, _ = expect.apply([F(Severity.INFO, "config", "r1")], e, {})
    assert out[0].expected_by == "c1"


def test_pattern_restricts_matching(tmp_path):
    e = _exp(tmp_path, _c(pattern="'10\\.1\\.23\\.0/30'"))
    findings = [F(Severity.ATTENTION, "next_hop", "r1", "next-hop modifié pour 10.1.23.0/30"),
                F(Severity.ATTENTION, "next_hop", "r1", "next-hop modifié pour 192.168.2.0/24")]
    out, _ = expect.apply(findings, e, {})
    assert out[0].expected_by == "c1" and out[1].expected_by is None
    assert diff.verdict(out) == ("ATTENTION", 1)


def test_count_exact_match_is_ok(tmp_path):
    e = _exp(tmp_path, _c(count=2))
    out, _ = expect.apply([F(Severity.ATTENTION, "next_hop", "r1")] * 2, e, {})
    assert diff.verdict(out) == ("OK", 0)


def test_count_mismatch_adds_attention_with_exact_message(tmp_path):
    e = _exp(tmp_path, _c(count=3))
    out, _ = expect.apply([F(Severity.ATTENTION, "next_hop", "r1")] * 2, e, {})
    extra = [f for f in out if f.category == expect.CATEGORY_COUNT]
    assert len(extra) == 1
    assert "nombre de constats différent (attendu 3, observé 2)" in extra[0].message
    assert diff.verdict(out) == ("ATTENTION", 1)


def test_count_with_zero_matches_reports_missing_not_count_mismatch(tmp_path):
    e = _exp(tmp_path, _c(count=2))
    out, _ = expect.apply([], e, {})
    assert [f.category for f in out] == [expect.CATEGORY_MISSING]


def test_overlapping_criteria_first_one_owns_but_both_count(tmp_path):
    e = _exp(tmp_path, _c(id_="first"), _c(id_="second"))
    out, _ = expect.apply([F(Severity.ATTENTION, "next_hop", "r1")], e, {})
    assert out[0].expected_by == "first"
    assert not [f for f in out if f.category == expect.CATEGORY_MISSING]  # "second" a bien compté


AFTER_OSPF = ("after:\n  - id: a1\n    description: d\n    device: r1\n"
              "    type: ospf_neighbors\n    count: 1\n")


def _devices(neighbors: int) -> dict[str, DeviceState]:
    nbrs = [OspfNeighbor(f"10.0.0.{i}", "Full/-", "eth1") for i in range(neighbors)]
    return {"r1": DeviceState(name="r1", host="h", timestamp="t", reachable=True, ospf_neighbors=nbrs)}


def test_after_ok_adds_no_finding(tmp_path):
    e = _exp(tmp_path, after=AFTER_OSPF)
    out, results = expect.apply([], e, _devices(1))
    assert out == [] and results[0].status == Status.OK
    assert diff.verdict(out) == ("OK", 0)


def test_after_echec_becomes_critique_finding(tmp_path):
    e = _exp(tmp_path, after=AFTER_OSPF)
    out, results = expect.apply([], e, _devices(0))
    assert results[0].status == Status.ECHEC
    assert out[0].severity == Severity.CRITIQUE and out[0].category == expect.CATEGORY_STATE
    assert diff.verdict(out) == ("ÉCHEC", 2)


def test_after_non_evaluable_becomes_attention_finding(tmp_path):
    e = _exp(tmp_path, after=AFTER_OSPF)
    out, results = expect.apply([], e, {})  # r1 absent du relevé
    assert results[0].status == Status.NON_EVALUABLE
    assert out[0].severity == Severity.ATTENTION and "non évaluable" in out[0].message
    assert diff.verdict(out) == ("ATTENTION", 1)


def test_planned_critique_does_not_hide_a_failed_after_assertion(tmp_path):
    e = _exp(tmp_path, _c(category="interface", severity="critique"), after=AFTER_OSPF)
    out, _ = expect.apply([F(Severity.CRITIQUE, "interface", "r1")], e, _devices(0))
    assert diff.verdict(out) == ("ÉCHEC", 2)


# ------------------------------------------------------------------------------------------
# Compatibilité : sans --expect, rien ne change
# ------------------------------------------------------------------------------------------

def test_verdict_without_expectation_is_unchanged():
    assert diff.verdict([]) == ("OK", 0)
    assert diff.verdict([F(Severity.INFO, "route", "r1")]) == ("OK", 0)
    assert diff.verdict([F(Severity.ATTENTION, "route", "r1")]) == ("ATTENTION", 1)
    assert diff.verdict([F(Severity.CRITIQUE, "route", "r1")]) == ("ÉCHEC", 2)


# ------------------------------------------------------------------------------------------
# Bout en bout : `diff --expect` via la CLI, sur des snapshots écrits dans un dossier temporaire
# ------------------------------------------------------------------------------------------

def _router(cost: int) -> DeviceState:
    direct, via_r2 = NextHop(ip="10.1.13.2", interface="eth2"), NextHop(ip="10.1.12.2", interface="eth1")
    nexthop = direct if cost == 10 else via_r2
    cfg = "interface eth2\n description vers-r3\n" + (" ip ospf cost 100\n" if cost == 100 else "") + "exit\n"
    return DeviceState(
        name="r1", host="h", timestamp="t", reachable=True,
        interfaces=[Interface("eth2", "vers-r3", True, True, ["10.1.13.1/30"])],
        routes=[Route("10.2.0.0/16", "ospf", cost, 110, True, [nexthop])],
        ospf_neighbors=[OspfNeighbor("10.1.255.3", "Full/-", "eth2")],
        running_config=cfg,
    )


@pytest.fixture
def two_snapshots(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setenv("COLUMNS", "250")  # rich ne replie pas les messages dans les assertions
    snapshot.save("avant", {"r1": (True, _router(10))})
    snapshot.save("apres", {"r1": (True, _router(100))})
    return tmp_path


FULL_EXPECT = (
    "findings:\n"
    "  - id: bascule-next-hop\n    description: d\n    device: r1\n    category: next_hop\n    count: 1\n"
    "  - id: metrique\n    description: d\n    device: r1\n    category: metric\n    count: 1\n"
    "  - id: config\n    description: d\n    device: r1\n    category: config\n"
    "    pattern: 'ip ospf cost 100'\n    count: 1\n"
    "after:\n"
    "  - id: r1-garde-son-voisin\n    description: d\n    device: r1\n"
    "    type: ospf_neighbors\n    count: 1\n"
)


def test_cli_diff_without_expect_is_attention(two_snapshots, capsys):
    assert cli.main(["diff", "avant", "apres"]) == 1


def test_cli_diff_with_full_expect_is_ok_and_shows_planned(two_snapshots, capsys):
    path = two_snapshots / "expect.yml"
    path.write_text(FULL_EXPECT, encoding="utf-8")
    code = cli.main(["diff", "avant", "apres", "--expect", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "PRÉVU" in out and "prévu(s)" in out and "Verdict : OK" in out
    assert "États attendus : 1 OK" in out


def test_cli_diff_with_expect_writes_planned_in_json(two_snapshots, capsys):
    import json
    path = two_snapshots / "expect.yml"
    path.write_text(FULL_EXPECT, encoding="utf-8")
    out_json = two_snapshots / "out.json"
    cli.main(["diff", "avant", "apres", "--expect", str(path), "--json", str(out_json)])
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert all(f["planned"] for f in data["findings"])
    assert {f["expected_by"] for f in data["findings"]} == {"bascule-next-hop", "metrique", "config"}
    assert data["after"][0]["status"] == "OK"


def test_cli_diff_with_expect_missing_change_is_attention(two_snapshots, capsys):
    path = two_snapshots / "expect.yml"
    # Critère supplémentaire (bgp_session sur r1) qu'aucun constat ne peut satisfaire.
    extra = "  - id: absent\n    description: d\n    device: r1\n    category: bgp_session\n"
    path.write_text(FULL_EXPECT.replace("after:\n", extra + "after:\n"), encoding="utf-8")
    code = cli.main(["diff", "avant", "apres", "--expect", str(path)])
    assert code == 1
    assert "changement attendu absent" in capsys.readouterr().out


def test_cli_diff_with_expect_wrong_count_is_attention(two_snapshots, capsys):
    path = two_snapshots / "expect.yml"
    wrong = FULL_EXPECT.replace("category: next_hop\n    count: 1", "category: next_hop\n    count: 5")
    path.write_text(wrong, encoding="utf-8")
    assert cli.main(["diff", "avant", "apres", "--expect", str(path)]) == 1
    assert "nombre de constats différent (attendu 5, observé 1)" in capsys.readouterr().out


def test_cli_diff_with_failed_after_assertion_is_echec(two_snapshots, capsys):
    path = two_snapshots / "expect.yml"
    path.write_text(FULL_EXPECT.replace(
        "type: ospf_neighbors\n    count: 1\n", "type: ospf_neighbors\n    count: 2\n"), encoding="utf-8")
    assert cli.main(["diff", "avant", "apres", "--expect", str(path)]) == 2
    assert "état attendu non respecté" in capsys.readouterr().out


def test_cli_diff_with_invalid_expect_is_usage_error(two_snapshots, capsys):
    path = two_snapshots / "expect.yml"
    path.write_text(_criterion(pattern=".*"), encoding="utf-8")
    assert cli.main(["diff", "avant", "apres", "--expect", str(path)]) == 3
    assert "trop large" in capsys.readouterr().err


def test_cli_diff_with_missing_expect_file_is_usage_error(two_snapshots, capsys):
    assert cli.main(["diff", "avant", "apres", "--expect", str(two_snapshots / "nope.yml")]) == 3
