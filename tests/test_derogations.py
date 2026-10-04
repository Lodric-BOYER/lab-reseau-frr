"""Phase B3 : les dérogations (netcheck/derogations.py) : chargement, correspondance, horloge, rapports, CLI.

Aucune date du jour ici : le moteur reçoit `today` en paramètre et tous les tests utilisent une date fixe,
donc une dérogation qui expire ne rend jamais la CI rouge à cause du calendrier. Les configurations sont
celles relevées en direct sur les labs en double pile (tests/fixtures/live_dualstack/) ou les fichiers de
démarrage du dépôt.
"""
import hashlib
import io
import json
import re
from datetime import date
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from netcheck import cli, compliance, derogations, report
from netcheck.model import DeviceState
from netcheck.ruletypes import Violation

REPO = Path(__file__).resolve().parent.parent
FX = Path(__file__).resolve().parent / "fixtures" / "live_dualstack"
RULE_FILES = [REPO / "netcheck/rules/security.yml", REPO / "netcheck/rules/security-ipv6.yml"]
RULES = compliance.load_rule_files(RULE_FILES)
TODAY = date(2026, 10, 5)
OSPF6 = "ospf6-authentification"


def entry(**over) -> dict:
    base = {"id": "DER-T-001", "rule": OSPF6, "targets": [{"device": "r4", "object": "eth2"}],
            "justification": "défaut connu et documenté", "validated_by": "Test",
            "validated_on": date(2026, 10, 1), "expires": date(2026, 12, 31)}
    base.update(over)
    return base


def write(tmp_path: Path, *entries: dict, version=1, name="d.yml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump({"version": version, "derogations": list(entries)}, allow_unicode=True),
                    encoding="utf-8")
    return path


def load(tmp_path: Path, *entries: dict, today: date = TODAY, **kw) -> derogations.DerogationSet:
    return derogations.load(write(tmp_path, *entries, **kw), RULES, today)


def refused(tmp_path: Path, match: str, *entries: dict, today: date = TODAY, **kw):
    with pytest.raises(ValueError, match=match):
        load(tmp_path, *entries, today=today, **kw)


# ------------------------------------------------------------------------------------------
# Chargement : tout est validé avant le moindre audit
# ------------------------------------------------------------------------------------------

def test_a_valid_file_loads_with_its_path_and_sha256(tmp_path):
    path = write(tmp_path, entry())
    dset = derogations.load(path, RULES, TODAY)
    assert dset.path == str(path) and dset.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    d, = dset.derogations
    assert (d.id, d.rule, d.targets, d.validated_by) == ("DER-T-001", OSPF6, (("r4", "eth2"),), "Test")
    assert (d.validated_on, d.expires) == (date(2026, 10, 1), date(2026, 12, 31))


def test_dates_may_be_written_as_iso_strings(tmp_path):
    d, = load(tmp_path, entry(validated_on="2026-10-01", expires="2026-12-31")).derogations
    assert d.expires == date(2026, 12, 31)


@pytest.mark.parametrize("lab", ["lab", "lab-multivendor", "lab-ceos"])
def test_the_shipped_lab_files_load_and_their_justification_is_documented(lab):
    dset = derogations.load(REPO / "derogations" / f"{lab}.yml", RULES, TODAY)
    assert dset.derogations
    for d in dset.derogations:
        assert d.justification and d.validated_by
        assert (d.expires - d.validated_on).days <= derogations.MAX_VALIDITY_DAYS
        assert d.rule in {r.id for r in RULES}


@pytest.mark.parametrize(("content", "match"), [
    ("- a\n- b\n", "seules clés"),
    ("version: 1\nderogations: []\nextra: 1\n", "seules clés"),
    ("version: 2\nderogations: []\n", "« version » doit valoir 1"),
    ("derogations: []\n", "« version » doit valoir 1"),
    ("version: 1\n", "« derogations » doit être une liste"),
    ("version: 1\nderogations: oui\n", "« derogations » doit être une liste"),
    ("version: 1\nderogations: [uneligne]\n", "doit être un objet YAML"),
    ("version: !!python/object/apply:os.system ['echo x']\nderogations: []\n", "invalide ou refusé"),
    ("version: [1\n", "invalide ou refusé"),
])
def test_malformed_files_are_refused(tmp_path, content, match):
    path = tmp_path / "d.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        derogations.load(path, RULES, TODAY)


def test_an_unreadable_file_is_refused(tmp_path):
    with pytest.raises(ValueError, match="illisible"):
        derogations.load(tmp_path / "absent.yml", RULES, TODAY)


def test_expiry_is_mandatory(tmp_path):
    raw = entry()
    del raw["expires"]
    refused(tmp_path, "expires.*l'expiration est obligatoire", raw)


@pytest.mark.parametrize("missing",
                         ["id", "rule", "targets", "justification", "validated_by", "validated_on"])
def test_every_other_field_is_mandatory(tmp_path, missing):
    raw = entry()
    del raw[missing]
    refused(tmp_path, f"manquant.*{missing}", raw)


def test_unknown_rule_is_refused(tmp_path):
    refused(tmp_path, "règle inconnue 'ospf-inexistante'", entry(rule="ospf-inexistante"))


def test_a_critical_rule_can_never_be_derogated(tmp_path):
    critical = [r.id for r in RULES if r.severity == "critique"]
    assert critical, "security.yml doit contenir au moins une règle critique pour ce test"
    refused(tmp_path, "gravité « critique »", entry(rule=critical[0]))


@pytest.mark.parametrize(("validated_on", "expires", "match"), [
    (date(2026, 10, 1), date(2027, 10, 2), "au plus 365 jours"),
    (date(2026, 10, 1), date(2026, 9, 30), "précède validated_on"),
    (date(2026, 10, 6), date(2026, 12, 1), "dans le futur"),
])
def test_validity_rules(tmp_path, validated_on, expires, match):
    refused(tmp_path, match, entry(validated_on=validated_on, expires=expires))


def test_exactly_365_days_is_allowed_and_validation_today_too(tmp_path):
    load(tmp_path, entry(validated_on=date(2026, 10, 5), expires=date(2027, 10, 5)))
    refused(tmp_path, "au plus 365 jours", entry(validated_on=date(2026, 10, 5), expires=date(2027, 10, 6)))


@pytest.mark.parametrize("bad", ["demain", "2026-13-40", "05/10/2026", 20261005, None])
def test_dates_must_be_iso(tmp_path, bad):
    refused(tmp_path, "date ISO", entry(expires=bad))


def test_a_date_and_time_is_not_a_date(tmp_path):
    path = tmp_path / "d.yml"
    path.write_text("version: 1\nderogations:\n  - id: X\n    rule: ospf6-authentification\n"
                    "    targets: [{device: r4, object: eth2}]\n    justification: j\n    validated_by: v\n"
                    "    validated_on: 2026-10-01\n    expires: 2026-12-31 10:00:00\n", encoding="utf-8")
    with pytest.raises(ValueError, match="pas une date et heure"):
        derogations.load(path, RULES, TODAY)


@pytest.mark.parametrize("field", ["justification", "validated_by", "id", "rule"])
@pytest.mark.parametrize("empty", ["", "   ", None, 3])
def test_text_fields_cannot_be_empty(tmp_path, field, empty):
    refused(tmp_path, "texte non vide", entry(**{field: empty}))


@pytest.mark.parametrize("targets", [
    [], "r4", [{"device": "r4"}], [{"device": "r4", "object": "eth2", "x": 1}],
    [{"device": "", "object": "eth2"}], [{"device": "r4", "object": 2}], ["r4:eth2"]])
def test_targets_must_be_non_empty_pairs_of_texts(tmp_path, targets):
    refused(tmp_path, "targets|cible|texte non vide", entry(targets=targets))


def test_one_device_object_pair_cannot_be_covered_twice(tmp_path):
    refused(tmp_path, "déjà couverte par la dérogation DER-T-001",
            entry(), entry(id="DER-T-002", justification="autre"))
    refused(tmp_path, "déjà couverte", entry(targets=[{"device": "r4", "object": "eth2"},
                                                      {"device": "r4", "object": "eth2"}]))


def test_the_same_pair_for_two_different_rules_is_fine(tmp_path):
    load(tmp_path, entry(), entry(id="DER-T-002", rule="eos-ospf6-authentification-ipsec"))


def test_duplicate_ids_are_refused(tmp_path):
    refused(tmp_path, "id de dérogation en double", entry(),
            entry(targets=[{"device": "r5", "object": "eth1"}]))


def test_unknown_keys_are_refused(tmp_path):
    refused(tmp_path, "clé\\(s\\) inconnue\\(s\\) : \\['device'\\]", entry(device="r4"))


@pytest.mark.parametrize("references", ["https://x", [""], [3], ["ok", None]])
def test_references_must_be_a_list_of_texts(tmp_path, references):
    refused(tmp_path, "references", entry(references=references))


def test_references_are_kept(tmp_path):
    d, = load(tmp_path, entry(references=["https://www.rfc-editor.org/rfc/rfc7166.html"])).derogations
    assert d.references == ("https://www.rfc-editor.org/rfc/rfc7166.html",)


# ------------------------------------------------------------------------------------------
# Correspondance exacte, expiration, avertissement à 30 jours, orphelines
# ------------------------------------------------------------------------------------------

TWO_TARGETS = [{"device": "r4", "object": "eth2"}, {"device": "r5", "object": "eth1"}]


def violation(device="r4", subject: str | None = "eth2", rule_id=OSPF6) -> Violation:
    rule = next(r for r in RULES if r.id == rule_id)
    return Violation(rule, device, f"détail {device} {subject}", subject)


def apply(dset, violations, today=TODAY, audited=("r4", "r5")):
    return derogations.apply(violations, dset, today, set(audited))


def test_a_violation_is_covered_by_exact_rule_device_and_object(tmp_path):
    out = apply(load(tmp_path, entry()), [violation()])
    assert out.active == [] and [d.derogation.id for d in out.derogated] == ["DER-T-001"]
    assert out.notes == [] and out.reactivated == []


@pytest.mark.parametrize(("device", "subject", "rule_id"), [
    ("r5", "eth2", OSPF6),               # autre équipement
    ("r4", "eth20", OSPF6),              # objet voisin
    ("r4", "Eth2", OSPF6),               # la casse compte
    ("r4", "eth2 ", OSPF6),              # aucune normalisation, aucune regex
    ("r4", "eth.*", OSPF6),
    ("r4", "eth2", "srlinux-ospf6-authentification-keychain"),   # autre règle
])
def test_nothing_else_is_covered(tmp_path, device, subject, rule_id):
    v = violation(device, subject, rule_id)
    out = apply(load(tmp_path, entry()), [v])
    assert out.active == [v] and out.derogated == []


def test_only_the_listed_object_is_covered_among_several_of_one_rule(tmp_path):
    a, b = violation(subject="eth2"), violation(subject="eth1")
    out = apply(load(tmp_path, entry()), [a, b])
    assert out.active == [b] and [d.violation for d in out.derogated] == [a]
    notes = [n.kind for n in out.notes]
    assert notes == []                                       # eth1 n'est pas une cible : pas de note


def test_a_violation_without_an_object_cannot_be_covered_and_the_orphan_says_why(tmp_path):
    v = violation(subject=None)
    out = apply(load(tmp_path, entry()), [v])
    assert out.active == [v] and out.derogated == []
    assert [n.kind for n in out.notes] == [derogations.NOTE_ORPHAN]
    assert "pas d'objet identifiable" in out.notes[0].text


def test_an_orphan_derogation_is_an_information_only_on_an_audited_device(tmp_path):
    targets = [{"device": "r4", "object": "eth2"}, {"device": "r9", "object": "eth1"}]
    dset = load(tmp_path, entry(targets=targets))
    out = apply(dset, [], audited=("r4", "r5"))
    assert [(n.kind, n.derogation) for n in out.notes] == [(derogations.NOTE_ORPHAN, "DER-T-001")]
    assert "r4" in out.notes[0].text and "eth2" in out.notes[0].text
    assert "r9" not in out.notes[0].text                     # r9 n'est pas dans cet audit : non jugé


def test_a_derogation_is_valid_through_its_expiry_day_and_expired_the_day_after(tmp_path):
    dset = load(tmp_path, entry(expires=date(2026, 12, 31)))
    assert apply(dset, [violation()], today=date(2026, 12, 31)).active == []
    out = apply(dset, [violation()], today=date(2027, 1, 1))
    assert len(out.active) == 1 and out.derogated == [] and len(out.reactivated) == 1
    assert [n.kind for n in out.notes] == [derogations.NOTE_EXPIRED]
    assert "expirée le 2026-12-31" in out.notes[0].text and "de nouveau actives" in out.notes[0].text


def test_an_expired_derogation_is_reported_once_even_for_several_violations(tmp_path):
    dset = load(tmp_path, entry(targets=TWO_TARGETS))
    out = apply(dset, [violation("r4", "eth2"), violation("r5", "eth1")], today=date(2027, 6, 1))
    assert len(out.active) == 2 and len(out.reactivated) == 2
    assert [n.kind for n in out.notes] == [derogations.NOTE_EXPIRED]


@pytest.mark.parametrize(("today", "warned", "days"), [
    (date(2026, 12, 1), False, None),     # 30 jours : pas d'avertissement
    (date(2026, 12, 2), True, 29),        # 29 jours
    (date(2026, 12, 31), True, 0),        # le dernier jour
])
def test_the_thirty_day_warning(tmp_path, today, warned, days):
    out = apply(load(tmp_path, entry(expires=date(2026, 12, 31)), today=today), [violation()], today=today)
    assert out.active == [] and len(out.derogated) == 1       # sans aucun effet sur le résultat
    if warned:
        assert [n.kind for n in out.notes] == [derogations.NOTE_EXPIRING]
        assert f"expire dans {days} jour(s)" in out.notes[0].text
    else:
        assert out.notes == []


def test_the_warning_is_given_once_per_derogation(tmp_path):
    dset = load(tmp_path, entry(targets=TWO_TARGETS), today=date(2026, 12, 20))
    out = apply(dset, [violation("r4", "eth2"), violation("r5", "eth1")], today=date(2026, 12, 20))
    assert len(out.derogated) == 2 and [n.kind for n in out.notes] == [derogations.NOTE_EXPIRING]


def test_the_clock_is_never_read_by_the_engine():
    for module in ("netcheck/derogations.py", "netcheck/compliance.py"):
        text = (REPO / module).read_text(encoding="utf-8")
        assert "today()" not in text and "datetime.now" not in text and "time.time" not in text, module
    state = DeviceState(name="r4", host="-", timestamp="", reachable=True, driver="frr", running_config="")
    dset = derogations.DerogationSet((), "x", "0" * 64)
    with pytest.raises(ValueError, match="`today` est obligatoire"):
        compliance.evaluate_config(RULES, {"r4": state}, derogations=dset)


# ------------------------------------------------------------------------------------------
# Dans le moteur : les labs
# ------------------------------------------------------------------------------------------

LABS = {
    "lab": ({f"r{i}": ("frr", f"frr_r{i}.txt") for i in range(1, 6)}, ["r4", "r5"]),
    "lab-multivendor": ({**{f"r{i}": ("frr", f"frr_r{i}.txt") for i in range(1, 5)},
                         "r5": ("srlinux", "srl_r5.txt")},
                        ["r4", "r5"]),
    "lab-ceos": ({"r1": ("frr", "frr_r1.txt"), "r2": ("frr", "frr_r2.txt"), "r3": ("frr", "frr_r3.txt"),
                  "r4": ("eos", "eos_r4.txt"), "r5": ("frr", "frr_r5.txt")}, ["r4", "r5"]),
}


def lab_devices(lab: str) -> dict[str, DeviceState]:
    spec, _ = LABS[lab]
    return {n: DeviceState(name=n, host="-", timestamp="", reachable=True, driver=d,
                           running_config=(FX / f).read_text(encoding="utf-8")) for n, (d, f) in spec.items()}


def evaluate(lab: str, dset=None, today=TODAY, devices=None):
    return compliance.evaluate_config(RULES, devices or lab_devices(lab), {"eth0", "mgmt0", "Management0"},
                                      offline=True, derogations=dset, today=today)


@pytest.mark.parametrize("lab", list(LABS))
def test_the_lab_file_covers_exactly_the_r4_r5_link_and_nothing_else(lab):
    without = evaluate(lab)
    # Le défaut réel, sans dérogation.
    assert sorted(v.device for v in without.violations) == ["r4", "r5"]
    assert compliance.verdict(without.violations, without.config_warnings) == (False, 2)
    dset = derogations.load(REPO / "derogations" / f"{lab}.yml", RULES, TODAY)
    covered = evaluate(lab, dset)
    assert covered.violations == [] and sorted(d.violation.device for d in covered.derogated) == ["r4", "r5"]
    assert covered.derogation_notes == []                                           # ni orpheline, ni expirée
    assert covered.derogation_file == (str(REPO / "derogations" / f"{lab}.yml"), dset.sha256)
    # Sans effet sur le code retour : conforme, code 0.
    assert compliance.verdict(covered.violations, covered.config_warnings) == (True, 0)


def test_a_real_violation_next_to_a_derogated_one_keeps_the_verdict_red():
    dset = derogations.load(REPO / "derogations" / "lab.yml", RULES, TODAY)
    devices = lab_devices("lab")
    text = devices["r4"].running_config
    assert text.count("ebgp-") == 0
    devices["r4"].running_config = re.sub(r" neighbor 172\.16\.34\.1 password .*\n", "", text)
    result = evaluate("lab", dset, devices=devices)
    assert [(v.rule.id, v.subject) for v in result.violations] == [
        ("ebgp-authentification-tcp-md5", "172.16.34.1")]
    assert len(result.derogated) == 2
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 2)


def test_after_expiry_the_lab_goes_red_again_and_says_why():
    dset = derogations.load(REPO / "derogations" / "lab.yml", RULES, TODAY)
    result = evaluate("lab", dset, today=date(2027, 1, 5))
    assert len(result.violations) == 2 and result.derogated == [] and len(result.reactivated) == 2
    assert [n.kind for n in result.derogation_notes] == [derogations.NOTE_EXPIRED]
    assert compliance.verdict(result.violations, result.config_warnings) == (False, 2)


def test_when_the_authentication_is_fixed_the_derogation_becomes_an_orphan():
    dset = derogations.load(REPO / "derogations" / "lab.yml", RULES, TODAY)
    devices = lab_devices("lab")
    for name, interface in (("r4", "eth2"), ("r5", "eth1")):
        text = devices[name].running_config
        marker = " ipv6 ospf6 network point-to-point\n"
        assert text.count(marker) == 1
        devices[name].running_config = text.replace(
            marker, marker + " ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key k\n")
    result = evaluate("lab", dset, devices=devices)
    assert result.violations == [] and result.derogated == []
    assert sorted(n.kind for n in result.derogation_notes) == [derogations.NOTE_ORPHAN] * 2


# ------------------------------------------------------------------------------------------
# Les trois sorties : terminal, JSON, HTML
# ------------------------------------------------------------------------------------------

def reports_for(lab="lab", today=TODAY, tmp_path=None):
    dset = derogations.load(REPO / "derogations" / f"{lab}.yml", RULES, today)
    result = evaluate(lab, dset, today=today)
    info = report.derogation_data(result)
    compliant, _ = compliance.verdict(result.violations, result.config_warnings)
    return dset, result, info, compliant


def terminal(result, info, compliant) -> str:
    console = Console(file=io.StringIO(), width=2000, force_terminal=False)
    report.print_compliance_terminal(result.violations, compliant, result.not_applicable, console,
                                     result.config_warnings, derogations=info)
    return console.file.getvalue()


def test_terminal_shows_the_status_the_justification_the_expiry_and_the_file_fingerprint():
    dset, result, info, compliant = reports_for()
    out = terminal(result, info, compliant)
    assert "DÉROGATION" in out and "DER-LAB-FRR-001" in out and "défaut" not in out.split("Dérogations")[0]
    assert "Lodric BOYER" in out and "2027-01-04" in out and "2026-10-04" in out
    assert f"sha256 {dset.sha256}" in out and str(REPO / "derogations" / "lab.yml") in out
    assert "2 dérogation(s)" in out and "CONFORME" in out and "NON CONFORME" not in out
    assert "r4" in out and "eth2" in out and "eth1" in out
    assert "sans effet sur le code retour" in out


def test_json_carries_the_derogations_counted_apart_and_the_fingerprint():
    dset, result, info, compliant = reports_for()
    data = report.compliance_to_dict(result.violations, compliant, result.not_applicable,
                                     result.config_warnings, derogations=info)
    assert data["status"] == "CONFORME" and data["compliant"] is True and data["violations"] == []
    assert data["summary"]["violations"] == 0 and data["summary"]["derogated"] == 2
    d = data["derogations"]
    assert d["file"] == {"path": str(REPO / "derogations" / "lab.yml"), "sha256": dset.sha256}
    assert [(x["status"], x["device"], x["object"], x["rule_id"]) for x in d["derogated"]] == [
        ("DÉROGATION", "r4", "eth2", OSPF6), ("DÉROGATION", "r5", "eth1", OSPF6)]
    first = d["derogated"][0]
    assert first["derogation_id"] == "DER-LAB-FRR-001" and first["expires"] == "2027-01-04"
    assert first["validated_on"] == "2026-10-04" and "SR Linux 26.7.2" in first["justification"]
    json.dumps(data)                                            # sérialisable


def test_without_a_derogation_file_the_reports_have_no_derogation_key():
    result = evaluate("lab")
    data = report.compliance_to_dict(result.violations, False, result.not_applicable, result.config_warnings)
    assert "derogations" not in data and "derogated" not in data["summary"]
    assert all("object" in v for v in data["violations"])        # l'objet est toujours dans le JSON
    assert report.derogation_data(result) is None


def test_html_shows_the_derogations_and_escapes_the_text(tmp_path):
    dset = derogations.load(write(tmp_path, entry(justification="<script>alert(1)</script> défaut connu",
                                                   validated_by="<b>moi</b>")), RULES, TODAY)
    result = evaluate("lab", dset)
    assert len(result.derogated) == 1
    html = report.render_compliance_html(result.violations, False, "rules", result.not_applicable,
                                         result.config_warnings, derogations=report.derogation_data(result))
    assert "DÉROGATION" in html and dset.sha256 in html and str(tmp_path / "d.yml") in html
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html and "<b>moi</b>" not in html


def test_secrets_in_a_justification_are_masked_in_all_three_outputs(tmp_path):
    secret = "MonSecretDeLab42"
    dset = derogations.load(write(tmp_path, entry(justification=f"clé de secours : password {secret}")),
                            RULES, TODAY)
    result = evaluate("lab", dset)
    info = report.derogation_data(result)
    compliant, _ = compliance.verdict(result.violations, result.config_warnings)
    data = report.compliance_to_dict(result.violations, compliant, result.not_applicable, derogations=info)
    html = report.render_compliance_html(result.violations, compliant, "r", result.not_applicable,
                                         derogations=info)
    assert secret not in json.dumps(data) and secret not in html
    assert secret not in terminal(result, info, compliant)


def test_an_expired_derogation_is_shown_on_the_violation_it_no_longer_covers():
    dset, result, info, compliant = reports_for(today=date(2027, 1, 5))
    out = terminal(result, info, compliant)
    assert "dérogation DER-LAB-FRR-001 expirée le 2027-01-04" in out and "NON CONFORME" in out
    # Chaque ligne de violation réactivée porte aussi la mention (le tableau replie les cellules : on lit la
    # mention produite par le rapport, et on la retrouve en entier dans le HTML ci-dessous).
    # La mention figure sur chaque ligne réactivée.
    assert out.count("expirée le 2027-01-04 : violation de nouveau active") == 2
    notes = report._reactivation(info)
    assert sorted(notes) == [(OSPF6, "r4", "eth2"), (OSPF6, "r5", "eth1")]
    assert all("expirée le 2027-01-04 : violation de nouveau active" in n for n in notes.values())
    data = report.compliance_to_dict(result.violations, compliant, result.not_applicable, derogations=info)
    assert {r["derogation_id"] for r in data["derogations"]["reactivated"]} == {"DER-LAB-FRR-001"}
    html = report.render_compliance_html(result.violations, compliant, "r", result.not_applicable,
                                         derogations=info)
    assert "expirée le 2027-01-04 : violation de nouveau active" in html


def test_the_thirty_day_information_reaches_the_three_outputs():
    dset, result, info, compliant = reports_for(today=date(2026, 12, 20))
    assert compliant and len(result.derogated) == 2             # sans effet sur le code
    assert "expire dans 15 jour(s)" in terminal(result, info, compliant)
    assert "expire dans 15 jour(s)" in json.dumps(report.compliance_to_dict(
        result.violations, compliant, result.not_applicable, derogations=info), ensure_ascii=False)
    assert "expire dans 15 jour(s)" in report.render_compliance_html(
        result.violations, compliant, "r", result.not_applicable, derogations=info)


# ------------------------------------------------------------------------------------------
# CLI : check --derogations --today (les fichiers de démarrage du dépôt, hors ligne)
# ------------------------------------------------------------------------------------------

SEC = ["--rules", str(RULE_FILES[0]), "--rules", str(RULE_FILES[1])]
CLI_LABS = {
    "lab": (["--config-dir", str(REPO / "configs")], REPO / "automation/inventory.yml"),
    "lab-multivendor": (["--config-dir", str(REPO / "configs"), "--config-dir",
                         str(REPO / "configs-multivendor")],
                        REPO / "automation/inventory-multivendor.yml"),
    "lab-ceos": (["--config-dir", str(REPO / "configs"), "--config-dir", str(REPO / "configs-ceos")],
                 REPO / "automation/inventory-ceos.yml"),
}


def check(lab, *extra, tmp_path=None):
    dirs, inv = CLI_LABS[lab]
    return cli.main(["check", *dirs, "-i", str(inv), *SEC, *extra])


@pytest.mark.parametrize("lab", list(CLI_LABS))
def test_cli_the_startup_files_of_each_lab_are_red_without_and_green_with_their_derogations(lab, capsys):
    assert check(lab) == 2
    capsys.readouterr()
    d = REPO / "derogations" / f"{lab}.yml"
    assert check(lab, "--derogations", str(d), "--today", "2026-10-05") == 0
    out = re.sub(r"\s+", "", capsys.readouterr().out)
    assert "DÉROGATION" in out and "CONFORME" in out and "NONCONFORME" not in out
    assert "sha256" + hashlib.sha256(d.read_bytes()).hexdigest() in out
    assert re.sub(r"\s+", "", str(d)) in out


def test_cli_after_expiry_the_exit_code_is_2_again(capsys):
    d = REPO / "derogations" / "lab.yml"
    assert check("lab", "--derogations", str(d), "--today", "2027-01-05") == 2
    assert "expirée" in capsys.readouterr().out


def test_cli_json_and_html_carry_path_and_fingerprint(tmp_path):
    d = REPO / "derogations" / "lab-ceos.yml"
    out_json, out_html = tmp_path / "c.json", tmp_path / "c.html"
    assert check("lab-ceos", "--derogations", str(d), "--today", "2026-10-05",
                 "--json", str(out_json), "--html", str(out_html)) == 0
    sha = hashlib.sha256(d.read_bytes()).hexdigest()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["derogations"]["file"] == {"path": str(d), "sha256": sha}
    assert data["summary"]["derogated"] == 2
    html = out_html.read_text(encoding="utf-8")
    assert sha in html and str(d) in html and "DÉROGATION" in html


@pytest.mark.parametrize("extra", [
    ["--today", "2026-10-05"],                                         # --today sans --derogations
    ["--derogations", "absent.yml"],
    ["--derogations", str(REPO / "derogations/lab.yml"), "--today", "demain"],
    # validated_on est alors dans le futur.
    ["--derogations", str(REPO / "derogations/lab.yml"), "--today", "2025-01-01"],
])
def test_cli_refuses_a_bad_derogation_request_with_code_3(extra, capsys):
    assert check("lab", *extra) == 3
    assert "Erreur" in capsys.readouterr().err


def test_cli_without_derogations_nothing_changes(capsys):
    assert check("lab") == 2
    out = capsys.readouterr().out
    assert "Dérogations" not in out and "DÉROGATION" not in out
