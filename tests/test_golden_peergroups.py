"""Le gel des peer groups (SPEC_v4, A4) contient EXACTEMENT les réponses validées.

Les réponses de base ajoutées au gel par `golden.py add --current-code` ont été validées sous forme de
tableau (cas, v0.3.0, nouvelle réponse, justification). Ce test les compare, automatiquement, aux attentes
écrites à la main dans test_bgp_neighbors.py : le gel ne peut donc pas enregistrer autre chose que ce qui a
été validé, même si le moteur change un jour (c'est alors le test de comparaison au gel qui échoue, et ce
test qui dit si le gel lui-même était juste).
"""
import json
import re

import golden
import pytest
from test_bgp_neighbors import EOS_EXPECTED, EOS_KINDS, FRR_EXPECTED, FRR_KINDS

from netcheck import compliance

CASES = {f"peergroup:{name}": (name.split("_")[0], expected)
         for name, expected in {**FRR_EXPECTED, **EOS_EXPECTED}.items()}


def kinds_by_rule(rules_name):
    return {r.id: r.kind for r in compliance.load_rules(golden.RULE_FILES[rules_name])}


def frozen(rules_name):
    return json.loads(golden.golden_path(rules_name).read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_frozen_peergroup_answers_are_the_validated_table(case_id):
    vendor, expected = CASES[case_id]
    watched = FRR_KINDS if vendor == "frr" else EOS_KINDS
    seen: dict[str, set[str]] = {kind: set() for kind in watched}
    covered: set[str] = set()
    for rules_name in golden.RULE_FILES:
        by_rule = kinds_by_rule(rules_name)
        covered |= {k for k in by_rule.values() if k in watched}
        for severity, rule_id, device, detail, category in frozen(rules_name)[case_id]["base"]["violations"]:
            kind = by_rule[rule_id]
            assert kind in watched, f"{case_id} : violation d'une règle hors tableau : {rule_id} {detail}"
            seen[kind].add(re.match(r"voisin eBGP (\S+)", detail).group(1))
    # Le tableau ne vaut que si les règles qu'il décrit sont bien dans les fichiers de règles évalués.
    assert covered == set(watched)
    assert {kind: sorted(neighbors) for kind, neighbors in seen.items()} == expected


def test_every_peergroup_capture_is_frozen_with_mutations():
    for rules_name in golden.RULE_FILES:
        cases = frozen(rules_name)
        for case_id in CASES:
            assert cases[case_id]["mutants_total"] > 50, case_id
            assert "error" not in cases[case_id]["base"]


def test_the_maximum_routes_zero_case_is_frozen_as_validated():
    """Une limite posée à 0 (illimité sur EOS) sur un membre dont le groupe a une limite : signalée.
    La v0.3.0 répondait « conforme, code 0 » (le membre n'était pas vu) ; apparu avec le commit fe6b04e."""
    case_id = "scenario:eos-peergroup-member-maximum-routes-0"
    base = frozen("security")[case_id]["base"]
    assert base["compliant"] is False and base["code"] == 1
    assert [v[1:4] for v in base["violations"]] == [
        ["eos-ebgp-maximum-routes", "r4",
         "voisin eBGP 192.0.2.4 (peer group PG-OVR) : maximum-routes 0 (illimité) n'est pas une limite"]]
    assert frozen("default")[case_id]["base"]["violations"] == []
