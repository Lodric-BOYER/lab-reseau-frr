"""Non-régression de la conformité (SPEC_v4, Phase A) : le moteur répond comme netcheck 0.3.0.

tests/golden/compliance_*.json a été enregistré avec le code de la v0.3.0 (voir tests/tools/golden.py
et tests/golden/README.md) sur des entrées réelles, leurs mutations et des sondes nommées. Ces tests
recalculent et exigent la même réponse, constat par constat. Un écart est soit une régression, soit
un changement voulu, qui doit alors être justifié et documenté (jamais « régénéré pour que ça passe »).
"""
import json

import golden
import pytest

from netcheck import compliance


@pytest.mark.parametrize("rules_name", sorted(golden.RULE_FILES))
def test_verdicts_are_unchanged_since_v030(rules_name):
    diffs = golden.compare(rules_name)
    assert not diffs, f"{len(diffs)} écart(s) avec le gel v0.3.0 :\n" + "\n".join(diffs[:10])


@pytest.mark.parametrize("rules_name", sorted(golden.RULE_FILES))
def test_golden_is_not_vacuous(rules_name):
    """Un gel qui ne contient presque rien ne prouverait rien : il doit couvrir des équipements des
    trois constructeurs, des états conformes et non conformes, et chaque règle du fichier."""
    data = json.loads(golden.golden_path(rules_name).read_text(encoding="utf-8"))
    cases = data["cases"]
    assert data["meta"]["netcheck_version"] == "0.3.0"
    for needed in ("fixture:frr-r3", "fixture:srlinux-r5", "fixture:srlinux-r5-hardened",
                   "fixture:eos-r4", "config:frr-r3", "config:eos-r4", "lab:frr", "lab:multivendor",
                   "lab:ceos", "lab:config-frr"):
        assert needed in cases, needed
    # Le r5 durci (relevé sur le lab mixte) est conforme : c'est le chemin « conforme » de SR Linux.
    assert cases["fixture:srlinux-r5-hardened"]["base"]["compliant"] is True

    bases = [c["base"] for c in cases.values()]
    assert not any("error" in b for b in bases)
    if rules_name == "security":
        assert any(b["compliant"] for b in bases) and any(not b["compliant"] for b in bases)
    assert sum(c.get("mutants_total", 0) for c in cases.values()) > 1000

    # Chaque règle du fichier est violée au moins une fois, dans la base ou dans une mutation.
    violated = set()
    for case in cases.values():
        for record in [case["base"], *case.get("mutants_changed", {}).values()]:
            violated |= {v[1] for v in record.get("violations", [])}
    rule_ids = {r.id for r in compliance.load_rules(golden.RULE_FILES[rules_name])}
    assert rule_ids - violated == set(), f"règles jamais exercées par le gel : {sorted(rule_ids - violated)}"
