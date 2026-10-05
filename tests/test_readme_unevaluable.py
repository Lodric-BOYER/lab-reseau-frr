"""La documentation dit la règle « jamais de code 0 si NON ÉVALUABLE », l'état des lieux et l'option."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = (
    re.sub(r"\s+", " ", (ROOT / "README.md").read_text(encoding="utf-8")).replace("**", "").replace("`", "")
)
CHANGELOG = re.sub(r"\s+", " ", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")).replace("**", "")


def _section() -> str:
    start = README.index("### Jamais de code 0 avec des parties NON ÉVALUABLES")
    return README[start : README.index("### Codes retour", start)]


@pytest.mark.parametrize(
    "phrase",
    [
        "ne sort jamais en code 0",
        "mesuré avant la correction",
        "ANALYSE INCOMPLÈTE, code 1",
        "ATTENTION, code 1",
        "check --config-dir avec default.yml sort en code 0 quand tout ce qui est dans le périmètre",
        "HORS PÉRIMÈTRE (driver : srlinux)",
        "HORS PÉRIMÈTRE (source : hors ligne)",
        "sources: [live, snapshot]",
        "Une règle qui lit l'état collecté SANS cette déclaration reste ANALYSE INCOMPLÈTE (code 1)",
        "rien n'a été audité : check sort en code 3",
        "Une seule règle pour le code de check : zéro couple (règle, équipement) évalué",
        "c'était un faux OK, corrigé",
        "ÉQUIPEMENT INJOIGNABLE",
        "« NON AUDITÉ » désigne autre chose",
        "refuse AVANT d'exécuter le changement",
        "--accept-unverified r6,r7",
        "jamais de joker, jamais « all »",
        "le verdict final n'est jamais 0",
        "Le gel des verdicts (tests/golden/) enregistre la réponse du moteur, pas le code de la commande",
    ],
)
def test_the_readme_states_the_rule_the_inventory_of_behaviours_and_the_opt_in(phrase):
    assert phrase.replace("`", "").lower() in _section().lower(), phrase


def test_the_five_commands_are_listed_in_the_before_after_table():
    section = _section()
    for command in ("assert", "check", "diff", "monitor", "guard"):
        assert f"| {command} |" in section, command


def test_the_exit_code_table_and_the_other_docs_follow():
    assert "aucun échec mais au moins une assertion NON ÉVALUABLE" in README
    assert "ou analyse incomplète" in README
    assert "NON ÉVALUABLE ne change pas le code" not in (ROOT / "netcheck" / "README.md").read_text(
        encoding="utf-8"
    )
    assert "1 ATTENTION" in (ROOT / "intents" / "lab.yml").read_text(encoding="utf-8")


def test_the_changelog_lists_the_incompatible_changes_and_the_tls_distinction():
    assert "Modifié (incompatible)" in CHANGELOG and "ne sort plus jamais en code 0" in CHANGELOG
    assert "--accept-unverified r6,r7" in CHANGELOG and "assert == 0" in CHANGELOG
    assert "ne parle pas TLS sur ce port" in CHANGELOG and "RECORD_LAYER_FAILURE" in CHANGELOG


def test_the_changelog_records_the_nothing_audited_false_ok_under_security_and_incompatible():
    start = CHANGELOG.index("### Sécurité")
    security = CHANGELOG[start : CHANGELOG.index("### Corrigé", start)]
    assert "`check` ne sort plus en CONFORME quand rien n'a été audité" in security
    assert "faux OK préexistant" in security and "code 3" in security
    incompatible = CHANGELOG[CHANGELOG.index("### Modifié (incompatible)") : start]
    assert "zéro couple (règle, équipement) évalué" in incompatible and "unreachable" in incompatible
