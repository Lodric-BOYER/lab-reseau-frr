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
        "check --config-dir avec les règles default.yml sort en code 1",
        "refuse AVANT d'exécuter le changement",
        "--accept-unverified r6,r7",
        "jamais de joker, jamais « all »",
        "le verdict final n'est jamais 0",
        "Le gel des verdicts (tests/golden/) ne bouge pas",
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
