"""La documentation dit ce que `check --snapshot` et `assert --snapshot` affichent et décident (phase C6)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = (
    re.sub(r"\s+", " ", (ROOT / "README.md").read_text(encoding="utf-8")).replace("**", "").replace("`", "")
)
CHANGELOG = (
    re.sub(r"\s+", " ", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    .replace("**", "")
    .replace("`", "")
)


def _section() -> str:
    start = README.index("### Couverture et fraîcheur d'un snapshot lu hors ligne")
    return README[start : README.index("### Codes retour", start)]


@pytest.mark.parametrize(
    "phrase",
    [
        "affichent donc toujours",
        "snapshot_scope",
        "avec netcheck 0.4.0",
        "périmètre du snapshot : r5 (1/5 de l'inventaire)",
        "scope = {inventory:",
        "périmètre demandé par -d",
        "sans effet sur le code",
        "« ANALYSE INCOMPLÈTE » (code 1)",
        "périmètre inconnu (snapshot sans métadonnée de périmètre), 5/5 présents",
        "NetBox n'est jamais contacté",
        "--max-age JOURS",
        "aucune valeur par défaut",
        "sort en code 3",
    ],
)
def test_the_readme_states_what_is_displayed_and_decided(phrase):
    assert phrase.lower() in _section().lower(), phrase


def test_the_changelog_lists_the_incompatible_change_and_the_new_option():
    start = CHANGELOG.index("### Modifié (incompatible)")
    section = CHANGELOG[start : CHANGELOG.index("### Modifié", start + 10)]
    assert "check --snapshot et assert --snapshot disent ce que le snapshot couvre" in section
    assert "--max-age JOURS" in section and "meta.json gagne scope" in section


def test_the_module_is_listed_in_both_readmes():
    assert "netcheck/snapshotscope.py" in README
    assert "snapshotscope.py" in (ROOT / "netcheck" / "README.md").read_text(encoding="utf-8")
