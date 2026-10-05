"""Le README dit ce que les outils de lab ne sont PAS (conditions posées à la revue de la phase C5).

`lab-access/pathz_lab.py` est un outil de lab épinglé sur SR Linux 26.7.2 : le README doit dire, au même
endroit, qu'en production la politique Pathz se pousse avec l'outillage gNSI officiel, et documenter la
sémantique de Pathz observée (c'est elle qui explique la forme de la politique).
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# les retours à la ligne ne comptent pas
README = re.sub(r"\s+", " ", (ROOT / "README.md").read_text(encoding="utf-8"))
CHANGELOG = re.sub(r"\s+", " ", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


def _section() -> str:
    start = README.index("**L'outil `lab-access/pathz_lab.py`")
    return README[start : README.index("**Preuves négatives**", start)]


def test_the_readme_says_pathz_lab_is_not_for_production():
    section = _section()
    assert "lab seulement, pas pour la production" in section
    assert "outillage gNSI officiel" in section and "pas avec ce script" in section


def test_the_readme_names_the_pinned_srlinux_version():
    assert "26.7.2" in _section() and "--allow-other-version" in _section()


@pytest.mark.parametrize(
    "phrase",
    [
        "`MODE_WRITE` **implique** la lecture",
        "**annule** l'écriture",
        "une seule règle en écriture, à la racine",
        "refuse les jokers",
    ],
)
def test_the_readme_documents_the_observed_pathz_semantics(phrase):
    assert phrase in README


def test_the_readme_states_the_four_guards_of_the_tool():
    section = _section()
    for word in ("TLS", "Identifiants", "Jamais de succès silencieux", "Cloisonné"):
        assert re.search(rf"\*\*{word}", section), word
    assert "--insecure" in section and "lab: true" in section and "NON EFFECTIVE" in section


def test_the_changelog_records_the_pathz_conditions():
    assert "outil Pathz conservé sous conditions" in CHANGELOG
    assert "vérification après envoi" in CHANGELOG
