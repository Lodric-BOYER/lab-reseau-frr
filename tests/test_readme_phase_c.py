"""Le README tient ensemble la phase C : vue d'ensemble, écarts à la SPEC, licences (phase C7)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RAW = (ROOT / "README.md").read_text(encoding="utf-8")
README = re.sub(r"\s+", " ", RAW).replace("**", "").replace("`", "")


def _between(start: str, end: str) -> str:
    begin = README.index(start)
    return README[begin : README.index(end, begin)]


OVERVIEW = _between("### Phase C, accès d'entreprise : vue d'ensemble", "### Clés d'hôte SSH et migration")
LICENCE = _between("## Licence", "## Dépannage")


def test_the_overview_lists_the_seven_steps_with_their_tool_and_their_proof():
    for step, proof in (
        ("C1", "pin_hostkeys.sh"),
        ("C2", "tests/lib_"),
        ("C3", "tests/integration_vault.sh"),
        ("C4", "tests/lib_bastion.sh"),
        ("C5", "tests/lib_ro.sh"),
        ("C6", "tests/integration_netbox.sh"),
        ("C7", "tests/integration_e2e.sh"),
    ):
        row = re.search(rf"\| {step} \|[^|]*\|[^|]*\|[^|]*\|", OVERVIEW)
        assert row and proof in row.group(0), (step, proof)


def test_every_script_and_tool_named_in_the_overview_exists():
    start = RAW.index("### Phase C, accès")
    overview = RAW[start : RAW.index("### Clés d'hôte SSH et migration", start)]
    names = set(re.findall(r"(?:lab-access|tests)/[A-Za-z0-9_/.-]+\.(?:sh|py)", overview))
    names = {n for n in names if not n.endswith("lib_")}
    missing = sorted(n for n in names if not (ROOT / n).exists())
    assert not missing, missing


@pytest.mark.parametrize(
    "phrase",
    [
        "Écarts à la SPEC v4",
        "Pas de pynetbox côté netcheck",
        "SPEC C26",
        "Pathz de SR Linux par un outil de lab maison",
        "gnsic",
        "show running-config sanitized refusé",
        "Aucun repli silencieux",
        "rien n'a été évalué sort en code 3",
        "snapshots/c7-ref-<lab>",
    ],
)
def test_the_overview_states_the_principles_and_the_deviations_from_the_spec(phrase):
    assert phrase.lower() in OVERVIEW.lower(), phrase


def test_the_licence_says_paramiko_and_scp_are_lgpl_not_apache():
    assert "paramiko" in LICENCE and "scp" in LICENCE and "LGPL-2.1" in LICENCE
    assert "sans modification" in LICENCE and "non redistribuées" in LICENCE
    assert "permissives (MIT ou BSD)" not in LICENCE   # l'ancienne phrase, fausse pour paramiko et scp


def test_the_pyproject_says_the_same_about_the_indirect_lgpl_dependencies():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "paramiko et scp, sont LGPL-2.1" in text and "DIRECTE" in text
