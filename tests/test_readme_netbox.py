"""Le README et le CHANGELOG disent ce que le client NetBox fait ET ne fait pas (phases C6.1 et C6.2)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = re.sub(r"\s+", " ", (ROOT / "README.md").read_text(encoding="utf-8"))
CHANGELOG = re.sub(r"\s+", " ", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


def _section() -> str:
    start = README.index("### Inventaire NetBox (v4, phase C6)")
    return README[start : README.index("### Codes retour", start)]


@pytest.mark.parametrize(
    "phrase",
    [
        "Liste blanche exacte : deux appels",
        "`GET /api/status/` et `GET /api/dcim/devices/`",
        "jamais en option de commande",
        "jeton v1 est refusé",
        "NetBox n'est jamais contacté",
        "sans repli",
        "zéro équipement",
        "NON ÉVALUABLE",
        "tous les conflits listés ensemble",
        "faux NetBox local",
        "contre un vrai NetBox de lab",
        "NetBox de lab (v4, phase C6.2)",
        "uniquement** dans notre instance locale",
        "`POST`, `PUT`, `PATCH` et `DELETE` sur un équipement donnent **403**",
        "jeton refusé, HTTP 403",
        "lien de pagination hors du NetBox configuré",
        "après **2 requêtes** seulement",
        "`page_size: N`",
        "`--accept-unverified r9`",
        "`GET /api/users/tokens/` = 200",
        "`allowed_ips` n'est pas posé",
        "127.0.0.1:8000 uniquement",
    ],
)
def test_the_readme_states_the_guarantees_and_the_limit_of_the_proof(phrase):
    section = _section().replace("**", "")
    assert phrase.replace("**", "").lower() in section.lower(), phrase


def test_the_readme_gives_the_block_the_token_and_the_http_rule():
    section = _section()
    assert "netbox:" in section and "platforms:" in section and "NETCHECK_NETBOX_TOKEN_FILE" in section
    assert "`lab: true`" in section and "bouclage" in section and "--netbox-cacert" in section


def test_the_changelog_records_the_deviation_from_c26():
    assert "Écart avec SPEC C26" in CHANGELOG and "pynetbox" in CHANGELOG and "extra `[netbox]`" in CHANGELOG
    assert "aucune dépendance nouvelle" in CHANGELOG
