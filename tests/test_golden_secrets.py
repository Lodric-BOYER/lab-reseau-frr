"""Aucun secret de lab non masqué dans tests/golden/*.json (SPEC_v4, Phase A).

Les fichiers d'or sont des RAPPORTS : ils passent par le même masquage que les rapports publiés.
Ce test le prouve en cherchant, dans leur texte, chaque valeur de secret connue du lab. La liste
n'est pas recopiée à la main : elle est extraite des configurations réelles du dépôt (fixtures,
copies figées, configurations de démarrage), pour qu'une valeur ajoutée plus tard soit couverte.
Les copies figées de tests/golden/inputs/ contiennent, elles, ces valeurs (ce sont des
configurations réelles de lab) : seuls les fichiers .json sont contrôlés.
"""
import re
from pathlib import Path

import golden

REPO = Path(__file__).resolve().parent.parent
# Identifiants par défaut des images (documentés dans le README, « Secrets du lab »).
LAB_CREDENTIALS = ("netops", "admin", "NokiaSrl1!")
_TOKEN_PATTERNS = [
    r"lab-(?:ospf|bgp)-[A-Za-z0-9]+",     # clés OSPF et mots de passe BGP du lab
    r"\$aes1\$[^\s'\"]+",                  # clé obscurcie par SR Linux
    r"\$6\$[^\s'\"]+",                     # hash sha512 du compte admin
    r"(?:md5|password) 7 ([^\s'\"]+)",     # type 7 EOS (réversible) : la valeur seule
]
# Les valeurs « $aes1$ » de SR Linux ne sont pas dans les fixtures (capturées avant le durcissement) :
# elles vivent dans des chaînes de tests, relevées sur le lab durci.
_SOURCES = [
    *sorted((REPO / "tests" / "fixtures").rglob("*.txt")),
    *sorted((REPO / "tests" / "golden" / "inputs").glob("*")),
    REPO / "configs-multivendor" / "r5" / "config.cli",
    REPO / "tests" / "test_secrets.py",
    REPO / "tests" / "test_compliance.py",
]


def lab_secret_values() -> set[str]:
    values: set[str] = set()
    for path in _SOURCES:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in _TOKEN_PATTERNS:
            for m in re.finditer(pattern, text):
                values.add(m.group(1) if m.groups() else m.group(0))
    return values


def find_leaks(text: str) -> list[str]:
    """Valeurs de secret de lab présentes dans `text` (identifiants : mot entier seulement, car
    « admin » est aussi un préfixe de « admin-state » côté SR Linux)."""
    leaks = [v for v in lab_secret_values() if v in text]
    for cred in LAB_CREDENTIALS:
        if re.search(rf"(?<![\w-]){re.escape(cred)}(?![\w-])", text):
            leaks.append(cred)
    return sorted(leaks)


def test_the_detector_knows_the_lab_secrets():
    """Garde-fou contre un test vide : la liste extraite contient bien les valeurs attendues."""
    values = lab_secret_values()
    assert {"lab-bgp-r3r4", "lab-ospf-r1r3", "lab-ospf-r4r5"} <= values
    # Relevés de peer groups (A4) : mots de passe en clair côté FRR, hash « type 7 » côté EOS.
    assert {"lab-bgp-pgtest", "lab-bgp-pggroup", "lab-bgp-pgmember", "lab-bgp-pgorphan"} <= values
    eos_group = (REPO / "tests" / "fixtures" / "peergroups" / "eos_s1_group.txt").read_text(encoding="utf-8")
    assert re.search(r"neighbor PG-TEST password 7 (\S+)", eos_group).group(1) in values
    assert any(v.startswith("$aes1$") for v in values)
    assert any(v.startswith("$6$") for v in values)
    assert len(values) >= 8


def test_the_detector_flags_a_leak():
    assert find_leaks("ligne interdite : neighbor 10.0.0.1 password lab-bgp-r3r4") == ["lab-bgp-r3r4"]
    assert find_leaks("username admin privilege 15") == ["admin"]
    assert find_leaks("interface ethernet-1/1 admin-state enable") == []
    assert find_leaks("neighbor 10.0.0.1 password ****") == []


def test_no_lab_secret_in_the_golden_files():
    files = sorted(golden.GOLDEN_DIR.glob("*.json"))
    assert files, "aucun fichier d'or"
    for path in files:
        assert find_leaks(path.read_text(encoding="utf-8")) == [], path.name
