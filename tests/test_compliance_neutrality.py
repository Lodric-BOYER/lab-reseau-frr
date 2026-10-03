"""Critère de fin de la Phase A3 (SPEC_v4 §4) : `compliance.py` ne contient plus aucune syntaxe de
constructeur. Aucune chaîne de son code (hors docstrings) ne nomme une commande, un protocole ou un
mot-clé de configuration : tout cela vit dans les drivers (`drivers/<nom>_rules.py`)."""
import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Mots-clés de configuration des trois constructeurs et noms des drivers. Un mot générique du métier
# (« interface », « loopback ») n'y figure pas : le moteur lit le modèle normalisé, qui les connaît.
FORBIDDEN = re.compile(
    r"neighbor|route-map|prefix-list|\bbgp\b|\bospf\b|keychain|login-banner|management api|"
    r"passive-interface|maximum-(?:prefix|routes)|ttl-security|maximum-hops|exit-address-family|"
    r"interface-type|message-digest|vtysh|sr_cli|\bfrr\b|srlinux|\beos\b|arista|nokia", re.IGNORECASE)


def code_strings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def test_compliance_py_contains_no_vendor_syntax():
    offenders = [s for s in code_strings(REPO / "netcheck" / "compliance.py") if FORBIDDEN.search(s)]
    assert offenders == []


def test_the_guard_can_fail():
    """Garde-fou contre un test aveugle : le motif reconnaît bien les syntaxes des trois constructeurs."""
    for sample in ("neighbor 1.1.1.1 remote-as 2", "ip ospf area 0", "route-map X permit 10", "keychain k",
                   "management api http-commands", "passive-interface default", "router bgp 65001 # bgp"):
        assert FORBIDDEN.search(sample), sample


def test_the_engine_lost_its_vendor_helpers():
    from netcheck import compliance
    stale = [name for name in dir(compliance)
             if re.match(r"_(?:check|eos|srlinux|bgp|interface|route_map|prefix_list|ospf)_", name)
             and name not in ("_check_line_present", "_check_line_absent",
                              "_check_interface_description_required", "_check_unique_ids")]
    assert stale == []
