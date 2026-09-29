"""Tests du rapport HTML : sécurité (XSS) et autonomie, demandés explicitement pour la phase 3.

Le contexte : les messages des constats contiennent du texte venant des équipements (lignes
de config, noms d'interface...), jamais de confiance. Une description d'interface malveillante
du type '<script>alert(1)</script>' doit ressortir échappée, jamais exécutable.
"""
from rich.console import Console

from netcheck import report
from netcheck.compliance import NotApplicable, Rule, Violation
from netcheck.diff import Finding, Severity


def test_jinja_autoescape_is_explicitly_enabled():
    # Pas seulement "par défaut sur les .html" : autoescape=True est passé explicitement
    # à l'Environment (voir report.py), indépendamment de l'extension du gabarit.
    assert report._ENV.autoescape is True


def test_html_escapes_xss_payload_from_device_data():
    # Cas réaliste : une description d'interface piégée, telle qu'elle apparaîtrait dans
    # un diff de configuration (catégorie "config", §5.6).
    payload = "<script>alert(1)</script>"
    findings = [Finding(Severity.INFO, "config", "r1", f"+ description {payload}")]

    html = report.render_html(findings, "OK", "avant", "apres")

    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_escapes_xss_payload_in_every_text_field():
    # Le payload peut arriver par n'importe quel champ texte d'un Finding (device, category,
    # message) : device et category viennent aussi des équipements dans un futur driver.
    # Le device apparaît en plus dans un attribut HTML (data-device, <option value>) : un
    # contexte d'échappement différent, qui doit rester sûr lui aussi.
    payload = "<img src=x onerror=alert(1)>"
    findings = [Finding(Severity.CRITIQUE, payload, payload, payload)]

    html = report.render_html(findings, "ÉCHEC", "avant", "apres")

    assert payload not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_never_uses_innerhtml():
    # Le filtrage JS ne doit jamais réinjecter de texte : uniquement montrer/cacher des
    # lignes déjà rendues (et échappées) côté serveur, via l'attribut "hidden".
    findings = [Finding(Severity.INFO, "route", "r1", "nouvelle route : 10.0.0.0/8")]
    html = report.render_html(findings, "OK", "avant", "apres")
    assert "innerHTML" not in html


def test_html_report_is_self_contained_no_external_resources():
    # Rapport "autonome" (§5.6) : aucun appel réseau, aucune ressource externe.
    findings = [
        Finding(Severity.CRITIQUE, "bgp_session", "r3", "session BGP 172.16.34.2 n'est plus Established"),
        Finding(Severity.ATTENTION, "metric", "r1", "métrique modifiée pour 192.168.2.0/24 : 20 -> 30"),
        Finding(Severity.INFO, "config", "r2", "+ ip ospf cost 50"),
    ]
    html = report.render_html(findings, "ÉCHEC", "avant", "apres")

    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html


def test_html_report_empty_findings_still_renders():
    html = report.render_html([], "OK", "avant", "apres")
    assert "Verdict : OK" in html
    assert "Aucun constat." in html


# -- Rapport de conformité (netcheck check) : même rigueur de sécurité que le rapport diff --

def test_compliance_html_escapes_xss_payload():
    payload = "<script>alert(1)</script>"
    rule = Rule(id="r", description=payload, severity="critique", applies_to="all", kind="line_present")
    violations = [Violation(rule=rule, device="r1", detail=f"ligne interdite : {payload}")]

    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/default.yml")

    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_compliance_html_never_uses_innerhtml():
    rule = Rule(id="r", description="d", severity="basse", applies_to="all", kind="line_present")
    violations = [Violation(rule=rule, device="r1", detail="x")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/default.yml")
    assert "innerHTML" not in html


def test_compliance_html_is_self_contained_no_external_resources():
    rule = Rule(
        id="r", description="d", severity="haute", applies_to="all", kind="bgp_neighbor_inbound_policy",
    )
    violations = [Violation(rule=rule, device="r3", detail="voisin eBGP 172.16.34.2 sans politique")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/default.yml")
    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html


def test_compliance_html_conforme_still_renders():
    html = report.render_compliance_html([], compliant=True, rules_path="rules/default.yml")
    assert "CONFORME" in html
    assert "Aucune non-conformité." in html


# -- "Non applicable" (Phase D2) : présent dans les 3 sorties, jamais compté comme violation --

def test_not_applicable_appears_in_html():
    rule = Rule(id="frr-only", description="d", severity="haute", applies_to="all",
                drivers=["frr"], kind="line_present")
    na = [NotApplicable(rule=rule, device="r5", reason="driver 'srlinux' non couvert")]
    html = report.render_compliance_html(
        [], compliant=True, rules_path="rules/default.yml", not_applicable=na)
    assert "Non applicable" in html
    assert "r5" in html
    assert "frr-only" in html


def test_not_applicable_is_xss_escaped_in_html():
    payload = "<script>alert(1)</script>"
    rule = Rule(id="r", description="d", severity="haute", applies_to="all",
                drivers=["frr"], kind="line_present")
    na = [NotApplicable(rule=rule, device=payload, reason=payload)]
    html = report.render_compliance_html(
        [], compliant=True, rules_path="rules/default.yml", not_applicable=na)
    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_not_applicable_absent_when_empty():
    html = report.render_compliance_html([], compliant=True, rules_path="rules/default.yml")
    assert "Non applicable" not in html


def test_not_applicable_appears_in_json():
    rule = Rule(id="frr-only", description="d", severity="haute", applies_to="all",
                drivers=["frr"], kind="line_present")
    na = [NotApplicable(rule=rule, device="r5", reason="driver 'srlinux' non couvert")]
    d = report.compliance_to_dict([], compliant=True, not_applicable=na)
    assert d["not_applicable"] == [
        {"rule_id": "frr-only", "device": "r5", "reason": "driver 'srlinux' non couvert",
         "category": None, "references": None}
    ]
    assert d["violations"] == []  # jamais mélangé aux violations


def test_not_applicable_empty_list_in_json_when_omitted():
    d = report.compliance_to_dict([], compliant=True)
    assert d["not_applicable"] == []


# ------------------------------------------------------------------------------------------
# Masquage des secrets (Phase A, suite -- avant la Phase B) : les trois sorties, pour les deux
# familles de rapport (diff et conformité). netcheck.secrets a ses propres tests unitaires
# (tests/test_secrets.py) ; ceux-ci vérifient seulement que report.py l'applique bien partout.
# ------------------------------------------------------------------------------------------

def test_diff_html_masks_secret_in_config_diff():
    findings = [Finding(Severity.INFO, "config",
                         "r1", "+ ip ospf message-digest-key 1 md5 CleDeLabUniquement")]
    html = report.render_html(findings, "OK", "avant", "apres")
    assert "CleDeLabUniquement" not in html
    assert "message-digest-key 1 md5 ****" in html


def test_diff_terminal_masks_secret():
    findings = [Finding(Severity.INFO, "config", "r1", "+ neighbor 172.16.34.2 password Secret")]
    console = Console(record=True, width=120)
    report.print_terminal(findings, "OK", console=console)
    text = console.export_text()
    assert "Secret" not in text
    assert "password ****" in text


def test_diff_json_masks_secret():
    findings = [Finding(Severity.INFO, "config", "r1", "+ key-string SecretDeKeyChain")]
    d = report.to_dict(findings, "OK")
    assert "SecretDeKeyChain" not in d["findings"][0]["message"]
    assert "key-string ****" in d["findings"][0]["message"]


def test_compliance_html_masks_secret_in_violation_detail():
    rule = Rule(id="x", description="d", severity="critique", applies_to="all", kind="line_absent")
    violations = [Violation(rule=rule, device="r1", detail="ligne interdite trouvée : 'password secret123'")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/security.yml")
    assert "secret123" not in html
    assert "password ****" in html


def test_compliance_terminal_masks_secret():
    rule = Rule(id="x", description="d", severity="critique", applies_to="all", kind="line_absent")
    violations = [Violation(rule=rule, device="r1", detail="ligne interdite trouvée : 'password secret123'")]
    console = Console(record=True, width=120)
    report.print_compliance_terminal(violations, compliant=False, console=console)
    text = console.export_text()
    assert "secret123" not in text
    assert "password ****" in text


def test_compliance_json_masks_secret():
    rule = Rule(id="x", description="d", severity="critique", applies_to="all", kind="line_absent")
    violations = [Violation(rule=rule, device="r1", detail="ligne interdite trouvée : 'password secret123'")]
    d = report.compliance_to_dict(violations, compliant=False)
    assert "secret123" not in d["violations"][0]["detail"]
    assert "password ****" in d["violations"][0]["detail"]


def test_compliance_masking_does_not_mutate_the_original_violation():
    # report.py travaille sur une copie (dataclasses.replace) : l'objet Violation d'origine,
    # potentiellement réutilisé ailleurs (JSON écrit en plus du terminal, par ex.), garde son
    # detail complet.
    rule = Rule(id="x", description="d", severity="critique", applies_to="all", kind="line_absent")
    original = Violation(rule=rule, device="r1", detail="ligne interdite trouvée : 'password secret123'")
    report.compliance_to_dict([original], compliant=False)
    assert original.detail == "ligne interdite trouvée : 'password secret123'"


# ------------------------------------------------------------------------------------------
# Références et catégorie (Phase A, sécurité, C14)
# ------------------------------------------------------------------------------------------

def test_references_rendered_as_links_in_html():
    rule = Rule(id="ospf-auth", description="d", severity="haute", applies_to="all",
                drivers=["frr"], kind="line_present", category="ospf",
                references=[{"title": "RFC 2328", "url": "https://www.rfc-editor.org/rfc/rfc2328.html"}])
    violations = [Violation(rule=rule, device="r1", detail="x")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/security.yml")
    assert 'href="https://www.rfc-editor.org/rfc/rfc2328.html"' in html
    assert "RFC 2328" in html


def test_reference_title_and_url_are_escaped_against_xss():
    payload = "<script>alert(1)</script>"
    rule = Rule(id="x", description="d", severity="haute", applies_to="all", kind="line_present",
                references=[{"title": payload, "url": payload}])
    violations = [Violation(rule=rule, device="r1", detail="x")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/security.yml")
    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_no_references_no_reference_block_in_html():
    rule = Rule(id="x", description="d", severity="basse", applies_to="all", kind="line_present")
    violations = [Violation(rule=rule, device="r1", detail="x")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/default.yml")
    assert "Réf. :" not in html


def test_category_filter_select_present_in_html():
    rule = Rule(id="x", description="d", severity="haute", applies_to="all", kind="line_present",
                category="bgp")
    violations = [Violation(rule=rule, device="r3", detail="x")]
    html = report.render_compliance_html(violations, compliant=False, rules_path="rules/security.yml")
    assert 'id="f-category"' in html
    assert "<option value=\"bgp\">bgp</option>" in html


def test_violation_json_includes_category_and_references():
    rule = Rule(id="x", description="d", severity="haute", applies_to="all", kind="line_present",
                category="bgp", references=[{"title": "RFC 7454", "url": "https://www.rfc-editor.org/rfc/rfc7454.html"}])
    violations = [Violation(rule=rule, device="r3", detail="x")]
    d = report.compliance_to_dict(violations, compliant=False)
    assert d["violations"][0]["category"] == "bgp"
    assert d["violations"][0]["references"] == [
        {"title": "RFC 7454", "url": "https://www.rfc-editor.org/rfc/rfc7454.html"}
    ]


def test_violation_json_category_and_references_none_when_absent():
    rule = Rule(id="x", description="d", severity="basse", applies_to="all", kind="line_present")
    violations = [Violation(rule=rule, device="r1", detail="x")]
    d = report.compliance_to_dict(violations, compliant=False)
    assert d["violations"][0]["category"] is None
    assert d["violations"][0]["references"] is None


def test_references_listed_in_terminal_output():
    rule = Rule(id="ospf-auth", description="d", severity="haute", applies_to="all", kind="line_present",
                references=[{"title": "RFC 2328", "url": "https://www.rfc-editor.org/rfc/rfc2328.html"}])
    violations = [Violation(rule=rule, device="r1", detail="x")]
    console = Console(record=True, width=120)
    report.print_compliance_terminal(violations, compliant=False, console=console)
    text = console.export_text()
    assert "Références" in text
    assert "RFC 2328" in text


def test_not_applicable_appears_in_terminal():
    rule = Rule(id="frr-only", description="d", severity="haute", applies_to="all",
                drivers=["frr"], kind="line_present")
    na = [NotApplicable(rule=rule, device="r5", reason="driver 'srlinux' non couvert")]
    console = Console(record=True, width=120)
    report.print_compliance_terminal([], compliant=True, not_applicable=na, console=console)
    text = console.export_text()
    assert "Non applicable" in text
    assert "r5" in text
    assert "1 non applicable" in text
