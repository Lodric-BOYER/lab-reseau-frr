"""Tests du rapport HTML : sécurité (XSS) et autonomie, demandés explicitement pour la phase 3.

Le contexte : les messages des constats contiennent du texte venant des équipements (lignes
de config, noms d'interface...), jamais de confiance. Une description d'interface malveillante
du type '<script>alert(1)</script>' doit ressortir échappée, jamais exécutable.
"""
from netcheck import report
from netcheck.compliance import Rule, Violation
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
