"""
test_reportlab_generator.py
Unit tests for ReportLab security incident PDF report generation.
"""

import os
from src.reporting.reportlab_generator import generate_security_report


def test_missing_brand_reference_never_uses_paypal_image(tmp_path, monkeypatch):
    from src.reporting import reportlab_generator as generator
    monkeypatch.setattr(generator, 'REPORT_OUTPUT_DIR', str(tmp_path))
    def reject_image(*args, **kwargs):
        raise AssertionError('A report with no visual evidence must not use another brand image')
    monkeypatch.setattr(generator, 'Image', reject_image)
    path = generator.generate_security_report({'domain': 'suspect.example', 'matched_brand': 'unrelated.example', 'risk_level': 'LOW', 'risk_score': 12})
    assert os.path.getsize(path) > 1000


def test_generate_security_report():
    candidate = {
        "domain": "test-phish-domain.com",
        "matched_brand": "paypal.com",
        "risk_score": 92.5,
        "risk_level": "HIGH",
        "is_live": 1,
        "visual_similarity": 0.89,
        "has_login_form": 1,
        "screenshot_path": "data/screenshots/demo_paypal_high_risk.png",
        "reference_screenshot_path": "reference_assets/brands/paypal_com_reference.png",
        "recommended_action": "Request registrar domain suspension immediately.",
    }
    whois_info = {
        "registrar": "Mock Registrar Inc.",
        "creation_date": "2026-10-20T12:00:00Z",
        "emails": ["abuse@mockregistrar.com"],
    }
    dns_info = {
        "A": ["1.2.3.4"],
        "MX": ["10 mail.test-phish-domain.com"],
        "NS": ["ns1.mockregistrar.com"],
    }

    pdf_path = generate_security_report(
        candidate=candidate,
        whois_info=whois_info,
        dns_info=dns_info,
        output_filename="test_output_report.pdf",
    )

    assert pdf_path is not None
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000  # valid PDF generated

    if os.path.exists(pdf_path):
        os.remove(pdf_path)


def test_report_escapes_untrusted_evidence_and_string_email(tmp_path, monkeypatch):
    from pypdf import PdfReader
    from src.reporting import reportlab_generator as generator
    monkeypatch.setattr(generator, 'REPORT_OUTPUT_DIR', str(tmp_path))
    path = generator.generate_security_report(
        {'domain':'test.example','matched_brand':'A & B <unclosed', 'risk_level':'CRITICAL',
         'source':'feed <b>broken', 'recommended_action':'Review <b>unclosed tag'},
        whois_info={'registrar':'Registrar <b>unclosed', 'emails':'abuse@example.com'},
    )
    text = '\n'.join(page.extract_text() for page in PdfReader(path).pages)
    assert 'abuse@example.com' in text
    assert 'Registrar <b>unclosed' in text
    assert 'CRITICAL' in text
