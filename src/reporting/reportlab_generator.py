"""
reportlab_generator.py
Generates professional executive-grade cybersecurity takedown and evidence PDF reports
using ReportLab (SimpleDocTemplate, Table, Paragraph, Image).
"""

import os
import re
import hashlib
from html import escape
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether, HRFlowable
)

REPORT_OUTPUT_DIR = "reports"


def generate_security_report(
    candidate: Dict[str, Any],
    whois_info: Optional[Dict[str, Any]] = None,
    dns_info: Optional[Dict[str, Any]] = None,
    output_filename: Optional[str] = None,
) -> Optional[str]:
    """
    Generates a comprehensive PDF evidence report using ReportLab.
    Includes:
    - Executive Threat Summary
    - Risk Gauge & Severity Badge
    - Impersonated Brand vs Phishing Target metadata
    - Visual Screenshot Comparison (Candidate vs Official Reference)
    - WHOIS & Domain Registration data
    - DNS Infrastructure Records
    - Actionable Remediation & Takedown recommendations
    """
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    domain = candidate.get("domain", "unknown-domain.com")
    brand = candidate.get("matched_brand", "Unknown Brand")
    score = float(candidate.get("risk_score") or 0.0)
    level = (candidate.get("risk_level") or "LOW").upper()

    whois = whois_info or {}
    dns_data = dns_info or {}

    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", domain)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    if not output_filename:
        output_filename = f"incident_report_{safe_name}_{timestamp}.pdf"

    pdf_path = os.path.join(REPORT_OUTPUT_DIR, output_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    bold_label = ParagraphStyle(
        "BoldLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph(" <b>PHISHING & BRAND IMPERSONATION INCIDENT REPORT</b>", title_style),
            Paragraph(f"<b>REPORT ID:</b> #{hashlib.md5(domain.encode()).hexdigest()[:8].upper()}<br/><b>DATE:</b> {datetime.now(timezone.utc).strftime('%b %d, %Y %H:%M UTC')}", subtitle_style),
        ]
    ]
    header_table = Table(header_data, colWidths=[4.2 * inch, 3.0 * inch])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

    # 2. Risk Level Banner
    bg_color = "#dc2626" if level in {"HIGH", "CRITICAL"} else ("#ea580c" if level == "MEDIUM" else "#16a34a")
    risk_summary_text = (
        f"<font color='white'><b>RISK SEVERITY: {escape(level)}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>CONFIDENCE SCORE: {score:.1f} / 100</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"TARGET: {escape(brand.upper())}</font>"
    )
    risk_bar = Table(
        [[Paragraph(risk_summary_text, ParagraphStyle("RiskBar", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, alignment=1))]],
        colWidths=[7.2 * inch],
    )
    risk_bar.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(risk_bar)
    story.append(Spacer(1, 14))

    # 3. Domain & Target Overview Table
    story.append(Paragraph("Target & Evidence Summary", heading_style))
    overview_rows = [
        [Paragraph("Suspect Domain:", bold_label), Paragraph(f"<b>{escape(domain)}</b>", body_style)],
        [Paragraph("Impersonated Brand:", bold_label), Paragraph(f"{escape(brand)} (Official Domain: {escape(brand)})", body_style)],
        [Paragraph("HTTP Liveness:", bold_label), Paragraph("Reachable at last check" if candidate.get("is_live") else "Offline / inactive", body_style)],
        [Paragraph("Credential Harvesting:", bold_label), Paragraph(" <b>YES - Password Form Detected</b>" if candidate.get("has_login_form") else "None Detected", body_style)],
        [Paragraph("Visual Similarity:", bold_label), Paragraph(f"<b>{int((candidate.get('visual_similarity') or 0.0)*100)}%</b> Perceptual Hash Match (pHash)", body_style)],
        [Paragraph("Detection Source:", bold_label), Paragraph(escape(str(candidate.get("source") or "On-Demand dnstwist & crt.sh")), body_style)],
    ]
    overview_table = Table(overview_rows, colWidths=[2.2 * inch, 5.0 * inch])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 14))

    # 4. Side-by-Side Visual Comparison
    cand_img_path = candidate.get("screenshot_path")
    ref_img_path = candidate.get("reference_screenshot_path") or f"reference_assets/brands/{brand.replace('.', '_')}_reference.png"

    # Missing evidence stays missing; never substitute a different brand's image.

    cand_exists = cand_img_path and os.path.exists(cand_img_path)
    ref_exists = ref_img_path and os.path.exists(ref_img_path)

    if cand_exists or ref_exists:
        story.append(Paragraph("Visual Evidence & Perceptual Comparison", heading_style))
        img_w, img_h = 3.3 * inch, 2.1 * inch

        img_cells = []
        if ref_exists:
            img_cells.append([Paragraph("<b>Official Brand Reference</b>", bold_label), Image(ref_img_path, width=img_w, height=img_h)])
        else:
            img_cells.append([Paragraph("<b>Official Brand Reference</b>", bold_label), Paragraph("Reference screenshot not available", body_style)])

        if cand_exists:
            img_cells.append([Paragraph(f"<b>Flagged Domain ({escape(domain)})</b>", bold_label), Image(cand_img_path, width=img_w, height=img_h)])
        else:
            img_cells.append([Paragraph(f"<b>Flagged Domain ({escape(domain)})</b>", bold_label), Paragraph("Screenshot capture unavailable", body_style)])

        visual_table = Table(
            [
                [img_cells[0][0], img_cells[1][0]],
                [img_cells[0][1], img_cells[1][1]],
            ],
            colWidths=[3.6 * inch, 3.6 * inch],
        )
        visual_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(visual_table)
        story.append(Spacer(1, 14))

    # 5. WHOIS & RDAP Domain Registration Data
    story.append(Paragraph("Domain Registration & Infrastructure (WHOIS / RDAP)", heading_style))
    registrar = whois.get("registrar") or candidate.get("registered_domain") or "Unknown / Privacy Protected"
    created_at = whois.get("creation_date") or candidate.get("registered_at") or "Unknown"
    emails = whois.get("emails") or []
    if isinstance(emails, str):
        emails = [emails]
    emails_str = ", ".join(emails) if emails else "Not published / Privacy protected"

    dns_ips = dns_data.get("A") or dns_data.get("records", {}).get("A", [])
    if not dns_ips and candidate.get("ip"):
        dns_ips = [candidate.get("ip")]
    ip_str = ", ".join(dns_ips) if dns_ips else "No active A record resolved"

    mx_records = dns_data.get("MX") or dns_data.get("records", {}).get("MX", [])
    mx_str = ", ".join(mx_records) if mx_records else "None (No mail server configured)"

    ns_records = dns_data.get("NS") or dns_data.get("records", {}).get("NS", [])
    ns_str = ", ".join(ns_records) if ns_records else "None"

    infra_rows = [
        [Paragraph("Registrar:", bold_label), Paragraph(escape(str(registrar)), body_style)],
        [Paragraph("Registration Date:", bold_label), Paragraph(escape(str(created_at)), body_style)],
        [Paragraph("Abuse Contact:", bold_label), Paragraph(f"<b>{escape(emails_str)}</b>", body_style)],
        [Paragraph("Resolved IP(s):", bold_label), Paragraph(escape(str(ip_str)), body_style)],
        [Paragraph("Mail Servers (MX):", bold_label), Paragraph(escape(str(mx_str)), body_style)],
        [Paragraph("Nameservers (NS):", bold_label), Paragraph(escape(str(ns_str)), body_style)],
    ]
    infra_table = Table(infra_rows, colWidths=[2.2 * inch, 5.0 * inch])
    infra_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(infra_table)
    story.append(Spacer(1, 14))

    # 6. Actionable Remediation & Takedown
    story.append(Paragraph("Actionable Remediation & Takedown Guidance", heading_style))
    rec = escape(str(candidate["recommended_action"])) if candidate.get("recommended_action") else (
        "1. Submit DMCA / Impersonation Takedown Request to domain Registrar abuse desk.<br/>"
        "2. Report host IP to upstream hosting provider / ASN CERT team.<br/>"
        "3. Submit phishing URL to Google Safe Browsing and Microsoft SmartScreen.<br/>"
        "4. Enforce enterprise DNS sinkholing to protect corporate employees."
    )
    rec_table = Table(
        [[Paragraph(f"<b>Recommended Action Steps:</b><br/>{rec}", body_style)]],
        colWidths=[7.2 * inch],
    )
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0284c7")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(rec_table)

    # Build document
    def draw_branding(canvas, document):
        canvas.saveState()
        canvas.setTitle(f"CyberSentinel | Incident report: {domain}")
        canvas.setAuthor("CyberSentinel")
        canvas.drawImage(
            str(Path(__file__).resolve().parents[2] / "cybersentinel-mark.png"),
            36, 10, width=20, height=20, preserveAspectRatio=True, mask="auto",
        )
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(colors.HexColor("#0f172a"))
        canvas.drawString(62, 16, "CyberSentinel")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(letter[0] - 36, 16, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_branding, onLaterPages=draw_branding)
    return pdf_path


if __name__ == "__main__":
    sample = {
        "domain": "paypal-security-verification-login.com",
        "matched_brand": "paypal.com",
        "risk_score": 94.0,
        "risk_level": "HIGH",
        "is_live": 1,
        "visual_similarity": 0.94,
        "has_login_form": 1,
        "screenshot_path": "data/screenshots/demo_paypal_high_risk.png",
        "reference_screenshot_path": "reference_assets/brands/paypal_com_reference.png",
        "recommended_action": "Issue URGENT Takedown notice to Namecheap Registrar and Cloudflare CDN; report to Google Safe Browsing.",
    }
    whois_sample = {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2026-10-24T08:12:00Z",
        "emails": ["abuse@namecheap.com"],
    }
    path = generate_security_report(sample, whois_info=whois_sample)
    print("ReportLab PDF generated successfully:", path)
