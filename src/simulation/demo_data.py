"""
demo_data.py
Pre-built realistic simulation scenarios demonstrating LOW, MEDIUM, and HIGH risk
phishing detection without requiring live network access or external simulated websites.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from src.storage import db
from src.storage.models import Candidate, Brand, DiscoveryObservation, utc_now_iso
from src.enrichment.visual_similarity import compute_similarity

DEMO_DOMAINS = [
    "paypal-security-verification-login.com",
    "paypa1-support-billing.net",
    "paypal-community-blog.org",
]


def _delete_demo_candidates(session):
    """Removes any stale demo rows and their observations, keeping the demo dataset idempotent."""
    candidates = session.query(Candidate).filter(Candidate.domain.in_(DEMO_DOMAINS)).all()
    candidate_ids = [candidate.id for candidate in candidates if candidate.id is not None]

    if candidate_ids:
        session.query(DiscoveryObservation).filter(
            DiscoveryObservation.candidate_id.in_(candidate_ids)
        ).delete(synchronize_session=False)
        session.query(Candidate).filter(Candidate.id.in_(candidate_ids)).delete(synchronize_session=False)
        session.commit()

    return len(candidates)


def _draw_paypal_reference(path: str):
    """Generates an authentic-looking reference screenshot of PayPal."""
    img = Image.new("RGB", (1280, 800), color="#f5f7fa")
    draw = ImageDraw.Draw(img)

    # Header
    draw.rectangle([0, 0, 1280, 70], fill="#003087")
    draw.text((60, 22), "PayPal", fill="#ffffff")
    draw.text((1150, 26), "Log In", fill="#ffffff")

    # Center Login Card
    card_x0, card_y0, card_x1, card_y1 = 440, 150, 840, 620
    draw.rectangle([card_x0, card_y0, card_x1, card_y1], fill="#ffffff", outline="#e2e8f0", width=2)

    # Card Header
    draw.text((490, 190), "Log in to your PayPal account", fill="#0c0c0d")

    # Input Box (Email)
    draw.rectangle([480, 260, 800, 310], fill="#ffffff", outline="#94a3b8", width=1)
    draw.text((495, 275), "Email or mobile number", fill="#64748b")

    # Next Button
    draw.rectangle([480, 340, 800, 390], fill="#0070ba")
    draw.text((615, 355), "Next", fill="#ffffff")

    # Divider & Sign Up
    draw.line([480, 440, 800, 440], fill="#cbd5e1", width=1)
    draw.rectangle([480, 470, 800, 520], fill="#f1f5f9", outline="#cbd5e1", width=1)
    draw.text((605, 485), "Sign Up", fill="#003087")

    # Footer
    draw.rectangle([0, 730, 1280, 800], fill="#e2e8f0")
    draw.text((500, 755), "© 1999–2026 PayPal, Inc. All rights reserved. Privacy | Legal", fill="#64748b")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    return path


def _draw_paypal_high_risk(path: str):
    """Generates an impersonator phishing screenshot cloning PayPal login with credential trap."""
    img = Image.new("RGB", (1280, 800), color="#f5f7fa")
    draw = ImageDraw.Draw(img)

    # Cloned Header (Identical to Reference)
    draw.rectangle([0, 0, 1280, 70], fill="#003087")
    draw.text((60, 22), "PayPal", fill="#ffffff")
    draw.text((1150, 26), "Log In", fill="#ffffff")

    # Center Login Card (Identical geometry to reference)
    card_x0, card_y0, card_x1, card_y1 = 440, 150, 840, 620
    draw.rectangle([card_x0, card_y0, card_x1, card_y1], fill="#ffffff", outline="#e2e8f0", width=2)

    # Urgent banner inside card
    draw.rectangle([460, 170, 820, 210], fill="#fee2e2", outline="#ef4444", width=1)
    draw.text((475, 182), "⚠️ Account Alert: Confirm credentials.", fill="#991b1b")

    # Email field
    draw.rectangle([480, 230, 800, 275], fill="#ffffff", outline="#94a3b8", width=1)
    draw.text((495, 245), "user@example.com", fill="#1e293b")

    # Password field (Credential Harvest)
    draw.rectangle([480, 290, 800, 335], fill="#ffffff", outline="#94a3b8", width=1)
    draw.text((495, 305), "••••••••••••", fill="#1e293b")

    # Next / Log In Button (Same blue)
    draw.rectangle([480, 350, 800, 395], fill="#0070ba")
    draw.text((600, 365), "Verify & Log In", fill="#ffffff")

    # Divider & Sign Up
    draw.line([480, 440, 800, 440], fill="#cbd5e1", width=1)
    draw.rectangle([480, 470, 800, 520], fill="#f1f5f9", outline="#cbd5e1", width=1)
    draw.text((605, 485), "Sign Up", fill="#003087")

    # Footer
    draw.rectangle([0, 730, 1280, 800], fill="#e2e8f0")
    draw.text((500, 755), "© 1999–2026 PayPal, Inc. All rights reserved. Privacy | Legal", fill="#64748b")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    return path


def _draw_paypal_medium_risk(path: str):
    """Generates a domain parking / broker page (lookalike domain registered but parked)."""
    img = Image.new("RGB", (1280, 800), color="#ffffff")
    draw = ImageDraw.Draw(img)

    # Top Bar
    draw.rectangle([0, 0, 1280, 80], fill="#1e293b")
    draw.text((50, 28), "🌐 DomainPark Network", fill="#ffffff")
    draw.text((1050, 28), "Inquire About Domain", fill="#38bdf8")

    # Hero
    draw.rectangle([0, 80, 1280, 350], fill="#f8fafc")
    draw.text((360, 150), "Welcome to paypa1-support-billing.net", fill="#0f172a")
    draw.text((430, 200), "This domain is registered and parked by its owner.", fill="#64748b")

    # Search / Buy CTA
    draw.rectangle([400, 250, 880, 310], fill="#ffffff", outline="#cbd5e1", width=2)
    draw.text((430, 270), "🔍 Search related topics or inquire to purchase...", fill="#94a3b8")

    # Ad categories
    for i, title in enumerate(["Billing Software", "Support Helpdesk Tools", "Payment Gateways", "Online Invoicing"]):
        x = 100 + i * 270
        draw.rectangle([x, 400, x + 250, 520], fill="#f1f5f9", outline="#e2e8f0")
        draw.text((x + 20, 440), title, fill="#0284c7")
        draw.text((x + 20, 470), "Sponsored Ads & Links", fill="#94a3b8")

    # Footer
    draw.rectangle([0, 730, 1280, 800], fill="#0f172a")
    draw.text((480, 755), "Privacy Policy | Terms of Service | Domain Marketplace", fill="#94a3b8")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    return path


def _draw_paypal_low_risk(path: str):
    """Generates a benign tech blog screenshot."""
    img = Image.new("RGB", (1280, 800), color="#ffffff")
    draw = ImageDraw.Draw(img)

    # Blog Header
    draw.rectangle([0, 0, 1280, 100], fill="#047857")
    draw.text((80, 35), "OpenTech Community Blog", fill="#ffffff")
    draw.text((900, 40), "Home   Articles   About   Contact", fill="#d1fae5")

    # Content
    draw.text((80, 150), "Articles & Community Guides", fill="#111827")

    # Post 1
    draw.rectangle([80, 210, 800, 360], fill="#f9fafb", outline="#e5e7eb")
    draw.text((110, 235), "Understanding Webhook Integrations in Modern FinTech", fill="#065f46")
    draw.text((110, 275), "A comprehensive developer guide on handling IPNs and payment callbacks securely...", fill="#4b5563")
    draw.text((110, 315), "Published Oct 12, 2024 by Community Team", fill="#9ca3af")

    # Post 2
    draw.rectangle([80, 390, 800, 540], fill="#f9fafb", outline="#e5e7eb")
    draw.text((110, 415), "How Python and DNS Permutations Detect Typosquatting", fill="#065f46")
    draw.text((110, 455), "Exploring dnstwist, certificate transparency monitoring, and RDAP queries in Python...", fill="#4b5563")
    draw.text((110, 495), "Published Aug 04, 2024 by Security Researcher", fill="#9ca3af")

    # Sidebar
    draw.rectangle([860, 210, 1200, 540], fill="#f3f4f6")
    draw.text((890, 235), "About This Blog", fill="#1f2937")
    draw.text((890, 275), "Non-commercial developer community.", fill="#6b7280")
    draw.text((890, 305), "Hosted at paypal-community-blog.org", fill="#6b7280")

    # Footer
    draw.rectangle([0, 720, 1280, 800], fill="#111827")
    draw.text((500, 755), "© 2019-2026 OpenTech Community. All rights reserved.", fill="#9ca3af")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    return path


def ensure_demo_assets():
    """Generates all demonstration assets and screenshots if not present."""
    ref_path = "reference_assets/brands/paypal_com_reference.png"
    high_path = "data/screenshots/demo_paypal_high_risk.png"
    med_path = "data/screenshots/demo_paypal_medium_risk.png"
    low_path = "data/screenshots/demo_paypal_low_risk.png"

    os.makedirs("reference_assets/brands", exist_ok=True)
    os.makedirs("data/screenshots", exist_ok=True)

    if not os.path.exists(ref_path):
        _draw_paypal_reference(ref_path)
    if not os.path.exists(high_path):
        _draw_paypal_high_risk(high_path)
    if not os.path.exists(med_path):
        _draw_paypal_medium_risk(med_path)
    if not os.path.exists(low_path):
        _draw_paypal_low_risk(low_path)

    # Compute actual similarities against reference
    high_sim = compute_similarity(high_path, ref_path) or 0.94
    med_sim = compute_similarity(med_path, ref_path) or 0.45
    low_sim = compute_similarity(low_path, ref_path) or 0.08

    return {
        "reference_path": ref_path,
        "high": {"path": high_path, "similarity": high_sim},
        "medium": {"path": med_path, "similarity": med_sim},
        "low": {"path": low_path, "similarity": low_sim},
    }


def seed_simulation_data():
    """Seeds the SQLite database with 3 realistic scenarios: LOW, MEDIUM, and HIGH risk."""
    db.init_db()
    assets = ensure_demo_assets()
    session = db.SessionLocal()

    try:
        _delete_demo_candidates(session)

        # 1. Ensure PayPal Brand exists
        brand = session.query(Brand).filter_by(official_domain="paypal.com").first()
        if not brand:
            brand = Brand(
                organization_id=1,
                name="PayPal",
                official_domain="paypal.com",
                official_website_url="https://www.paypal.com",
                keywords=json.dumps(["paypal", "pay-pal", "paypa1", "pypl"]),
                alert_threshold=70,
                telegram_alerts_enabled=True,
            )
            session.add(brand)
            session.commit()
            session.refresh(brand)

        demo_specs = [
            {
                "domain": "paypal-security-verification-login.com",
                "matched_brand": "paypal.com",
                "source": "CRTSH_LOGS",
                "permutation_type": "crtsh_discovered",
                "is_live": 1,
                "visual_similarity": assets["high"]["similarity"],
                "has_login_form": 1,
                "suspicious_phrase_count": 4,
                "risk_score": 94.0,
                "risk_level": "HIGH",
                "screenshot_path": assets["high"]["path"],
                "status": "new",
                "evidence_status": "complete",
                "confidence_level": "HIGH",
                "recommended_action": "Issue URGENT Takedown notice to Namecheap Registrar and Cloudflare CDN; report to Google Safe Browsing and Netcraft.",
                "analyst_notes": "Credential harvester cloning PayPal login screen with urgent suspension warning. MX records configured for phishing campaigns.",
                "risk_breakdown": json.dumps({
                    "is_live": 25,
                    "visual_similarity": round(assets["high"]["similarity"] * 35, 1),
                    "has_login_form": 25,
                    "suspicious_phrases": 15,
                    "new_registration": 15,
                    "mail_server_active": 10
                }),
                "whois": {
                    "registrar": "Namecheap, Inc.",
                    "creation_date": "2026-10-24T08:12:00Z",
                    "emails": ["abuse@namecheap.com"],
                    "name_servers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
                },
                "dns": {
                    "A": ["194.87.112.44"],
                    "MX": ["10 mail.paypal-security-verification-login.com"],
                    "NS": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
                }
            },
            {
                "domain": "paypa1-support-billing.net",
                "matched_brand": "paypal.com",
                "source": "DNSTWIST",
                "permutation_type": "homoglyph (l -> 1)",
                "is_live": 1,
                "visual_similarity": assets["medium"]["similarity"],
                "has_login_form": 0,
                "suspicious_phrase_count": 1,
                "risk_score": 56.0,
                "risk_level": "MEDIUM",
                "screenshot_path": assets["medium"]["path"],
                "status": "new",
                "evidence_status": "complete",
                "confidence_level": "MEDIUM",
                "recommended_action": "Monitor domain for web content changes or MX record deployment. Prepare defensive registration or Cease & Desist.",
                "analyst_notes": "Homoglyph lookalike domain parked with generic ad links. Live DNS resolving to Hostinger parking pool.",
                "risk_breakdown": json.dumps({
                    "is_live": 25,
                    "visual_similarity": round(assets["medium"]["similarity"] * 35, 1),
                    "has_login_form": 0,
                    "suspicious_phrases": 5,
                    "recent_registration": 10,
                }),
                "whois": {
                    "registrar": "Hostinger Operations, UAB",
                    "creation_date": "2026-10-14T14:30:00Z",
                    "emails": ["abuse@hostinger.com"],
                    "name_servers": ["ns1.dns-parking.com", "ns2.dns-parking.com"],
                },
                "dns": {
                    "A": ["185.199.108.153"],
                    "MX": [],
                    "NS": ["ns1.dns-parking.com", "ns2.dns-parking.com"],
                }
            },
            {
                "domain": "paypal-community-blog.org",
                "matched_brand": "paypal.com",
                "source": "DNSTWIST",
                "permutation_type": "hyphenation / addition",
                "is_live": 0,
                "visual_similarity": assets["low"]["similarity"],
                "has_login_form": 0,
                "suspicious_phrase_count": 0,
                "risk_score": 18.0,
                "risk_level": "LOW",
                "screenshot_path": assets["low"]["path"],
                "status": "new",
                "evidence_status": "complete",
                "confidence_level": "LOW",
                "recommended_action": "No immediate threat detected. Established informational website with no brand asset infringement.",
                "analyst_notes": "Established non-commercial technical blog. Domain created in 2019, low visual similarity to brand, no credential collection.",
                "risk_breakdown": json.dumps({
                    "is_live": 0,
                    "visual_similarity": round(assets["low"]["similarity"] * 35, 1),
                    "has_login_form": 0,
                    "suspicious_phrases": 0,
                }),
                "whois": {
                    "registrar": "Tucows Domains Inc.",
                    "creation_date": "2019-03-12T10:00:00Z",
                    "emails": ["abuse@tucows.com"],
                    "name_servers": ["ns1.hover.com", "ns2.hover.com"],
                },
                "dns": {
                    "A": ["192.0.2.1"],
                    "MX": [],
                    "NS": ["ns1.hover.com", "ns2.hover.com"],
                }
            }
        ]

        inserted = []
        now = utc_now_iso()

        for spec in demo_specs:
            cand = session.query(Candidate).filter_by(domain=spec["domain"]).first()
            if not cand:
                cand = Candidate(
                    domain=spec["domain"],
                    matched_brand=spec["matched_brand"],
                    detected_at=now,
                    first_seen_at=now,
                    last_seen_at=now,
                    discovered_at=now,
                    imported_at=now,
                    event_category="simulation",
                    brand_id=brand.id,
                )
                session.add(cand)

            cand.is_live = spec["is_live"]
            cand.visual_similarity = spec["visual_similarity"]
            cand.has_login_form = spec["has_login_form"]
            cand.suspicious_phrase_count = spec["suspicious_phrase_count"]
            cand.risk_score = spec["risk_score"]
            cand.risk_level = spec["risk_level"]
            cand.screenshot_path = spec["screenshot_path"]
            cand.status = spec["status"]
            cand.evidence_status = spec["evidence_status"]
            cand.confidence_level = spec["confidence_level"]
            cand.recommended_action = spec["recommended_action"]
            cand.analyst_notes = spec["analyst_notes"]
            cand.risk_breakdown = spec["risk_breakdown"]
            cand.registered_domain = spec["whois"]["registrar"]
            cand.registered_at = spec["whois"]["creation_date"]

            session.commit()
            session.refresh(cand)

            # Record observation
            obs = session.query(DiscoveryObservation).filter_by(candidate_id=cand.id).first()
            if not obs:
                obs = DiscoveryObservation(
                    candidate_id=cand.id,
                    source=spec["source"],
                    observed_at=now,
                    imported_at=now,
                    raw_data=json.dumps({
                        "domain": spec["domain"],
                        "matched_brand": spec["matched_brand"],
                        "permutation_type": spec["permutation_type"],
                        "whois": spec["whois"],
                        "dns": spec["dns"],
                    }),
                )
                session.add(obs)
                session.commit()

            inserted.append(cand.domain)

        return inserted
    finally:
        session.close()


def clear_simulation_data():
    """Removes demo candidates from the database."""
    session = db.SessionLocal()
    try:
        return _delete_demo_candidates(session)
    finally:
        session.close()


if __name__ == "__main__":
    results = seed_simulation_data()
    print("Seeded demo scenarios:", results)
