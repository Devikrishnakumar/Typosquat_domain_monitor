"""
test_simulation_demo.py
Unit tests for simulation and demo data generation (LOW, MEDIUM, HIGH scenarios).
"""

import os
from src.simulation.demo_data import seed_simulation_data, clear_simulation_data, ensure_demo_assets
from src.storage import db
from src.storage.models import Candidate


def test_ensure_demo_assets():
    assets = ensure_demo_assets()
    assert os.path.exists(assets["reference_path"])
    assert os.path.exists(assets["high"]["path"])
    assert os.path.exists(assets["medium"]["path"])
    assert os.path.exists(assets["low"]["path"])
    assert assets["high"]["similarity"] >= 0.70
    assert assets["low"]["similarity"] <= 0.60
    assert assets["high"]["similarity"] > assets["low"]["similarity"]


def test_seed_and_clear_simulation_data():
    inserted = seed_simulation_data()
    assert len(inserted) == 3
    assert "paypal-security-verification-login.com" in inserted
    assert "paypa1-support-billing.net" in inserted
    assert "paypal-community-blog.org" in inserted

    session = db.SessionLocal()
    try:
        high_cand = session.query(Candidate).filter_by(domain="paypal-security-verification-login.com").first()
        assert high_cand is not None
        assert high_cand.risk_level == "HIGH"
        assert high_cand.risk_score >= 80

        med_cand = session.query(Candidate).filter_by(domain="paypa1-support-billing.net").first()
        assert med_cand is not None
        assert med_cand.risk_level == "MEDIUM"

        low_cand = session.query(Candidate).filter_by(domain="paypal-community-blog.org").first()
        assert low_cand is not None
        assert low_cand.risk_level == "LOW"
    finally:
        session.close()

    # Clear
    removed = clear_simulation_data()
    assert removed == 3
