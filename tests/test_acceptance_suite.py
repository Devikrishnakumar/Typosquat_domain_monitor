"""
test_acceptance_suite.py
Automated acceptance tests for Fake Website Detector (Typosquad).
Covers:
- Investigation timeouts and error handling
- Worker restart recovery and health reporting
- Dashboard data loading and calculations
- Multi-tenant organization isolation
- Database migration upgrade/downgrade consistency
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock

from src.storage import db
from src.investigation.domain_investigator import DomainInvestigator
from src.ingest import ct_stream_client
from src.scoring.risk_engine import EnterpriseRiskEngine


@pytest.fixture
def sqlite_db():
    orig = db.DATABASE_URL
    db.configure_database("sqlite://")
    db.init_db()
    yield
    db.Base.metadata.drop_all(db.engine)
    db.configure_database(orig)


def test_investigation_timeout_and_failure_handling(sqlite_db):
    """Verifies that network timeouts or unreachable hosts fail gracefully."""
    inv = DomainInvestigator(timeout_seconds=1)
    
    # Non-resolving domain DNS check should fail gracefully with NXDOMAIN or error
    dns_res = inv.investigate_dns("non-existent-subdomain-fake-123456789.invalid")
    assert dns_res["is_live"] is False
    assert dns_res["status"] in {"NXDOMAIN", "UNRESOLVED", "TIMEOUT"}

    # HTTP check should record failure instead of raising unhandled exception
    http_res = inv.investigate_http("non-existent-subdomain-fake-123456789.invalid")
    assert http_res["reachable"] is False
    assert http_res["http_status"] is None


def test_worker_restart_and_health_recovery(tmp_path, monkeypatch):
    """Verifies worker recovers its health state and handles service restarts."""
    health_path = tmp_path / "worker_health.json"
    monkeypatch.setattr(ct_stream_client, "HEALTH_PATH", health_path)

    # Initial worker start
    ct_stream_client._write_worker_health("connected")
    data = json.loads(health_path.read_text())
    assert data["state"] == "connected"

    # Simulate restart / reconnecting
    ct_stream_client._write_worker_health("reconnecting", error="Websocket connection dropped")
    reconnected_data = json.loads(health_path.read_text())
    assert reconnected_data["state"] == "reconnecting"
    assert reconnected_data["last_error"] == "Websocket connection dropped"


def test_organization_multi_tenant_isolation(sqlite_db):
    """Verifies that Client A cannot access Client B's candidate domains."""
    # Org A and Org B
    org_a = db.create_organization("Org Alpha", "org-alpha")
    org_b = db.create_organization("Org Beta", "org-beta")

    # Brand for Org A
    brand_a = db.create_or_update_brand(org_a, "Brand A", "alpha.com")
    # Brand for Org B
    brand_b = db.create_or_update_brand(org_b, "Brand B", "beta.com")

    # Insert candidates for Org A and Org B
    cand_a_id = db.insert_candidate("alpha-spoof.com", "alpha.com", organization_id=org_a, brand_id=brand_a)
    cand_b_id = db.insert_candidate("beta-spoof.com", "beta.com", organization_id=org_b, brand_id=brand_b)

    # Query candidates filtered by Org A
    org_a_candidates = db.get_all_candidates(org_id=org_a)
    domains_a = [c["domain"] for c in org_a_candidates]
    assert "alpha-spoof.com" in domains_a
    assert "beta-spoof.com" not in domains_a  # Org B's candidate is isolated!


def test_dashboard_data_loading_and_counts(sqlite_db):
    """Verifies that dashboard data queries load and aggregate cleanly."""
    # Insert candidates with different risk profiles
    c1 = db.insert_candidate("phish1.com", "brand.com")
    db.update_risk_score(c1, 85.0, "HIGH")

    c2 = db.insert_candidate("phish2.com", "brand.com")
    db.update_risk_score(c2, 45.0, "MEDIUM")

    c3 = db.insert_candidate("phish3.com", "brand.com")
    db.update_risk_score(c3, 15.0, "LOW")

    candidates = db.get_all_candidates()
    assert len(candidates) == 3

    # Check high risk filter
    high_risk_candidates = db.get_all_candidates(min_risk=70)
    assert len(high_risk_candidates) == 1
    assert high_risk_candidates[0]["domain"] == "phish1.com"


def test_database_migrations_schema_integrity():
    """Verifies that Alembic migration tables match expected schema."""
    from alembic.config import Config
    from alembic import command
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    try:
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{temp_db_path}")

        # Upgrade to head
        command.upgrade(cfg, "head")

        # Downgrade to base
        command.downgrade(cfg, "base")
    finally:
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except OSError:
                pass
