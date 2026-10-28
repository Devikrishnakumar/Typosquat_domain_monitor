import pytest
from fastapi.testclient import TestClient

from src.storage import db
from src.api.main import app

client = TestClient(app)


@pytest.fixture
def sqlite_db():
    orig = db.DATABASE_URL
    db.configure_database("sqlite://")
    db.init_db()
    yield
    db.Base.metadata.drop_all(db.engine)
    db.configure_database(orig)


def test_root_and_health_endpoints(sqlite_db):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["product"] == "CyberSentinel"

    health = client.get("/api/v1/health/system")
    assert health.status_code == 200
    assert health.json()["database_connected"] is True


def test_auth_registration_and_login(sqlite_db):
    # Register
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "SecurePassword123!",
            "full_name": "Test Analyst",
            "organization_name": "Acme Corp",
            "role": "analyst",
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert "access_token" in reg_data
    token = reg_data["access_token"]

    # Login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "SecurePassword123!"},
    )
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()

    # Get Current User (/auth/me)
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "analyst@example.com"


def test_brand_management_crud(sqlite_db):
    # Register admin
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@example.com",
            "password": "AdminPassword123!",
            "full_name": "Admin User",
            "organization_name": "Acme Security",
            "role": "admin",
        },
    )
    token = reg_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create Brand
    create_resp = client.post(
        "/api/v1/brands",
        headers=headers,
        json={
            "name": "PayPal Brand",
            "official_domain": "paypal.com",
            "keywords": ["paypal", "payment"],
            "monitoring_enabled": True,
            "check_interval_minutes": 5,
            "alert_threshold": 70,
        },
    )
    assert create_resp.status_code == 200
    brand_id = create_resp.json()["id"]

    # Add Approved Domain
    appr_resp = client.post(
        f"/api/v1/brands/{brand_id}/approved-domains",
        headers=headers,
        json={"domain": "paypal-cdn.com", "notes": "Official CDN domain"},
    )
    assert appr_resp.status_code == 200

    # List Brands
    list_resp = client.get("/api/v1/brands", headers=headers)
    assert list_resp.status_code == 200
    brands = list_resp.json()
    assert len(brands) == 1
    assert brands[0]["official_domain"] == "paypal.com"


def test_candidate_listing_and_review(sqlite_db):
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst2@example.com",
            "password": "AnalystPass123!",
            "full_name": "Analyst Two",
            "organization_name": "Org 2",
            "role": "analyst",
        },
    )
    headers = {"Authorization": f"Bearer {reg_resp.json()['access_token']}"}
    cid = db.insert_candidate("paypa1-spoof.com", "paypal.com",
                              organization_id=reg_resp.json()["user"]["organization_id"])

    # List Candidates
    cand_resp = client.get("/api/v1/candidates", headers=headers)
    assert cand_resp.status_code == 200
    cands = cand_resp.json()
    assert len(cands) == 1
    assert cands[0]["domain"] == "paypa1-spoof.com"

    # Review Candidate
    rev_resp = client.post(
        f"/api/v1/candidates/{cid}/review",
        headers=headers,
        json={"status": "under_investigation", "analyst_notes": "Identified suspicious landing page."},
    )
    assert rev_resp.status_code == 200

    # Verify Detail
    det_resp = client.get(f"/api/v1/candidates/{cid}", headers=headers)
    assert det_resp.status_code == 200
    assert det_resp.json()["status"] == "under_investigation"
