import pytest
from src.storage import db
from src.discovery.historical_discovery import (
    HistoricalDiscoveryEngine,
    MockHistoricalProvider,
    HistoricalRecord,
)


@pytest.fixture
def sqlite_db():
    original_url = db.DATABASE_URL
    db.configure_database("sqlite://")
    db.init_db()
    yield
    db.Base.metadata.drop_all(db.engine)
    db.configure_database(original_url)


def test_historical_discovery_ingestion_and_exclusion(sqlite_db):
    sample_records = [
        {"domain": "paypal.com", "observed_at": "2024-01-01T00:00:00Z"},  # Official - should exclude
        {"domain": "login.paypal.com", "observed_at": "2024-02-01T00:00:00Z"},  # Official subdomain - exclude
        {"domain": "paypal-login-security.com", "observed_at": "2024-05-10T12:00:00Z"},  # Impersonation - keep
        {"domain": "paypa1-update.com", "observed_at": "2024-06-15T08:30:00Z"},  # Typo - keep
        {"domain": "unrelated-shoes.org", "observed_at": "2024-07-01T00:00:00Z"},  # Unrelated - skip
    ]

    mock_provider = MockHistoricalProvider(sample_records)
    engine = HistoricalDiscoveryEngine(provider=mock_provider)

    result = engine.run_brand_discovery(
        brand_name="PayPal",
        official_domain="paypal.com",
        max_results=50,
    )

    assert result["status"] == "completed"
    assert result["discovered_count"] == 2
    domains = [c["domain"] for c in result["discovered_candidates"]]
    assert "paypal-login-security.com" in domains
    assert "paypa1-update.com" in domains
    assert "paypal.com" not in domains

    # Verify separate observed_at vs imported_at
    item = result["discovered_candidates"][0]
    assert item["observed_at"].startswith("2024-")
    assert item["imported_at"] != item["observed_at"]

    # Verify DB records
    candidates = db.get_all_candidates()
    assert len(candidates) == 2
    for c in candidates:
        assert c["event_category"] == "historical"


def test_historical_discovery_deduplication(sqlite_db):
    sample_records = [
        {"domain": "paypal-phish.net", "observed_at": "2024-03-01T00:00:00Z"},
    ]
    mock_provider = MockHistoricalProvider(sample_records)
    engine = HistoricalDiscoveryEngine(provider=mock_provider)

    res1 = engine.run_brand_discovery("PayPal", "paypal.com")
    assert res1["discovered_count"] == 1

    # Second run should not create duplicate candidate
    res2 = engine.run_brand_discovery("PayPal", "paypal.com")
    assert res2["discovered_count"] == 1

    candidates = db.get_all_candidates()
    assert len(candidates) == 1
    assert candidates[0]["seen_count"] == 2
