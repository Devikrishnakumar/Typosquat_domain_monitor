import pytest
from src.storage import db
from src.alerts.notification_manager import NotificationManager, BaseNotificationChannel


class MockTestChannel(BaseNotificationChannel):
    def __init__(self):
        self.sent_payloads = []

    @property
    def channel_name(self):
        return "mock"

    def send(self, payload):
        self.sent_payloads.append(payload)
        return True, None


@pytest.fixture
def sqlite_db():
    orig = db.DATABASE_URL
    db.configure_database("sqlite://")
    db.init_db()
    yield
    db.Base.metadata.drop_all(db.engine)
    db.configure_database(orig)


def test_alert_threshold_and_deduplication(sqlite_db):
    cid = db.insert_candidate("paypa1-phish.com", "paypal.com")
    mgr = NotificationManager()
    mock_chan = MockTestChannel()
    mgr.telegram = mock_chan

    # 1. Low risk below threshold should be skipped
    res1 = mgr.dispatch_candidate_alert(
        candidate_id=cid,
        domain="paypa1-phish.com",
        brand_name="PayPal",
        official_domain="paypal.com",
        risk_score=40.0,
        severity="MEDIUM",
        alert_threshold=70,
    )
    assert res1.get("status") == "skipped"
    assert len(mock_chan.sent_payloads) == 0

    # 2. High risk above threshold should send alert
    res2 = mgr.dispatch_candidate_alert(
        candidate_id=cid,
        domain="paypa1-phish.com",
        brand_name="PayPal",
        official_domain="paypal.com",
        risk_score=85.0,
        severity="HIGH",
        alert_threshold=70,
    )
    assert res2["channels"]["telegram"]["status"] == "sent"
    assert len(mock_chan.sent_payloads) == 1

    # 3. Duplicate event should be skipped by deduplication
    res3 = mgr.dispatch_candidate_alert(
        candidate_id=cid,
        domain="paypa1-phish.com",
        brand_name="PayPal",
        official_domain="paypal.com",
        risk_score=85.0,
        severity="HIGH",
        alert_threshold=70,
    )
    assert res3.get("status") == "skipped"
    assert res3.get("reason") == "already_alerted"
    assert len(mock_chan.sent_payloads) == 1  # No duplicate alert delivered
