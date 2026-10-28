import pytest
from src.scoring.risk_engine import EnterpriseRiskEngine, get_severity_for_score


def test_enterprise_risk_engine_dead_domain():
    engine = EnterpriseRiskEngine()
    result = engine.evaluate(
        domain="paypa1-fake.com",
        official_domain="paypal.com",
        is_live=False,
    )
    assert result.score < 30
    assert result.severity == "LOW"
    assert result.confidence == "LOW"
    assert any("site is not live" in m for m in result.missing_evidence)


def test_enterprise_risk_engine_critical_phishing_site():
    engine = EnterpriseRiskEngine()
    result = engine.evaluate(
        domain="paypal-login-security.com",
        official_domain="paypal.com",
        is_live=True,
        visual_similarity=0.92,
        has_login_form=True,
        suspicious_phrase_count=3,
        has_tls=True,
        whois_info={"creation_date": "2026-10-15T00:00:00Z"},
    )
    assert result.score >= 80.0
    assert result.severity == "CRITICAL"
    assert result.confidence in {"HIGH", "CONFIRMED"}
    assert "Credential entry form" in str(result.reasons)
    assert "takedown" in result.recommended_action.lower()


def test_enterprise_risk_engine_medium_lookalike():
    engine = EnterpriseRiskEngine()
    result = engine.evaluate(
        domain="paypal-partner-blog.org",
        official_domain="paypal.com",
        is_live=True,
        visual_similarity=0.1,
        has_login_form=False,
        suspicious_phrase_count=0,
    )
    assert result.severity in {"MEDIUM", "LOW"}


def test_official_domain_zero_domain_similarity():
    engine = EnterpriseRiskEngine()
    result = engine.evaluate(
        domain="paypal.com",
        official_domain="paypal.com",
        is_live=True,
    )
    assert result.breakdown["domain_similarity"] == 0.0

@pytest.mark.parametrize('score,expected', [(29.95,'LOW'), (59.95,'MEDIUM'), (79.95,'HIGH'), (30,'MEDIUM'), (60,'HIGH'), (80,'CRITICAL')])
def test_severity_fractional_boundaries_have_no_gaps(score, expected):
    assert get_severity_for_score(score) == expected
