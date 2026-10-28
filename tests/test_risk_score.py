"""
Unit tests for the composite risk scoring engine.
Pure logic tests -- no network, no mocking needed.
"""

import pytest
from src.scoring.risk_score import compute_risk_score, risk_level


def test_dead_domain_scores_zero():
    score, breakdown = compute_risk_score(
        is_live=False, visual_similarity=0.0, has_login_form=False, suspicious_phrase_count=0
    )
    assert score == 0.0
    assert risk_level(score) == "LOW"


def test_dangerous_site_scores_high():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=0.95, has_login_form=True, suspicious_phrase_count=2
    )
    assert score >= 70
    assert risk_level(score) == "HIGH"


def test_live_unrelated_site_stays_low():
    # A benign live site with no visual similarity or login form
    # should NOT be inflated into MEDIUM/HIGH just for being live.
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=0.375, has_login_form=False, suspicious_phrase_count=0
    )
    assert risk_level(score) == "LOW"


def test_risk_level_boundaries():
    assert risk_level(70) == "HIGH"
    assert risk_level(69.9) == "MEDIUM"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(49.9) == "LOW"


def test_breakdown_components_sum_to_total():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=0.8, has_login_form=True, suspicious_phrase_count=1
    )
    assert round(sum(breakdown.values()), 2) == score
