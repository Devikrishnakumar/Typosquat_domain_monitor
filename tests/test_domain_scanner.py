"""
test_domain_scanner.py
Unit tests for DomainScanner resolution, permutations, and risk scoring integration.
"""

from src.discovery.domain_scanner import DomainScanner, _resolve_dns


def test_resolve_dns_valid_and_invalid():
    # Test valid resolution
    res = _resolve_dns("google.com", timeout=3.0)
    assert res["is_live"] is True
    assert len(res["records"]["A"]) > 0

    # Test non-existent domain resolution
    res_nx = _resolve_dns("this-domain-does-not-exist-xyz999888.com", timeout=1.0)
    assert res_nx["is_live"] is False


def test_scanner_permutation_handling():
    scanner = DomainScanner()
    # Scan with 5 permutations and offline options
    results = scanner.scan_brand("paypal.com", max_permutations=5, include_crtsh=False, take_screenshots=False)
    assert len(results) >= 1
    for r in results:
        assert "risk_score" in r
        assert r["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
        assert "matched_brand" in r
