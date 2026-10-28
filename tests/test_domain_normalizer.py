import pytest
from src.normalization.domain_normalizer import (
    normalize_domain,
    extract_hostname,
    validate_hostname,
    is_excluded_domain,
)


def test_normalize_clean_hostname():
    res = normalize_domain("  HTTPS://WWW.Example.Com:8080/path/test?q=1#hash ")
    assert res.is_valid
    assert res.clean_hostname == "www.example.com"
    assert res.ascii_domain == "www.example.com"
    assert res.registered_domain == "example.com"
    assert res.subdomain == "www"
    assert res.tld == "com"


def test_normalize_trailing_dot_and_wildcard():
    res = normalize_domain("*.login.paypal.com.")
    assert res.is_valid
    assert res.clean_hostname == "login.paypal.com"
    assert res.registered_domain == "paypal.com"
    assert res.subdomain == "login"


def test_normalize_idn_punycode():
    # Cyrillic 'a' (U+0430) in paypal
    cyrillic_paypal = "payp\u0430l.com"
    res = normalize_domain(cyrillic_paypal)
    assert res.is_valid
    assert "xn--" in res.ascii_domain
    assert res.unicode_domain == cyrillic_paypal


def test_invalid_hostnames():
    invalid_cases = [
        "",
        "   ",
        "-badlabel.com",
        "badlabel-.com",
        "example..com",
        "a" * 64 + ".com",
        "http://",
    ]
    for case in invalid_cases:
        res = normalize_domain(case)
        assert not res.is_valid or res.error


def test_official_and_approved_domain_exclusion():
    official = ["paypal.com", "example.co.uk"]
    approved = ["partner-cdn.com"]

    # Official domain matches
    assert is_excluded_domain("paypal.com", official, approved)[0] is True
    assert is_excluded_domain("www.paypal.com", official, approved)[0] is True
    assert is_excluded_domain("auth.login.paypal.com", official, approved)[0] is True
    assert is_excluded_domain("sub.example.co.uk", official, approved)[0] is True

    # Approved domain matches
    assert is_excluded_domain("partner-cdn.com", official, approved)[0] is True
    assert is_excluded_domain("assets.partner-cdn.com", official, approved)[0] is True

    # Malicious lookalikes must NOT be excluded!
    assert is_excluded_domain("paypal-security.com", official, approved)[0] is False
    assert is_excluded_domain("paypa1.com", official, approved)[0] is False
    assert is_excluded_domain("paypal.com.evil.com", official, approved)[0] is False
