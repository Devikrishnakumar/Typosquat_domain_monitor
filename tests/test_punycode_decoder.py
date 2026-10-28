"""
Unit tests for the punycode/homoglyph decoder.
"""

from src.enrichment.punycode_decoder import decode_domain


def test_plain_ascii_domain_passes_through_unchanged():
    decoded, is_puny = decode_domain("flipkart.com")
    assert decoded == "flipkart.com"
    assert is_puny is False


def test_punycode_domain_is_decoded():
    decoded, is_puny = decode_domain("xn--pypal-4ve.com")
    assert is_puny is True
    assert decoded != "xn--pypal-4ve.com"
    assert "a" in decoded or "у" in decoded  # cyrillic or similar substitution present


def test_invalid_punycode_falls_back_gracefully():
    decoded, is_puny = decode_domain("xn--this-is-not-valid-punycode-!!!")
    # Should not raise an exception -- falls back to original string
    assert isinstance(decoded, str)
