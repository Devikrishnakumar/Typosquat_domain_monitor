"""
Unit tests for DNS liveness check, using mocked socket resolution
so tests run reliably without depending on real network access.
"""

from unittest.mock import patch
from src.enrichment.dns_check import is_domain_live


def test_live_domain_returns_true():
    with patch("socket.gethostbyname", return_value="1.2.3.4"):
        assert is_domain_live("example.com") is True


def test_dead_domain_returns_false():
    import socket
    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        assert is_domain_live("this-should-not-exist-xyz123.com") is False


def test_timeout_returns_false():
    import socket
    with patch("socket.gethostbyname", side_effect=socket.timeout):
        assert is_domain_live("slow-domain.com") is False
