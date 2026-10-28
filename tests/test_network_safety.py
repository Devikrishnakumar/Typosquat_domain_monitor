import socket
from unittest.mock import patch

import pytest

from src.enrichment.network_safety import (
    UnsafeTargetError,
    validate_public_http_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://10.0.0.8",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]",
        "file:///etc/passwd",
        "http://user:pass@example.com",
    ],
)
def test_non_public_and_non_http_targets_are_rejected(url):
    with pytest.raises(UnsafeTargetError):
        validate_public_http_url(url)


def test_domain_resolving_to_private_address_is_rejected():
    private_result = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        6,
        "",
        ("192.168.1.10", 443),
    )
    with patch(
        "src.enrichment.network_safety.socket.getaddrinfo",
        return_value=[private_result],
    ):
        with pytest.raises(UnsafeTargetError, match="non-public"):
            validate_public_http_url("https://brand-lookalike.example")


def test_domain_resolving_only_to_public_addresses_is_allowed():
    public_result = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        6,
        "",
        ("93.184.216.34", 443),
    )
    with patch(
        "src.enrichment.network_safety.socket.getaddrinfo",
        return_value=[public_result],
    ):
        assert validate_public_http_url("https://brand-lookalike.example")


def test_explicit_simulation_host_can_be_allowed():
    assert validate_public_http_url(
        "http://simulation-site:8765/reference.html",
        allowed_hosts={"simulation-site"},
    )
