"""
Unit tests for the RDAP-based WHOIS lookup, using the `responses`
library to mock HTTP calls so tests never depend on the real
(sometimes flaky) rdap.org / registry servers.
"""

import responses
from src.enrichment.whois_lookup import get_whois_info


@responses.activate
def test_successful_rdap_lookup_parses_registrar_and_abuse_email():
    fake_rdap_response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar Inc."]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@testregistrar.com"]]],
            },
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
    }

    responses.add(
        responses.GET,
        "https://rdap.org/domain/example.com",
        json=fake_rdap_response,
        status=200,
    )

    result = get_whois_info("example.com")

    assert result["registrar"] == "Test Registrar Inc."
    assert "abuse@testregistrar.com" in result["emails"]
    assert result["creation_date"] == "2020-01-01T00:00:00Z"
    assert "ns1.example.com" in result["name_servers"]


@responses.activate
def test_rdap_timeout_returns_empty_result_gracefully():
    import requests
    responses.add(
        responses.GET,
        "https://rdap.org/domain/example.com",
        body=requests.exceptions.Timeout(),
    )

    result = get_whois_info("example.com")

    assert result["registrar"] is None
    assert result["emails"] == []


@responses.activate
def test_rdap_non_200_status_returns_empty_result():
    responses.add(
        responses.GET,
        "https://rdap.org/domain/example.com",
        status=404,
    )

    result = get_whois_info("example.com")

    assert result["registrar"] is None
