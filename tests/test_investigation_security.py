"""Network redirect, bounded body, and certificate decoding regressions."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from src.enrichment import network_safety as safety
from src.investigation import domain_investigator as investigation


def response(url, status=200, location=None, body=b'<title>Example</title>'):
    result = Mock(url=url, status_code=status, encoding='utf-8')
    result.headers = {'Location':location} if location else {}
    result.iter_content.return_value = iter([body])
    return result


def test_private_redirect_is_blocked_before_second_request(monkeypatch):
    first = response('https://public.example', 302, 'http://127.0.0.1/admin')
    get = Mock(return_value=first)
    def validate(url, **kwargs):
        if '127.0.0.1' in url:
            raise safety.UnsafeTargetError('Private IP')
        return True
    monkeypatch.setattr(safety, 'validate_public_http_url', validate)
    monkeypatch.setattr(safety.requests, 'get', get)
    with pytest.raises(safety.UnsafeTargetError):
        safety.public_http_get('https://public.example')
    get.assert_called_once()
    assert get.call_args.kwargs['allow_redirects'] is False
    first.close.assert_called_once()


def test_relative_redirect_and_body_limit_release_connections(monkeypatch):
    first = response('https://public.example/start', 302, '/finish')
    second = response('https://public.example/finish', body=b'123456789')
    get = Mock(side_effect=[first, second])
    monkeypatch.setattr(safety, 'validate_public_http_url', lambda *args, **kwargs: True)
    monkeypatch.setattr(safety.requests, 'get', get)
    result = safety.public_http_get('https://public.example/start')
    assert get.call_args_list[1].args[0] == 'https://public.example/finish'
    assert result.history == [first]
    assert safety.read_bounded_text(result, 4) == '1234'
    first.close.assert_called_once()
    second.close.assert_called_once()


def test_investigator_never_connects_to_localhost_by_default(monkeypatch):
    connection = Mock()
    monkeypatch.setattr(investigation.socket, 'create_connection', connection)
    inv = investigation.DomainInvestigator()
    assert 'SSRF Blocked' in inv.investigate_http('127.0.0.1')['error']
    assert inv.investigate_tls_certificate('127.0.0.1')['has_tls'] is False
    connection.assert_not_called()


def test_tls_metadata_is_decoded_from_der_even_without_verification(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'public.example')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(123)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('public.example')]), critical=False)
            .sign(key, hashes.SHA256()))
    context = MagicMock()
    tls_socket = context.wrap_socket.return_value.__enter__.return_value
    tls_socket.getpeercert.return_value = cert.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(investigation, 'validate_public_http_url', lambda *args, **kwargs: True)
    monkeypatch.setattr(investigation.ssl, 'create_default_context', lambda: context)
    monkeypatch.setattr(investigation.socket, 'create_connection', MagicMock())
    result = investigation.DomainInvestigator().investigate_tls_certificate('public.example')
    assert result['has_tls'] and result['subject'] == 'public.example'
    assert result['san_list'] == ['public.example']
    assert result['serial_number'] == '123' and result['valid_to']
