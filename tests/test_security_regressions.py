"""Regression checks for authentication, tenant boundaries, and storage scope."""
from datetime import timedelta
from unittest.mock import Mock

import bcrypt
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api import routes
from src.api.auth import create_access_token, get_password_hash, verify_password
from src.storage import db
from src.storage.models import Organization


@pytest.fixture
def isolated_db():
    original = db.DATABASE_URL
    db.configure_database('sqlite://')
    db.init_db()
    try:
        yield
    finally:
        db.configure_database(original)


def signup(client, email, name='Shared organization name', role='analyst'):
    response = client.post('/api/v1/auth/register', json={
        'email': email, 'password': 'CorrectPassword123!',
        'organization_name': name, 'role': role,
    })
    assert response.status_code == 200, response.text
    result = response.json()
    return result['user']['organization_id'], {'Authorization': 'Bearer '+result['access_token']}


def test_protected_endpoints_reject_missing_and_expired_tokens(isolated_db):
    with TestClient(app) as client:
        for path in ('/auth/me', '/brands', '/candidates', '/alerts', '/monitoring/jobs', '/audit'):
            assert client.get('/api/v1'+path).status_code == 401
        token = create_access_token({'sub': 'none@example.com'}, timedelta(seconds=-1))
        assert client.get('/api/v1/auth/me', headers={'Authorization': 'Bearer '+token}).status_code == 401
    with db.SessionLocal() as session:
        assert session.query(db.User).count() == 0


def test_registration_isolated_and_me_never_exposes_hash(isolated_db):
    with TestClient(app) as client:
        first_org, first_headers = signup(client, 'first@example.com')
        second_org, _ = signup(client, 'second@example.com')
        assert first_org != second_org
        me = client.get('/api/v1/auth/me', headers=first_headers)
        assert me.status_code == 200
        assert 'hashed_password' not in me.json()
        assert client.post('/api/v1/auth/register', json={
            'email':'third@example.com', 'password':'GoodPassword123!',
            'organization_name':'Test', 'role':'superadmin',
        }).status_code == 422
        duplicate = client.post('/api/v1/auth/register', json={
            'email':'first@example.com', 'password':'AnotherPassword123!', 'organization_name':'New tenant',
        })
        assert duplicate.status_code == 400
        with db.SessionLocal() as session:
            assert session.query(Organization).count() == 2


def test_foreign_resources_cannot_be_read_or_modified(isolated_db, monkeypatch):
    with TestClient(app) as client:
        org_a, headers_a = signup(client, 'owner@example.com')
        org_b, headers_b = signup(client, 'other@example.com')
        brand_a = db.create_or_update_brand(org_a, 'A', 'brand.example')
        brand_b = db.create_or_update_brand(org_b, 'B', 'other.example')
        candidate = db.insert_candidate('spoof.example', 'brand.example', organization_id=org_a, brand_id=brand_a)
        unowned = db.insert_candidate('legacy.example', 'brand.example')
        db.record_alert(candidate, 'mock', 'local', 'sent', {})
        job_a = db.create_monitoring_job('test', brand_a)
        db.create_monitoring_job('test', brand_b)
        investigation = Mock()
        monkeypatch.setattr(routes.investigator, 'run_full_investigation', investigation)
        discovery = Mock()
        monkeypatch.setattr(routes.HistoricalDiscoveryEngine, 'run_brand_discovery', discovery)
        assert client.get(f'/api/v1/candidates/{candidate}', headers=headers_b).status_code == 404
        assert client.get(f'/api/v1/candidates/{unowned}', headers=headers_a).status_code == 404
        assert client.post(f'/api/v1/candidates/{candidate}/review', headers=headers_b, json={'status':'resolved'}).status_code == 404
        assert client.post('/api/v1/investigation/run', headers=headers_b, json={'candidate_id':candidate}).status_code == 404
        assert client.post('/api/v1/investigation/run', headers=headers_a, json={'candidate_id':candidate,'domain':'different.example'}).status_code == 400
        for method in ('get', 'post'):
            kwargs = {'json':{'domain':'approved.example'}} if method == 'post' else {}
            assert getattr(client, method)(f'/api/v1/brands/{brand_a}/approved-domains', headers=headers_b, **kwargs).status_code == 404
        assert client.post('/api/v1/discovery/historical', headers=headers_b,
                           json={'brand_id':brand_a,'official_domain':'bypass.example'}).status_code == 404
        assert client.get('/api/v1/alerts', headers=headers_b).json() == []
        assert len(client.get('/api/v1/alerts', headers=headers_a).json()) == 1
        assert client.get('/api/v1/monitoring/jobs', headers=headers_a).json()[0]['id'] == job_a
        assert len(client.get('/api/v1/monitoring/jobs', headers=headers_a).json()) == 1
        assert client.get('/api/v1/candidates',headers=headers_b).json() == []
        assert db.get_candidate(candidate)['status'] == 'new'
        investigation.assert_not_called()
        discovery.assert_not_called()


def test_candidate_deduplication_is_scoped_to_tenant(isolated_db):
    org_a = db.create_organization('A', 'a')
    org_b = db.create_organization('B', 'b')
    first = db.insert_candidate('same.example', 'brand.example', organization_id=org_a)
    second = db.insert_candidate('same.example', 'brand.example', organization_id=org_b)
    local = db.insert_candidate('same.example', 'brand.example')
    repeat = db.insert_candidate('same.example', 'brand.example', organization_id=org_a)
    assert first == repeat
    assert len({first, second, local}) == 3
    assert len(db.get_all_candidates(org_id=org_b)) == 1
    assert db.get_candidate(first)['seen_count'] == 2


def test_password_hash_supports_long_passwords_and_existing_bcrypt():
    password = 'very-long-password-'*12
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password(password+'x', hashed)
    old_hash = bcrypt.hashpw(b'legacy-password', bcrypt.gensalt()).decode()
    assert verify_password('legacy-password', old_hash)
    assert not verify_password('wrong', old_hash)

def test_monitor_ignores_disabled_targets_and_preserves_reviews(isolated_db, monkeypatch):
    import json
    from src.ingest import background_service as service
    org = db.create_organization('Monitor', 'monitor')
    disabled = db.create_or_update_brand(org, 'Disabled', 'disabled.example', monitoring_enabled=False)
    brand = db.create_or_update_brand(org, 'Brand', 'brand.example')
    monitor = service.BackgroundDomainMonitor.__new__(service.BackgroundDomainMonitor)
    monitor.recent_seen = set()
    monitor.matches_found = 0
    monitor.log_event = Mock()
    targets = monitor.get_active_targets()
    assert [target['id'] for target in targets] == [brand]
    assert targets[0]['organization_id'] == org
    monkeypatch.setattr(service.socket, 'gethostbyname', lambda _: '93.184.216.34')
    alert = Mock()
    monkeypatch.setattr(service, 'send_alert', alert)
    match = {'brand_id':brand, 'organization_id':org, 'official_domain':'brand.example', 'matched_keyword':'brand'}
    existing = db.insert_candidate('brand-old.example', 'brand.example', organization_id=org, brand_id=brand)
    db.update_candidate_review(existing, 'resolved', 'Reviewed by analyst')
    db.update_evidence_details(existing, 'complete')
    db.update_risk_score(existing, 90, 'HIGH')
    monitor.process_matched_domain('brand-old.example', match)
    preserved = db.get_candidate(existing)
    assert preserved['status'] == 'resolved'
    assert preserved['risk_score'] == 90 and preserved['evidence_status'] == 'complete'
    monitor.process_matched_domain('brand-new.example', match)
    new = next(c for c in db.get_all_candidates(org_id=org) if c['domain']=='brand-new.example')
    breakdown = json.loads(new['risk_breakdown'])
    assert breakdown['visual_similarity'] == 0 and breakdown['suspicious_phrases'] == 0
    assert new['organization_id'] == org and new['confidence_level'] == 'LOW'
    alert.assert_not_called()
