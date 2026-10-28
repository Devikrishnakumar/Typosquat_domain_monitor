"""Navigation regression checks without starting monitoring or touching user data."""
import time
from unittest.mock import Mock

import pytest
import streamlit as st
from sqlalchemy import event
from streamlit.testing.v1 import AppTest

from src.storage import db
from src.storage.models import Brand, Candidate, DiscoveryObservation
from src.ui.dashboard_data import get_all_flagged_with_observations
from src.ui.navigation import DESTINATIONS, PAGE_KEY


@pytest.fixture
def isolated_dashboard(tmp_path, monkeypatch):
    original_url = db.DATABASE_URL
    db.configure_database('sqlite:///' + (tmp_path / 'navigation.db').as_posix())
    db.init_db()
    with db.SessionLocal() as session:
        session.add_all([
            Brand(organization_id=1, name='Example', official_domain='example.com'),
            Brand(organization_id=1, name='Other', official_domain='example.org'),
        ])
        session.commit()
    import src.ingest.background_service as monitor
    monkeypatch.setattr(monitor, 'start_background_monitor', Mock(return_value=(True, 'Test monitor')))
    monkeypatch.setattr(monitor, 'get_monitor_status', lambda: {
        'state': 'stopped', 'events_seen': 0, 'matches_found': 0,
        'updated_at': time.time(), 'active_targets': [],
    })
    import src.simulation.demo_data as demo
    monkeypatch.setattr(demo, 'ensure_demo_assets', Mock(return_value={}))
    st.cache_resource.clear()
    yield demo
    st.cache_resource.clear()
    db.configure_database(original_url)


def assert_healthy(app):
    assert not app.exception, [exc.message for exc in app.exception]


def test_all_destinations_and_expand_collapse(isolated_dashboard, monkeypatch):
    init = Mock(wraps=db.init_db)
    monkeypatch.setattr(db, 'init_db', init)
    app = AppTest.from_file('app.py', default_timeout=120).run()
    assert_healthy(app)
    for index, (slug, page) in enumerate(DESTINATIONS.items()):
        app.button(key=f'menu_item_{PAGE_KEY}_{index}').click().run()
        assert_healthy(app)
        assert app.session_state[PAGE_KEY] == page
        assert app.query_params['view'] == [slug]
        assert len([b for b in app.sidebar.button if b.key.startswith('menu_item_')]) == 7
    selected_page = app.session_state[PAGE_KEY]
    app.button(key=f'menu_toggle_{PAGE_KEY}').click().run()
    assert app.session_state[f'{PAGE_KEY}_menu_expanded'] is False
    assert app.session_state[PAGE_KEY] == selected_page
    app.button(key=f'menu_item_{PAGE_KEY}_0').click().run()
    assert app.session_state[PAGE_KEY] == DESTINATIONS['explorer']
    app.button(key=f'menu_toggle_{PAGE_KEY}').click().run()
    assert app.session_state[f'{PAGE_KEY}_menu_expanded'] is True
    assert app.session_state[PAGE_KEY] == DESTINATIONS['explorer']
    assert_healthy(app)
    assert init.call_count == 1
    # Similarities should only be computed when the demo page is actually visited.
    assert isolated_dashboard.ensure_demo_assets.call_count == 1


def test_deep_link_and_report_return(isolated_dashboard):
    app = AppTest.from_file('app.py', default_timeout=120)
    app.query_params['view'] = 'reports'
    app.run()
    assert_healthy(app)
    assert app.session_state[PAGE_KEY] == DESTINATIONS['reports']
    next(b for b in app.button if b.label == 'Open domain explorer').click().run()
    assert_healthy(app)
    assert app.session_state[PAGE_KEY] == DESTINATIONS['explorer']
    assert app.query_params['view'] == ['explorer']


def test_watchlist_scan_shortcut_changes_existing_scanner_target(isolated_dashboard):
    app = AppTest.from_file('app.py', default_timeout=120).run()
    app.button(key=f'menu_item_{PAGE_KEY}_4').click().run()
    assert app.selectbox(key='scan_target_domain').value == 'example.com'
    app.button(key=f'menu_item_{PAGE_KEY}_2').click().run()
    app.button(key='scan_slot_2').click().run()
    assert_healthy(app)
    assert app.session_state[PAGE_KEY] == DESTINATIONS['scanner']
    assert app.selectbox(key='scan_target_domain').value == 'example.org'


def test_latest_evidence_in_one_query_including_missing_and_bad_json(isolated_dashboard):
    with db.SessionLocal() as session:
        candidates = [Candidate(domain=f'candidate-{i}.test', matched_brand='Example',
                                detected_at='2026-10-28T00:00:00+00:00') for i in range(300)]
        session.add_all(candidates)
        session.flush()
        session.add_all([
            DiscoveryObservation(candidate_id=candidates[0].id, source='manual', raw_data='{"version":1}'),
            DiscoveryObservation(candidate_id=candidates[0].id, source='manual', raw_data='{"version":2}'),
            DiscoveryObservation(candidate_id=candidates[1].id, source='manual', raw_data='broken'),
            DiscoveryObservation(candidate_id=candidates[2].id, source='manual', raw_data='[]'),
        ])
        session.commit()
    statements = []
    def record(*args):
        statements.append(args[2])
    event.listen(db.engine, 'before_cursor_execute', record)
    try:
        findings = get_all_flagged_with_observations()
    finally:
        event.remove(db.engine, 'before_cursor_execute', record)
    assert len(statements) == 1
    assert len(findings) == 300
    by_domain = {c.domain: evidence for c, evidence in findings}
    assert by_domain['candidate-0.test'] == {'version': 2}
    assert by_domain['candidate-1.test'] == {}
    assert by_domain['candidate-2.test'] == {}
    assert by_domain['candidate-299.test'] == {}


def test_loader_clears_after_success_and_failure():
    for should_fail in (False, True):
        app = AppTest.from_string(f'''
from src.ui.loading import task_loading
import streamlit as st
try:
    with task_loading('Loading <workspace>'):
        if {should_fail!r}:
            raise ValueError('Example failure')
except ValueError:
    pass
st.write('Finished')
''', default_timeout=120).run()
        assert_healthy(app)
        assert not app.get('html')
        assert app.markdown[0].value == 'Finished'


def test_enterprise_dashboard_renders_nonempty_risk_chart(isolated_dashboard):
    candidate = db.insert_candidate('suspicious.example', 'example.com')
    db.update_risk_score(candidate, 85, 'CRITICAL')
    app = AppTest.from_file('dashboard/app.py', default_timeout=120).run()
    assert_healthy(app)
    for index in range(7):
        app.button(key=f'menu_item_enterprise_dashboard_current_page_{index}').click().run()
        assert_healthy(app)
        if index == 1:
            search = next(widget for widget in app.text_input if 'Search Domain or Brand' in widget.label)
            search.input('[').run()
            assert_healthy(app)
            next(widget for widget in app.text_input if 'Search Domain or Brand' in widget.label).input('').run()
            assert_healthy(app)


def test_severity_chart_keeps_critical_and_unknown_separate():
    from types import SimpleNamespace
    from src.ui.threat_charts import severity_counts
    counts = severity_counts([SimpleNamespace(risk_level='CRITICAL'), SimpleNamespace(risk_level=None)])
    by_level = dict(zip(counts.Severity, counts.Findings))
    assert by_level['CRITICAL'] == 1
    assert by_level['LOW'] == 0
    assert sum(by_level.values()) == 1
