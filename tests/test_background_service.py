import json
import time

from src.ingest.background_service import BackgroundDomainMonitor


def test_background_monitor_processes_real_certstream_updates():
    monitor = BackgroundDomainMonitor.__new__(BackgroundDomainMonitor)
    monitor.url = "wss://certstream.example/"
    monitor.events_seen = 0
    monitor.matches_found = 0
    monitor.start_time = time.time()
    monitor.running = True
    monitor.ws = None
    monitor.recent_seen = set()
    monitor.last_health_update = 0

    targets = [{
        "id": 7,
        "name": "PayPal",
        "domain": "paypal.com",
        "keywords": ["paypal", "paypa1"],
    }]
    monitor.get_active_targets = lambda: targets
    logged_events = []
    matched_domains = []
    health_updates = []
    monitor.log_event = logged_events.append
    monitor.update_health = lambda state, msg="": health_updates.append((state, msg))

    def record_match(domain, match, issuer):
        matched_domains.append((domain, match["official_domain"], issuer))
        monitor.matches_found += 1

    monitor.process_matched_domain = record_match
    monitor.handle_message(json.dumps({
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["www.example.org", "*.paypal-login.example.net"],
                "issuer": {"O": "Example Certificate Authority"},
            },
        },
    }))

    assert monitor.events_seen == 1
    assert monitor.matches_found == 1
    assert matched_domains == [
        ("paypal-login.example.net", "paypal.com", "Example Certificate Authority")
    ]
    assert logged_events[0]["source"] == "LIVE_CERTSTREAM"
    assert logged_events[0]["stream_mode"] == "live"
    assert logged_events[0]["domains"] == [
        "www.example.org",
        "paypal-login.example.net",
    ]
    assert health_updates == [("connected", "")]


def test_background_monitor_ignores_non_certificate_messages():
    monitor = BackgroundDomainMonitor.__new__(BackgroundDomainMonitor)
    monitor.events_seen = 0
    monitor.handle_message(json.dumps({"message_type": "heartbeat"}))
    assert monitor.events_seen == 0


def test_connected_socket_without_certificates_is_waiting(tmp_path, monkeypatch):
    from src.ingest import background_service as service
    monitor = BackgroundDomainMonitor.__new__(BackgroundDomainMonitor)
    monitor.url = 'wss://feed.example/lite'
    monitor.events_seen = monitor.matches_found = 0
    monitor.start_time = time.time()
    monitor.connected_at = time.time()
    monitor.last_event_at = 0
    monitor.get_active_targets = lambda: []
    path = tmp_path / 'health.json'
    monkeypatch.setattr(service, 'HEALTH_FILE', path)
    monitor.update_health('connected')
    assert service.get_monitor_status()['state'] == 'waiting'
    monitor.last_event_at = time.time()
    monitor.events_seen = 1
    monitor.update_health('connected')
    assert service.get_monitor_status()['state'] == 'connected'
    monitor.last_event_at = time.time() - 70
    monitor.update_health('connected')
    assert service.get_monitor_status()['state'] == 'stalled'


def test_old_heartbeat_never_claims_live(tmp_path, monkeypatch):
    from src.ingest import background_service as service
    path = tmp_path / 'health.json'
    path.write_text(json.dumps({'state': 'connected', 'updated_at': time.time()-100, 'last_event_at': time.time()}))
    monkeypatch.setattr(service, 'HEALTH_FILE', path)
    assert service.get_monitor_status()['state'] == 'stale'


def test_monitor_runtime_survives_module_reload():
    import importlib
    from src.ingest import background_service as service
    runtime = service._runtime
    assert importlib.reload(service)._runtime is runtime


def test_event_log_retries_transient_windows_lock(tmp_path, monkeypatch):
    from pathlib import Path
    from src.ingest import background_service as service
    path = tmp_path / 'events.jsonl'
    path.write_text('{}\n{}\n', encoding='utf-8')
    monkeypatch.setattr(service, 'EVENTS_FILE', path)
    monkeypatch.setattr(service, 'EVENT_LOG_LIMIT', 2)
    actual_replace = Path.replace
    attempts = []
    def temporarily_locked(source, target):
        attempts.append(1)
        if len(attempts) == 1:
            raise PermissionError('Windows reader holds target')
        return actual_replace(source, target)
    monkeypatch.setattr(Path, 'replace', temporarily_locked)
    monitor = service.BackgroundDomainMonitor.__new__(service.BackgroundDomainMonitor)
    monitor.log_event({'source':'test'})
    lines = path.read_text(encoding='utf-8').splitlines()
    assert len(lines) == 2 and json.loads(lines[-1])['source'] == 'test'
    assert len(attempts) == 2
    assert not list(tmp_path.glob('*.tmp'))


def test_event_log_failure_never_raises_into_certificate_callback(tmp_path, monkeypatch):
    from pathlib import Path
    from src.ingest import background_service as service
    path = tmp_path / 'events.jsonl'
    path.write_text('{}\n', encoding='utf-8')
    monkeypatch.setattr(service, 'EVENTS_FILE', path)
    monkeypatch.setattr(service, 'EVENT_LOG_LIMIT', 1)
    def locked(*args):
        raise PermissionError('File still locked')
    monkeypatch.setattr(Path, 'replace', locked)
    monitor = service.BackgroundDomainMonitor.__new__(service.BackgroundDomainMonitor)
    monitor.log_event({'source':'test'})
    assert json.loads(path.read_text(encoding='utf-8').splitlines()[-1])['source'] == 'test'
    assert not list(tmp_path.glob('*.tmp'))
