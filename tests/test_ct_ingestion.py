import json
from concurrent.futures import Future

from src.ingest import ct_stream_client


class DeferredExecutor:
    def __init__(self):
        self.calls = []
        self.future = Future()

    def submit(self, function, *args):
        self.calls.append((function, args))
        return self.future


def test_suspicious_matches_are_queued_and_recent_duplicates_skipped(
    monkeypatch, tmp_path
):
    domain = "paypa1-example.test"
    brand = "paypal.example"
    key = (domain, brand)
    ct_stream_client._recent_matches.pop(key, None)
    executor = DeferredExecutor()
    event_log = tmp_path / "events.jsonl"

    monkeypatch.setattr(ct_stream_client, "_ENRICHMENT_POOL", executor)
    monkeypatch.setattr(ct_stream_client, "EVENT_LOG_PATH", event_log)
    monkeypatch.setattr(ct_stream_client, "is_suspicious", lambda *args, **kwargs: True)

    message = json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "leaf_cert": {
                    "all_domains": [domain],
                    "issuer": {"O": "Example CA"},
                }
            },
        }
    )

    ct_stream_client.on_message(None, message, {domain}, brand)
    ct_stream_client.on_message(None, message, {domain}, brand)

    assert len(executor.calls) == 1
    assert executor.calls[0][1] == (domain, brand)
    logged = [json.loads(line) for line in event_log.read_text().splitlines()]
    assert len(logged) == 2
    assert logged[0]["source"] == "LIVE_CERTSTREAM"

    executor.future.set_result(None)
    ct_stream_client._recent_matches.pop(key, None)


def test_multiple_brand_matches_are_independent():
    assert ct_stream_client._find_matching_brands(
        "paypa1.example",
        {
            "paypal.example": {"paypa1.example"},
            "other.example": {"other-lookalike.example"},
        },
        "multiple brands",
    ) == ["paypal.example"]


def test_worker_health_status_is_written_atomically(tmp_path, monkeypatch):
    health_path = tmp_path / "health.json"
    monkeypatch.setattr(ct_stream_client, "HEALTH_PATH", health_path)

    ct_stream_client._write_worker_health("connected")

    health = json.loads(health_path.read_text(encoding="utf-8"))
    assert health["state"] == "connected"
    assert isinstance(health["updated_at"], float)
    assert not health_path.with_suffix(".tmp").exists()
