"""
ct_stream_client.py
Full Continuous Monitoring Pipeline:
CertStream CT event stream -> domain normalization & deduplication ->
multi-signal investigation (DNS, TLS, HTTP, visual, content, WHOIS) ->
composite risk scoring -> deduplicated alerts & takedown reports -> PostgreSQL storage.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
import websocket

from .permutation_filter import (
    get_brand_settings,
    get_monitored_brands,
    build_permutation_set,
    is_suspicious,
)
from src.normalization.domain_normalizer import normalize_domain, is_excluded_domain
from src.investigation.domain_investigator import DomainInvestigator
from src.scoring.risk_engine import EnterpriseRiskEngine
from src.alerts.notification_manager import notification_manager
from src.storage import db
from src.storage.models import utc_now_iso
from src.enrichment.screenshot import capture_screenshot, ensure_reference_screenshot
from src.enrichment.whois_lookup import get_whois_info
from src.reporting.report_generator import generate_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("continuous_monitor")

CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "ws://localhost:8081/full-stream")

EVENT_LOG_PATH = Path(
    os.getenv(
        "CERTSTREAM_EVENT_LOG",
        str(Path(__file__).resolve().parents[2] / "data" / "certstream_events.jsonl"),
    )
)
HEALTH_PATH = Path(
    os.getenv(
        "MONITOR_HEALTH_PATH",
        str(Path(__file__).resolve().parents[2] / "data" / "worker_health.json"),
    )
)

ENRICHMENT_WORKERS = max(1, int(os.getenv("ENRICHMENT_WORKERS", "4")))
MAX_PENDING_ENRICHMENTS = max(
    ENRICHMENT_WORKERS,
    int(os.getenv("MAX_PENDING_ENRICHMENTS", "100")),
)
_pending_slots = threading.BoundedSemaphore(MAX_PENDING_ENRICHMENTS)
_recent_matches = OrderedDict()
_recent_matches_lock = threading.Lock()
_RECENT_MATCH_LIMIT = 10000
_connection_opened_at = None
_REFERENCE_PATHS = {}
_ENRICHMENT_POOL = ThreadPoolExecutor(
    max_workers=ENRICHMENT_WORKERS,
    thread_name_prefix="domain-enrichment",
)

# Operational metrics
_metrics = {
    "events_seen": 0,
    "candidates_found": 0,
    "last_successful_run": None,
    "last_error": None,
}

investigator = DomainInvestigator()
risk_engine = EnterpriseRiskEngine()


def _claim_recent_match(domain, official_domain):
    """Avoid re-enriching repeated CT entries during this worker's lifetime."""
    key = (domain.lower().rstrip("."), official_domain.lower().rstrip("."))
    now = time.monotonic()
    with _recent_matches_lock:
        for old_key, observed_at in list(_recent_matches.items()):
            if now - observed_at < 3600:
                break
            _recent_matches.pop(old_key, None)
        if key in _recent_matches:
            _recent_matches.move_to_end(key)
            _recent_matches[key] = now
            return False
        _recent_matches[key] = now
        if len(_recent_matches) > _RECENT_MATCH_LIMIT:
            _recent_matches.popitem(last=False)
        return True


def _write_worker_health(state, error=None):
    try:
        HEALTH_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = HEALTH_PATH.with_suffix(".tmp")
        payload = {
            "state": state,
            "updated_at": time.time(),
            "queue_depth": MAX_PENDING_ENRICHMENTS - _pending_slots._value,
            "events_seen": _metrics["events_seen"],
            "candidates_found": _metrics["candidates_found"],
            "last_successful_run": _metrics["last_successful_run"],
            "last_error": error or _metrics["last_error"],
            "product_name": "CyberSentinel",
        }
        temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary_path.replace(HEALTH_PATH)
    except OSError as exc:
        logger.warning(f"[HEALTH] Could not update worker health file: {exc}")


def _process_candidate(domain, official_domain):
    candidate_id = None
    try:
        logger.info(f"[SUSPICIOUS MATCH] {domain} impersonating {official_domain}")
        _metrics["candidates_found"] += 1
        _metrics["last_successful_run"] = utc_now_iso()

        norm = normalize_domain(domain)
        clean_domain = norm.ascii_domain or domain

        # 1. Insert candidate domain into database
        candidate_id = db.insert_candidate(
            domain=clean_domain,
            matched_brand=official_domain,
            decoded_domain=norm.unicode_domain,
            event_category="newly_observed",
            source="certstream",
            observed_at=utc_now_iso(),
            imported_at=utc_now_iso(),
        )

        # 2. Run multi-signal investigation
        ref_path = _REFERENCE_PATHS.get(official_domain)
        inv_results = investigator.run_full_investigation(
            candidate_id=candidate_id,
            domain=clean_domain,
            official_domain=official_domain,
            reference_image_path=ref_path,
        )

        # 3. Compute enterprise risk score & classifications
        risk_result = risk_engine.evaluate(
            domain=clean_domain,
            official_domain=official_domain,
            is_live=inv_results["is_live"],
            visual_similarity=inv_results["visual_similarity"],
            has_login_form=inv_results["has_login_form"],
            suspicious_phrase_count=inv_results["suspicious_phrase_count"],
            whois_info=inv_results.get("whois"),
            has_tls=inv_results.get("tls", {}).get("has_tls", False),
        )

        db.update_risk_score(
            candidate_id=candidate_id,
            score=risk_result.score,
            level=risk_result.severity,
            confidence=risk_result.confidence,
            reasons=risk_result.reasons,
            recommended_action=risk_result.recommended_action,
        )
        logger.info(f"  -> RISK SCORE: {risk_result.score}/100 ({risk_result.severity})")

        # 4. Dispatch Alert (Telegram & Email with deduplication)
        notification_manager.dispatch_candidate_alert(
            candidate_id=candidate_id,
            domain=clean_domain,
            brand_name=official_domain,
            official_domain=official_domain,
            risk_score=risk_result.score,
            severity=risk_result.severity,
            reasons=risk_result.reasons,
            source="CERTSTREAM",
            event_category="newly_observed",
            alert_threshold=60,
            enable_telegram=True,
            enable_email=False,
        )

        # 5. Generate PDF Report if High or Critical risk
        if risk_result.severity in {"HIGH", "CRITICAL"}:
            whois_info = inv_results.get("whois") or get_whois_info(clean_domain)
            candidate_record = {
                "domain": clean_domain,
                "decoded_domain": norm.unicode_domain,
                "matched_brand": official_domain,
                "detected_at": utc_now_iso(),
                "is_live": inv_results["is_live"],
                "visual_similarity": inv_results["visual_similarity"],
                "has_login_form": inv_results["has_login_form"],
                "risk_score": risk_result.score,
                "risk_level": risk_result.severity,
                "screenshot_path": inv_results.get("screenshot_path"),
                "reference_screenshot_path": ref_path,
            }
            try:
                report_path = generate_report(candidate_record, whois_info)
                logger.info(f"  -> Takedown report generated: {report_path}")
            except Exception as r_err:
                logger.warning(f"Report generation error: {r_err}")

    except Exception as exc:
        _metrics["last_error"] = str(exc)
        if candidate_id is not None:
            try:
                db.update_evidence_details(candidate_id, "failed")
            except Exception:
                pass
        logger.error(f"[ENRICHMENT] Failed for {domain}: {exc}", exc_info=True)


def record_certstream_event(leaf_cert, domains, permutation_set, official_domain):
    """Write genuine certificate update to the shared rolling event log."""
    try:
        domain_names = [
            str(domain)[:253]
            for domain in domains
            if isinstance(domain, str) and domain.strip()
        ]

        matched_by_domain = {
            domain: _find_matching_brands(domain, permutation_set, official_domain)
            for domain in domain_names
        }
        matched_domains = [d for d, brands in matched_by_domain.items() if brands]
        matched_brands = sorted({b for brands in matched_by_domain.values() for b in brands})

        issuer_data = leaf_cert.get("issuer") or {}
        if isinstance(issuer_data, dict):
            issuer = (
                issuer_data.get("O")
                or issuer_data.get("organizationName")
                or issuer_data.get("CN")
                or "Not provided"
            )
        else:
            issuer = str(issuer_data) if issuer_data else "Not provided"

        event = {
            "stream_mode": "live",
            "observed_at": utc_now_iso(),
            "event_type": "certificate_update",
            "domain_count": len(domain_names),
            "domains": domain_names[:10],
            "issuer": str(issuer)[:200],
            "matched_domains": matched_domains[:10],
            "matched_brand": matched_brands[0] if len(matched_brands) == 1 else None,
            "matched_brands": matched_brands,
            "brand_match": bool(matched_domains),
            "certificate_not_before": leaf_cert.get("not_before"),
            "certificate_not_after": leaf_cert.get("not_after"),
            "fingerprint": leaf_cert.get("fingerprint"),
            "source": "LIVE_CERTSTREAM",
        }

        EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EVENT_LOG_PATH.open("a", encoding="utf-8") as event_file:
            event_file.write(json.dumps(event, ensure_ascii=False) + "\n")

        if EVENT_LOG_PATH.stat().st_size > 2 * 1024 * 1024:
            lines = EVENT_LOG_PATH.read_text(encoding="utf-8").splitlines()
            EVENT_LOG_PATH.write_text("\n".join(lines[-200:]) + "\n", encoding="utf-8")

    except Exception as exc:
        logger.warning(f"[EVENT FEED] Could not record certificate update: {exc}")


def on_message(ws, message, permutation_set, official_domain):
    try:
        data = json.loads(message)
        if data.get("message_type") != "certificate_update":
            return

        _metrics["events_seen"] += 1
        leaf_cert = data.get("data", {}).get("leaf_cert", {})
        domains = leaf_cert.get("all_domains", [])
        if not isinstance(domains, list):
            domains = []

        record_certstream_event(leaf_cert, domains, permutation_set, official_domain)

        for domain in domains:
            if not isinstance(domain, str):
                continue
            for matched_brand in _find_matching_brands(domain, permutation_set, official_domain):
                # Exclude if domain is official or approved
                is_excl, _ = is_excluded_domain(domain, official_domains=[matched_brand])
                if is_excl:
                    continue

                if not _claim_recent_match(domain, matched_brand):
                    continue

                _pending_slots.acquire()
                try:
                    future = _ENRICHMENT_POOL.submit(_process_candidate, domain, matched_brand)
                except Exception:
                    _pending_slots.release()
                    raise
                future.add_done_callback(lambda _: _pending_slots.release())
    except Exception as exc:
        logger.warning(f"Error processing CT message: {exc}")


def _find_matching_brands(domain, permutation_set, official_domain):
    if isinstance(permutation_set, dict):
        return [
            brand
            for brand, permutations in permutation_set.items()
            if is_suspicious(domain, permutations, official_domain=brand)
        ]
    if official_domain and is_suspicious(domain, permutation_set, official_domain=official_domain):
        return [official_domain]
    return []


def on_error(ws, error):
    _write_worker_health("reconnecting", error=str(error))
    logger.warning(f"Websocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    _write_worker_health("reconnecting")
    logger.info("Connection closed.")


def on_open(ws):
    global _connection_opened_at
    _connection_opened_at = time.monotonic()
    _write_worker_health("connected")
    logger.info("Connected to certstream-server-go. Watching for fake website impersonation matches...\n")


def on_pong(ws, payload):
    _write_worker_health("connected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Continuous Monitoring Worker")
    parser.add_argument("--brand", help="Override brand domain, e.g. paypal.com")
    args = parser.parse_args()

    db.init_db()

    # Load brands from DB if any, otherwise from config file
    db_brands = db.get_brands()
    if db_brands:
        brands = [{"official_domain": b["official_domain"], "name": b["name"]} for b in db_brands]
    else:
        brands = (
            [{"official_domain": get_brand_settings(cli_brand=args.brand)}]
            if args.brand
            else get_monitored_brands()
        )

    official_domain = brands[0]["official_domain"] if len(brands) == 1 else "multiple brands"
    permutation_set = {}
    for brand in brands:
        domain = brand["official_domain"]
        try:
            permutation_set[domain] = build_permutation_set(domain)
            _REFERENCE_PATHS[domain] = ensure_reference_screenshot(domain)
            logger.info(f"Monitoring {domain}: {len(permutation_set[domain])} permutations.")
        except Exception as e:
            logger.warning(f"Failed to generate permutations for {domain}: {e}")

    retry_delay = 1
    while True:
        _connection_opened_at = None
        _write_worker_health("connecting")
        ws = websocket.WebSocketApp(
            CERTSTREAM_URL,
            on_open=on_open,
            on_message=lambda ws, msg: on_message(ws, msg, permutation_set, official_domain),
            on_error=on_error,
            on_close=on_close,
            on_pong=on_pong,
        )
        try:
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as exc:
            logger.warning(f"[CERTSTREAM] Connection failed: {exc}")

        if _connection_opened_at is not None and time.monotonic() - _connection_opened_at >= 60:
            retry_delay = 1
        _write_worker_health("reconnecting")
        logger.info(f"[CERTSTREAM] Reconnecting in {retry_delay}s.")
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 60)
