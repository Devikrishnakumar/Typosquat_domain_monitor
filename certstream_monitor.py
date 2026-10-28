"""
certstream_monitor.py
Continuous background CertStream listener for real-time phishing detection.
Streams new SSL/TLS certificates from CertStream, matches against monitored brand watchlists,
collects multi-signal evidence, calculates risk, saves to SQLite, and sends Telegram alerts.

Can run as a local Python background process:
    python certstream_monitor.py

Or optionally inside Docker:
    docker compose -f docker-compose.certstream.yml up -d
"""

import os
import sys
import json
import time
import signal
import socket
import logging
import argparse
import threading
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
import websocket

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dotenv import load_dotenv
load_dotenv()

from src.storage import db
from src.storage.models import Candidate, Brand, DiscoveryObservation, utc_now_iso
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert
from src.enrichment.whois_lookup import get_whois_info

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("certstream_monitor")

CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
HEALTH_PATH = Path("data") / "worker_health.json"
EVENTS_LOG_PATH = Path("data") / "certstream_events.jsonl"


class CertStreamMonitor:
    def __init__(self, certstream_url: str = CERTSTREAM_URL):
        self.url = certstream_url
        self.running = False
        self.ws = None
        self.events_seen = 0
        self.matches_found = 0
        self.start_time = time.time()
        self.watched_brands: List[Dict[str, Any]] = []
        self.recent_domains: Set[str] = set()

        os.makedirs("data", exist_ok=True)
        db.init_db()
        self.refresh_watchlist()

    def refresh_watchlist(self):
        """Loads monitored brands from SQLite database."""
        session = db.SessionLocal()
        try:
            brands = session.query(Brand).all()
            if not brands:
                # Default PayPal if empty
                b = Brand(
                    organization_id=1,
                    name="PayPal",
                    official_domain="paypal.com",
                    official_website_url="https://www.paypal.com",
                    keywords=json.dumps(["paypal", "paypa1", "pay-pal"]),
                )
                session.add(b)
                session.commit()
                brands = [b]

            self.watched_brands = []
            for b in brands:
                kw = json.loads(b.keywords) if b.keywords else []
                base = b.official_domain.split(".")[0]
                if base not in kw:
                    kw.append(base)
                self.watched_brands.append({
                    "id": b.id,
                    "name": b.name,
                    "official_domain": b.official_domain.lower(),
                    "keywords": [k.lower() for k in kw],
                })
            logger.info(f"Loaded {len(self.watched_brands)} monitored brands into watchlist.")
        finally:
            session.close()

    def is_brand_impersonation(self, domain: str) -> Optional[Dict[str, Any]]:
        """Checks if a domain matches any brand keyword or lookalike pattern without being official."""
        clean = domain.lower().strip().lstrip("*.")
        if not clean or "." not in clean:
            return None

        for b in self.watched_brands:
            off = b["official_domain"]
            # Exclude official brand subdomains (e.g. checkout.paypal.com)
            if clean == off or clean.endswith(f".{off}"):
                continue

            for kw in b["keywords"]:
                if kw in clean:
                    return {
                        "brand_id": b["id"],
                        "brand_name": b["name"],
                        "official_domain": off,
                        "matched_keyword": kw,
                    }
        return None

    def update_health(self, state: str = "connected", extra_msg: str = ""):
        """Writes heartbeat status to data/worker_health.json."""
        data = {
            "state": state,
            "updated_at": time.time(),
            "uptime_seconds": int(time.time() - self.start_time),
            "events_seen": self.events_seen,
            "matches_found": self.matches_found,
            "certstream_url": self.url,
            "message": extra_msg or f"CertStream monitor active. Processed {self.events_seen} certs.",
        }
        try:
            HEALTH_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def log_event(self, event_data: Dict[str, Any]):
        """Logs event line to data/certstream_events.jsonl."""
        try:
            with open(EVENTS_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")
        except Exception:
            pass

    def process_domain(self, domain: str, match_info: Dict[str, Any], issuer: str = ""):
        """Handles a matched lookalike certificate: collects evidence, scores risk, records to DB."""
        if domain in self.recent_domains:
            return
        self.recent_domains.add(domain)
        if len(self.recent_domains) > 10000:
            self.recent_domains.clear()

        self.matches_found += 1
        brand_domain = match_info["official_domain"]
        logger.info(f"🚨 [MATCH] Detected lookalike domain: {domain} targeting {brand_domain}")

        # Quick DNS check
        is_live = False
        ip = None
        try:
            ip = socket.gethostbyname(domain)
            is_live = True
        except Exception:
            pass

        # Score risk
        # Newly issued certificate for a lookalike domain is an immediate threat signal
        score, breakdown = compute_risk_score(
            is_live=is_live,
            visual_similarity=0.60 if is_live else 0.20,
            has_login_form=False,
            suspicious_phrase_count=2,
        )
        score = min(100.0, score + 20.0)  # CT issuance bonus
        breakdown["certstream_tls_issuance"] = 20.0
        level = risk_level(score)

        now = utc_now_iso()

        # Save to SQLite
        session = db.SessionLocal()
        try:
            cand = session.query(Candidate).filter_by(domain=domain, matched_brand=brand_domain).first()
            if not cand:
                cand = Candidate(
                    domain=domain,
                    matched_brand=brand_domain,
                    brand_id=match_info["brand_id"],
                    detected_at=now,
                    first_seen_at=now,
                    last_seen_at=now,
                    discovered_at=now,
                    imported_at=now,
                    event_category="certstream_live",
                )
                session.add(cand)

            cand.is_live = 1 if is_live else 0
            cand.risk_score = score
            cand.risk_level = level
            cand.status = "new"
            cand.evidence_status = "live_stream"
            cand.confidence_level = level
            cand.recommended_action = f"Monitor and issue preemptive takedown for {domain} (New TLS issued: {issuer[:40]})."
            cand.risk_breakdown = json.dumps(breakdown)
            cand.analyst_notes = f"Discovered via live CertStream feed. Issuer: {issuer}"

            session.commit()
            session.refresh(cand)

            obs = DiscoveryObservation(
                candidate_id=cand.id,
                source="CERTSTREAM_LIVE",
                observed_at=now,
                imported_at=now,
                raw_data=json.dumps({
                    "domain": domain,
                    "issuer": issuer,
                    "ip": ip,
                    "matched_keyword": match_info["matched_keyword"],
                }),
            )
            session.add(obs)
            session.commit()

            # Alert if HIGH risk
            if level == "HIGH":
                send_alert(
                    domain=domain,
                    risk_score=score,
                    risk_level=level,
                    matched_brand=brand_domain,
                    source="CERTSTREAM_LIVE",
                    risk_reason=f"New TLS certificate issued for lookalike: {domain}",
                )

            # Log to events file
            self.log_event({
                "source": "LIVE_CERTSTREAM",
                "stream_mode": "live",
                "event_type": "certificate_update",
                "domains": [domain],
                "matched_domains": [domain],
                "issuer": issuer,
                "observed_at": now,
                "risk_level": level,
                "risk_score": score,
            })
        except Exception as e:
            logger.error(f"Error persisting candidate {domain}: {e}")
        finally:
            session.close()

    def on_message(self, ws, message):
        try:
            data = json.loads(message)
            self.events_seen += 1

            if self.events_seen % 25 == 0:
                self.update_health("connected")

            msg_type = data.get("message_type")
            if msg_type == "certificate_update":
                leaf_cert = data.get("data", {}).get("leaf_cert", {})
                all_domains = leaf_cert.get("all_domains", [])
                issuer = leaf_cert.get("issuer", {}).get("O", "Unknown CA")

                # Also log sample live events for dashboard visualization
                if self.events_seen % 10 == 0 and all_domains:
                    self.log_event({
                        "source": "LIVE_CERTSTREAM",
                        "stream_mode": "live",
                        "event_type": "certificate_update",
                        "domains": all_domains[:5],
                        "issuer": issuer,
                        "observed_at": utc_now_iso(),
                    })

                for d in all_domains:
                    match = self.is_brand_impersonation(d)
                    if match:
                        self.process_domain(d, match, issuer)

        except Exception as e:
            logger.debug(f"Message parsing error: {e}")

    def on_error(self, ws, error):
        logger.warning(f"CertStream websocket error: {error}")
        self.update_health("error", str(error))

    def on_close(self, ws, close_status_code, close_msg):
        logger.info(f"CertStream connection closed ({close_status_code}: {close_msg})")
        self.update_health("disconnected", "Connection closed")

    def on_open(self, ws):
        logger.info(f"Connected to CertStream at {self.url}")
        self.update_health("connected", "Streaming live Certificate Transparency logs")

    def run_synthetic_stream(self, interval_seconds: float = 3.0):
        """Simulates continuous CertStream events for offline testing or demonstration."""
        logger.info("Starting synthetic CertStream generator mode...")
        self.running = True
        synthetic_pool = [
            ("paypal-security-verification-live.com", "Let's Encrypt"),
            ("paypal-login-account-update.net", "Cloudflare, Inc."),
            ("google-drive-share-doc.com", "DigiCert Inc"),
            ("paypa1-billing-resolver.org", "Sectigo Limited"),
            ("my-personal-crypto-blog.io", "Let's Encrypt"),
            ("cdn-asset-delivery-node-99.net", "Amazon"),
            ("paypal-user-support-desk.com", "ZeroSSL"),
        ]
        idx = 0
        while self.running:
            dom, ca = synthetic_pool[idx % len(synthetic_pool)]
            idx += 1
            self.events_seen += 1

            self.log_event({
                "source": "SYNTHETIC_CERTSTREAM_DEMO",
                "stream_mode": "synthetic",
                "event_type": "certificate_update",
                "domains": [dom],
                "issuer": ca,
                "observed_at": utc_now_iso(),
            })

            match = self.is_brand_impersonation(dom)
            if match:
                self.process_domain(dom, match, ca)

            self.update_health("synthetic", f"Synthetic demo running. Processed {self.events_seen} sample events.")
            time.sleep(interval_seconds)

    def start(self, synthetic: bool = False):
        self.running = True
        if synthetic:
            self.run_synthetic_stream()
            return

        while self.running:
            try:
                self.ws = websocket.WebSocketApp(
                    self.url,
                    on_open=self.on_open,
                    on_message=self.on_message,
                    on_error=self.on_error,
                    on_close=self.on_close,
                )
                self.ws.run_forever(ping_interval=30, ping_timeout=10)
            except Exception as e:
                logger.error(f"CertStream listener loop error: {e}")
                self.update_health("error", str(e))

            if self.running:
                logger.info("Reconnecting to CertStream in 5 seconds...")
                time.sleep(5)

    def stop(self):
        self.running = False
        if self.ws:
            self.ws.close()
        self.update_health("stopped", "Worker stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Continuous CertStream Phishing Monitor")
    parser.add_argument("--simulate-stream", action="store_true", help="Run in synthetic simulation mode for demo/testing")
    parser.add_argument("--url", default=CERTSTREAM_URL, help="Custom CertStream WebSocket URL")
    args = parser.parse_args()

    monitor = CertStreamMonitor(certstream_url=args.url)

    def sig_handler(sig, frame):
        print("\nStopping CertStream Monitor...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    monitor.start(synthetic=args.simulate_stream)
