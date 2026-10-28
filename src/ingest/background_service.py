"""
background_service.py
Daemon Background Monitoring Engine.
Runs continuously in the background, checking streaming domains from Certificate Transparency
against at most 3 monitored websites. Persists flagged domains to SQLite and dispatches Telegram alerts.
"""

import os
import sys
import time
import json
import socket
import logging
import threading
import tempfile
from types import SimpleNamespace
from pathlib import Path
from typing import List, Dict, Any, Optional

import websocket

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dotenv import load_dotenv
load_dotenv()

from src.storage import db
from src.storage.models import Candidate, Brand, Organization, DiscoveryObservation, utc_now_iso
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert

logger = logging.getLogger("background_service")
logging.basicConfig(level=logging.INFO)

MAX_WATCHLIST_LIMIT = 3
HEALTH_FILE = Path(ROOT_DIR) / "data" / "worker_health.json"
EVENTS_FILE = Path(ROOT_DIR) / "data" / "certstream_events.jsonl"
CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://api.certstream.dev/lite")
EVENT_LOG_LIMIT = 300

# Keep process resources across Streamlit's reload of this module.
_runtime = getattr(sys, "_cybersentinel_monitor_runtime", None)
if _runtime is None:
    _runtime = SimpleNamespace(thread=None, instance=None, stop_event=threading.Event(),
                               event_lock=threading.Lock(), start_lock=threading.Lock())
    sys._cybersentinel_monitor_runtime = _runtime
_stop_event = _runtime.stop_event
_event_log_lock = _runtime.event_lock
_monitor_start_lock = _runtime.start_lock


def _replace_with_retry(source, destination):
    """Windows readers may briefly prevent replacing an open file."""
    for attempt in range(4):
        try:
            source.replace(destination)
            return
        except PermissionError:
            if attempt == 3:
                raise
            time.sleep(.01 * (attempt + 1))



class BackgroundDomainMonitor:
    def __init__(self, certstream_url: str = CERTSTREAM_URL):
        self.url = certstream_url
        self.events_seen = 0
        self.matches_found = 0
        self.start_time = time.time()
        self.running = False
        self.ws = None
        self.recent_seen = set()
        self.last_health_update = 0.0
        self.last_event_at = 0.0
        self.connected_at = 0.0
        self.last_event_logged = 0.0

        os.makedirs("data", exist_ok=True)
        db.init_db()
        self.ensure_default_targets()

    def ensure_default_targets(self):
        """Ensures up to 3 default monitored brands exist if table is empty."""
        session = db.SessionLocal()
        try:
            count = session.query(Brand).count()
            if count == 0:
                organization = session.query(Organization).filter_by(slug="local-workspace").first()
                if organization is None:
                    organization = Organization(name="Local Workspace", slug="local-workspace")
                    session.add(organization)
                    session.flush()
                defaults = [
                    {"name": "PayPal", "domain": "paypal.com", "keywords": ["paypal", "paypa1", "pay-pal"]},
                    {"name": "Netflix", "domain": "netflix.com", "keywords": ["netflix", "netf1ix", "net-flix"]},
                    {"name": "Google", "domain": "google.com", "keywords": ["google", "goog1e", "goog-le"]},
                ]
                for d in defaults[:MAX_WATCHLIST_LIMIT]:
                    b = Brand(
                        organization_id=organization.id,
                        name=d["name"],
                        official_domain=d["domain"],
                        official_website_url=f"https://{d['domain']}",
                        keywords=json.dumps(d["keywords"]),
                        alert_threshold=70,
                    )
                    session.add(b)
                session.commit()
        except Exception as e:
            logger.warning(f"Error ensuring default targets: {e}")
        finally:
            session.close()

    def get_active_targets(self) -> List[Dict[str, Any]]:
        """Returns at most 3 active monitored brands."""
        session = db.SessionLocal()
        try:
            brands = session.query(Brand).filter(Brand.monitoring_enabled.is_(True)).order_by(Brand.id).limit(MAX_WATCHLIST_LIMIT).all()
            targets = []
            for b in brands:
                kw = json.loads(b.keywords) if b.keywords else []
                base = b.official_domain.split(".")[0]
                if base not in kw:
                    kw.append(base)
                targets.append({
                    "id": b.id,
                    "organization_id": b.organization_id,
                    "name": b.name,
                    "domain": b.official_domain.lower(),
                    "keywords": [k.lower() for k in kw],
                })
            return targets[:MAX_WATCHLIST_LIMIT]
        finally:
            session.close()

    def check_domain_impersonation(self, domain: str, targets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Checks if domain impersonates any of the 3 active targets."""
        clean = domain.lower().strip().lstrip("*.")
        if not clean or "." not in clean:
            return None

        for t in targets:
            off_domain = t["domain"]
            # Exclude legitimate subdomains of the brand
            if clean == off_domain or clean.endswith(f".{off_domain}"):
                continue

            for kw in t["keywords"]:
                if kw in clean:
                    return {
                        "brand_id": t["id"],
                        "organization_id": t.get("organization_id"),
                        "brand_name": t["name"],
                        "official_domain": off_domain,
                        "matched_keyword": kw,
                    }
        return None

    def log_event(self, event_data: Dict[str, Any]):
        """Appends event data to data/certstream_events.jsonl."""
        with _event_log_lock:
            temporary_path = None
            try:
                EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
                with EVENTS_FILE.open("a", encoding="utf-8") as event_file:
                    event_file.write(json.dumps(event_data, ensure_ascii=False) + "\n")
                lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
                if len(lines) > EVENT_LOG_LIMIT:
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                            dir=EVENTS_FILE.parent, suffix=".tmp", delete=False) as handle:
                        handle.write("\n".join(lines[-EVENT_LOG_LIMIT:]) + "\n")
                        temporary_path = Path(handle.name)
                    _replace_with_retry(temporary_path, EVENTS_FILE)
            except OSError as exc:
                logger.warning("Could not update certificate display log: %s", exc)
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)

    def update_health(self, state: str = "connected", msg: str = ""):
        """Writes health heartbeat to data/worker_health.json."""
        targets = self.get_active_targets()
        last_event = getattr(self, 'last_event_at', 0)
        if state == 'connected' and not last_event:
            state = 'waiting'
        elif state == 'connected' and time.time() - last_event > 60:
            state = 'stalled'
        data = {
            "state": state,
            "updated_at": time.time(),
            "uptime_seconds": int(time.time() - self.start_time),
            "events_seen": self.events_seen,
            "matches_found": self.matches_found,
            "last_event_at": last_event,
            "connected_at": getattr(self, 'connected_at', 0),
            "active_targets": [t["domain"] for t in targets],
            "max_targets": MAX_WATCHLIST_LIMIT,
            "certstream_url": self.url,
            "source": "LIVE_CERTSTREAM",
            "message": msg or f"CertStream {state}; watching {len(targets)} websites.",
        }
        HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        # A unique temporary file prevents competing worker writes sharing one .tmp.
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=HEALTH_FILE.parent, suffix='.tmp', delete=False) as handle:
            handle.write(json.dumps(data, indent=2))
            temporary_path = Path(handle.name)
        try:
            _replace_with_retry(temporary_path, HEALTH_FILE)
        except OSError as exc:
            logger.warning('Could not update monitor heartbeat: %s', exc)
        finally:
            temporary_path.unlink(missing_ok=True)
        self.last_health_update = time.monotonic()

    def handle_message(self, message: str) -> None:
        """Parse and process one genuine CertStream certificate update."""
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            logger.warning("Ignoring malformed CertStream message.")
            return

        if not isinstance(payload, dict) or payload.get("message_type") != "certificate_update":
            return

        data = payload.get("data")
        leaf_cert = data.get("leaf_cert") if isinstance(data, dict) else None
        if not isinstance(leaf_cert, dict):
            logger.warning("Ignoring CertStream update without a leaf certificate.")
            return

        raw_domains = leaf_cert.get("all_domains", [])
        domains = [
            domain.strip().lower().lstrip("*.")
            for domain in raw_domains
            if isinstance(domain, str) and domain.strip()
        ] if isinstance(raw_domains, list) else []
        issuer_data = leaf_cert.get("issuer") or {}
        if isinstance(issuer_data, dict):
            issuer = (
                issuer_data.get("O")
                or issuer_data.get("organizationName")
                or issuer_data.get("CN")
                or "Not provided"
            )
        else:
            issuer = str(issuer_data)
        issuer = str(issuer)[:200]

        # Refresh watchlist changes without opening a database session per certificate.
        if time.monotonic() - getattr(self, '_targets_cached_at', 0) > 5:
            self._targets_cache = self.get_active_targets()
            self._targets_cached_at = time.monotonic()
        targets = self._targets_cache
        matches = []
        for domain in domains:
            match = self.check_domain_impersonation(domain, targets)
            if match:
                matches.append((domain, match))

        self.events_seen += 1
        self.last_event_at = time.time()
        observed_at = utc_now_iso()
        matched_domains = [domain for domain, _ in matches]
        matched_brands = sorted({match["official_domain"] for _, match in matches})
        primary_domain = domains[0] if domains else "Unknown"
        event = {
            "source": "LIVE_CERTSTREAM",
            "stream_mode": "live",
            "event_type": "certificate_update",
            "domain": primary_domain,
            "domains": domains[:10],
            "domain_count": len(domains),
            "issuer": issuer,
            "matched_domain": matched_domains[0] if matched_domains else None,
            "matched_domains": matched_domains[:10],
            "matched_brand": matched_brands[0] if len(matched_brands) == 1 else None,
            "matched_brands": matched_brands,
            "brand_match": bool(matched_domains),
            "risk_level": "UNASSESSED" if matched_domains else "INFO",
            "observed_at": observed_at,
        }
        # Count every certificate; sample the display log to keep disk IO bounded.
        if matches or time.monotonic() - getattr(self, 'last_event_logged', 0) >= .5:
            self.log_event(event)
            self.last_event_logged = time.monotonic()

        for domain, match in matches:
            self.process_matched_domain(domain, match, issuer)

        if time.monotonic() - self.last_health_update >= 5:
            self.update_health("connected")

    def process_matched_domain(self, domain: str, match: Dict[str, Any], issuer: str = ""):
        """Handles a detected lookalike domain."""
        seen_key = (domain, match["brand_id"], match.get("organization_id"))
        if seen_key in self.recent_seen:
            return
        self.recent_seen.add(seen_key)
        if len(self.recent_seen) > 5000:
            self.recent_seen.clear()

        self.matches_found += 1
        off_domain = match["official_domain"]
        logger.info(f"🚨 [MATCH] {domain} matches watched website {off_domain}")

        # Quick DNS check
        is_live = False
        ip = None
        try:
            ip = socket.gethostbyname(domain)
            is_live = True
        except Exception:
            pass

        # Calculate Risk Score
        score, breakdown = compute_risk_score(
            is_live=is_live,
            visual_similarity=None,
            has_login_form=False,
            suspicious_phrase_count=0,
        )
        score = min(100.0, score + 20.0)  # Newly issued TLS certificate bonus
        breakdown["certstream_tls_issuance"] = 20.0
        level = risk_level(score)

        now = utc_now_iso()

        # Save to SQLite
        session = db.SessionLocal()
        try:
            cand = session.query(Candidate).filter_by(domain=domain, matched_brand=off_domain, organization_id=match.get("organization_id")).first()
            if not cand:
                cand = Candidate(
                    domain=domain,
                    matched_brand=off_domain,
                    brand_id=match["brand_id"],
                    organization_id=match.get("organization_id"),
                    detected_at=now,
                    first_seen_at=now,
                    last_seen_at=now,
                    discovered_at=now,
                    imported_at=now,
                    event_category="certstream_live",
                )
                session.add(cand)

            cand.last_seen_at = now
            cand.seen_count = (cand.seen_count or 0) + 1
            cand.status = cand.status or "new"
            # A certificate event provides no visual or page-content evidence.
            # Preserve completed investigations and analyst review decisions.
            if cand.evidence_status in (None, "pending", "live_stream"):
                cand.is_live = 1 if is_live else 0
                cand.risk_score = score
                cand.risk_level = level
                cand.evidence_status = "live_stream"
                cand.confidence_level = "LOW"
                cand.recommended_action = f"Review new TLS certificate for {domain} (Issuer: {issuer[:30]}). Page evidence has not been collected."
                cand.risk_breakdown = json.dumps(breakdown)

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
                    "matched_keyword": match["matched_keyword"],
                }),
            )
            session.add(obs)
            session.commit()

            # Trigger Telegram alert if HIGH risk
            if level == "HIGH":
                send_alert(
                    domain=domain,
                    risk_score=score,
                    risk_level=level,
                    matched_brand=off_domain,
                    source="LIVE_CERTSTREAM",
                    risk_reason=f"New TLS certificate issued by {issuer[:30]} for lookalike: {domain}",
                )

            # Record event in live stream telemetry
            self.log_event({
                "source": "LIVE_CERTSTREAM",
                "stream_mode": "live",
                "event_type": "certificate_match",
                "domain": domain,
                "matched_brand": off_domain,
                "issuer": issuer,
                "risk_level": level,
                "risk_score": score,
                "observed_at": now,
            })
        except Exception as exc:
            logger.error(f"Error persisting match {domain}: {exc}")
        finally:
            session.close()

    def run_loop(self):
        """Connect to the real CertStream feed and reconnect on disconnect."""
        logger.info("Connecting to CertStream at %s", self.url)
        self.running = True
        retry_delay = 1

        def watch_feed_health():
            while self.running and not _stop_event.wait(5):
                try:
                    ws = self.ws
                    if not ws or not ws.sock or not ws.sock.connected:
                        continue
                    last_data = self.last_event_at or self.connected_at
                    if last_data and time.time() - last_data > 60:
                        self.update_health('stalled', 'No certificates received for 60 seconds; reconnecting.')
                        ws.close()
                    else:
                        self.update_health('connected')
                except Exception:
                    logger.exception('Could not refresh live-feed health')

        threading.Thread(target=watch_feed_health, name='PhishShieldFeedHealth', daemon=True).start()

        while self.running and not _stop_event.is_set():
            self.update_health("connecting", "Connecting to the live CertStream feed.")

            def on_open(ws):
                logger.info("Connected to CertStream.")
                retry_delay_state["delay"] = 1
                self.connected_at = time.time()
                self.last_event_at = 0
                self.update_health("connected")

            def on_message(_ws, message):
                self.handle_message(message)

            def on_error(_ws, error):
                logger.warning("CertStream connection error: %s", error)
                self.update_health(
                    "reconnecting",
                    f"CertStream connection error: {str(error)[:240]}",
                )

            def on_close(_ws, close_status_code, close_msg):
                logger.info(
                    "CertStream connection closed (code=%s, message=%s).",
                    close_status_code,
                    close_msg,
                )
                if self.running and not _stop_event.is_set():
                    self.update_health(
                        "reconnecting",
                        f"Reconnecting to CertStream (close code: {close_status_code or 'unknown'}).",
                    )

            def on_pong(_ws, _payload):
                last_data = self.last_event_at or self.connected_at
                if last_data and time.time() - last_data > 60:
                    self.update_health('stalled', 'No certificates received for 60 seconds; reconnecting.')
                    _ws.close()
                    return
                if time.monotonic() - self.last_health_update >= 5:
                    self.update_health("connected")

            retry_delay_state = {"delay": retry_delay}
            self.ws = websocket.WebSocketApp(
                self.url,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
                on_pong=on_pong,
            )
            try:
                # Application-level data freshness is monitored above. A busy public
                # feed can delay pong frames even while valid certificates arrive.
                self.ws.run_forever(ping_interval=0)
            except Exception:
                logger.exception("CertStream WebSocket loop failed.")

            if not self.running or _stop_event.is_set():
                break

            retry_delay = retry_delay_state["delay"]
            self.update_health(
                "reconnecting",
                f"CertStream unavailable; retrying in {retry_delay} seconds.",
            )
            _stop_event.wait(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

        self.running = False
        self.ws = None
        self.update_health("stopped", "CertStream monitor stopped.")


def start_background_monitor():
    """Starts the background monitoring engine as a persistent daemon thread."""

    with _monitor_start_lock:
        if _runtime.thread and _runtime.thread.is_alive():
            return True, "Monitor is already running."

        _stop_event.clear()
        _runtime.instance = BackgroundDomainMonitor()
        _runtime.thread = threading.Thread(
            target=_runtime.instance.run_loop,
            name="PhishShieldBackgroundMonitor",
            daemon=True,
        )
        _runtime.thread.start()
        return True, "Background monitor started successfully."


def stop_background_monitor():
    """Stops the background monitoring thread."""
    _stop_event.set()
    if _runtime.instance:
        _runtime.instance.running = False
        if _runtime.instance.ws:
            _runtime.instance.ws.close()
    if _runtime.thread and _runtime.thread is not threading.current_thread():
        _runtime.thread.join(timeout=5)
    return True, "Background monitor signal sent to stop."


def get_monitor_status() -> Dict[str, Any]:
    """Retrieves current health and telemetry from the background monitor."""
    if HEALTH_FILE.exists():
        try:
            health = json.loads(HEALTH_FILE.read_text(encoding="utf-8"))
            now = time.time()
            if now - float(health.get('updated_at', 0)) > 90:
                health['state'] = 'stale'
                health['message'] = 'The monitor heartbeat is out of date. Reconnect the feed.'
            elif health.get('state') == 'connected':
                last_event = float(health.get('last_event_at', 0))
                if not last_event:
                    health['state'] = 'waiting'
                elif now - last_event > 60:
                    health['state'] = 'stalled'
            return health
        except Exception:
            pass
    return {
        "state": "unknown",
        "updated_at": 0,
        "uptime_seconds": 0,
        "events_seen": 0,
        "matches_found": 0,
        "active_targets": ["paypal.com", "netflix.com", "google.com"],
        "max_targets": MAX_WATCHLIST_LIMIT,
        "message": "Initializing background monitor...",
    }


if __name__ == "__main__":
    print("Starting background domain monitor...")
    start_background_monitor()
    try:
        while True:
            time.sleep(2)
            print("Status:", get_monitor_status())
    except KeyboardInterrupt:
        stop_background_monitor()
        print("Stopped.")
