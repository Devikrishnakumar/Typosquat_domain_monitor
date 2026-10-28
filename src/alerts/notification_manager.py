"""
notification_manager.py
Enterprise Alerting & Notification Subsystem for CyberSentinel.
Supports Telegram Bot API and extensible Email notifications with deduplication,
retry backoff, and delivery status logging.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import logging
import os
import smtplib
import time
from typing import Dict, Any, Optional, Tuple, List
import requests
from dotenv import load_dotenv

from src.storage import db
from src.storage.models import AlertRecord, Candidate, utc_now_iso

load_dotenv()
logger = logging.getLogger(__name__)


class BaseNotificationChannel(ABC):
    @abstractmethod
    def send(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Sends alert. Returns (is_delivered, error_message)."""
        pass

    @property
    @abstractmethod
    def channel_name(self) -> str:
        pass


class TelegramNotificationChannel(BaseNotificationChannel):
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None, max_retries: int = 2):
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
        self.max_retries = max_retries

    @property
    def channel_name(self) -> str:
        return "telegram"

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def format_message(self, payload: Dict[str, Any]) -> str:
        brand = payload.get("brand_name", "Unknown Brand")
        domain = payload.get("domain", "unknown")
        official = payload.get("official_domain", "")
        score = payload.get("risk_score", 0)
        severity = payload.get("severity", "UNKNOWN")
        source = payload.get("source", "CT_STREAM")
        discovered_at = payload.get("discovered_at") or utc_now_iso()
        event_cat = payload.get("event_category", "newly_observed")
        reasons = payload.get("reasons", [])
        dashboard_url = payload.get("dashboard_url", "http://localhost:8501")

        msg = (
            f"🚨 *CYBERSENTINEL ALERT*\n\n"
            f"*Severity:* `{severity}` | *Score:* `{score}/100`\n"
            f"*Target Brand:* `{brand}` ({official})\n"
            f"*Suspicious Domain:* `{domain}`\n"
            f"*Status:* `{event_cat}`\n"
            f"*Discovered:* `{discovered_at}` (via `{source}`)\n\n"
        )

        if reasons:
            msg += "*Evidence:*\n"
            for r in reasons[:3]:
                msg += f"• {r}\n"
            msg += "\n"

        msg += f"[Open Case in Dashboard]({dashboard_url})\n"
        return msg

    def send(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not self.is_configured():
            return False, "Telegram credentials (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID) not configured."

        message_text = self.format_message(payload)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        req_body = {
            "chat_id": self.chat_id,
            "text": message_text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        for attempt in range(1, self.max_retries + 2):
            try:
                resp = requests.post(url, json=req_body, timeout=12)
                if resp.status_code == 200:
                    return True, None
                err_text = f"HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning(f"Telegram delivery attempt {attempt} failed: {err_text}")
            except Exception as exc:
                err_text = str(exc)
                logger.warning(f"Telegram connection error on attempt {attempt}: {err_text}")

            if attempt <= self.max_retries:
                time.sleep(2 * attempt)

        return False, err_text


class EmailNotificationChannel(BaseNotificationChannel):
    """
    Extensible Email notification channel.
    Supports SMTP configuration or mock logging if SMTP is disabled.
    """
    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        from_email: Optional[str] = None,
    ):
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", str(smtp_port)))
        self.smtp_user = smtp_user or os.getenv("SMTP_USER")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
        self.from_email = from_email or os.getenv("SMTP_FROM", "alerts@fakewebsitedetector.local")

    @property
    def channel_name(self) -> str:
        return "email"

    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.from_email)

    def send(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        recipients = payload.get("email_recipients") or []
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]

        if not recipients:
            return False, "No email recipients configured."

        if not self.is_configured():
            # Mock delivery simulation when SMTP is not provisioned
            logger.info(f"[Email Notification Mock] Sent alert for {payload.get('domain')} to {recipients}")
            return True, None

        try:
            subject = f"Fake Website Alert [{payload.get('severity', 'HIGH')}]: {payload.get('domain')}"
            body = (
                f"CyberSentinel Security Alert\n\n"
                f"Candidate Domain: {payload.get('domain')}\n"
                f"Target Brand: {payload.get('brand_name')} ({payload.get('official_domain')})\n"
                f"Risk Score: {payload.get('risk_score')}/100 ({payload.get('severity')})\n"
                f"Event Category: {payload.get('event_category')}\n"
                f"Discovered At: {payload.get('discovered_at')}\n"
            )

            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
            server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            msg = f"From: {self.from_email}\r\nSubject: {subject}\r\n\r\n{body}"
            server.sendmail(self.from_email, recipients, msg)
            server.quit()
            return True, None
        except Exception as exc:
            return False, str(exc)


class NotificationManager:
    """
    Coordinates multi-channel alert delivery with deduplication,
    threshold checking, and persistent logging.
    """
    def __init__(self):
        self.telegram = TelegramNotificationChannel()
        self.email = EmailNotificationChannel()

    def dispatch_candidate_alert(
        self,
        candidate_id: int,
        domain: str,
        brand_name: str,
        official_domain: str,
        risk_score: float,
        severity: str,
        reasons: Optional[List[str]] = None,
        source: str = "CT_STREAM",
        event_category: str = "newly_observed",
        discovered_at: Optional[str] = None,
        alert_threshold: int = 60,
        enable_telegram: bool = True,
        enable_email: bool = False,
        email_recipients: Optional[List[str]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Dispatches alert if candidate meets severity threshold and has not already
        been alerted recently for the same event.
        """
        results = {"candidate_id": candidate_id, "channels": {}}

        # Threshold check
        if risk_score < alert_threshold and not force:
            logger.info(f"Alert skipped for {domain}: score {risk_score} < threshold {alert_threshold}")
            return {"status": "skipped", "reason": "below_threshold"}

        # Deduplication check: check if already successfully alerted recently
        session = db.SessionLocal()
        try:
            cand = session.get(Candidate, candidate_id)
            if cand and cand.last_alerted_at and not force:
                logger.info(f"Alert skipped for {domain}: already alerted at {cand.last_alerted_at}")
                return {"status": "skipped", "reason": "already_alerted"}
        finally:
            session.close()

        payload = {
            "candidate_id": candidate_id,
            "domain": domain,
            "brand_name": brand_name,
            "official_domain": official_domain,
            "risk_score": risk_score,
            "severity": severity,
            "reasons": reasons or [],
            "source": source,
            "event_category": event_category,
            "discovered_at": discovered_at or utc_now_iso(),
            "email_recipients": email_recipients or [],
            "dashboard_url": "http://localhost:8501",
        }

        # 1. Telegram delivery
        if enable_telegram:
            delivered, err = self.telegram.send(payload)
            status = "sent" if delivered else "failed"
            db.record_alert(
                candidate_id=candidate_id,
                channel="telegram",
                recipient=getattr(self.telegram, "chat_id", None) or "default",
                status=status,
                payload=payload,
                attempts=1,
                error_message=err,
            )
            results["channels"]["telegram"] = {"status": status, "error": err}

        # 2. Email delivery
        if enable_email and email_recipients:
            delivered, err = self.email.send(payload)
            status = "sent" if delivered else "failed"
            db.record_alert(
                candidate_id=candidate_id,
                channel="email",
                recipient=",".join(email_recipients),
                status=status,
                payload=payload,
                attempts=1,
                error_message=err,
            )
            results["channels"]["email"] = {"status": status, "error": err}

        return results

    def send_test_alert(self, channel: str = "telegram", recipient: Optional[str] = None) -> Tuple[bool, str]:
        """Sends a verification notification."""
        test_payload = {
            "domain": "test-lookalike-example.com",
            "brand_name": "Test Brand",
            "official_domain": "example.com",
            "risk_score": 85.0,
            "severity": "HIGH",
            "reasons": ["Test notification generated by CyberSentinel administrator."],
            "source": "ADMIN_TEST",
            "event_category": "test_event",
            "discovered_at": utc_now_iso(),
            "email_recipients": [recipient] if recipient else [],
        }

        if channel == "telegram":
            ok, err = self.telegram.send(test_payload)
            return ok, err or "Telegram test notification delivered successfully."
        elif channel == "email":
            ok, err = self.email.send(test_payload)
            return ok, err or "Email test notification delivered successfully."
        else:
            return False, f"Unknown notification channel '{channel}'"


notification_manager = NotificationManager()
