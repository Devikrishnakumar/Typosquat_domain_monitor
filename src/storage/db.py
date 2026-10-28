"""
db.py
Enterprise Storage Engine for CyberSentinel.
PostgreSQL storage via SQLAlchemy, with SQLite support for isolated tests.
Preserves backwards compatibility with initial Candidate APIs while exposing
enterprise models and query helpers.
"""

import os
import json
import socket
from datetime import datetime, timezone
from sqlalchemy import create_engine, inspect, text, desc
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from src.storage.models import (
    Base, Organization, User, Brand, ApprovedDomain, Candidate,
    DiscoveryObservation, DomainInvestigation, DnsObservation,
    CertificateObservation, RiskAssessment, AlertRecord,
    MonitoringJob, AuditLog, utc_now_iso
)


def _is_pg_available(host="localhost", port=5432, timeout=0.3):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


from dotenv import load_dotenv
load_dotenv()

os.makedirs("data", exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/phishing_detector.db")

def _make_engine(database_url):
    options = {"pool_pre_ping": True}
    if str(database_url).startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if make_url(database_url).database in (None, "", ":memory:"):
            options["poolclass"] = StaticPool
    return create_engine(database_url, **options)


engine = _make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def configure_database(database_url):
    """Reconfigure the engine, primarily for isolated tests and local tooling."""
    global DATABASE_URL, engine, SessionLocal
    engine.dispose()
    DATABASE_URL = database_url
    engine = _make_engine(database_url)
    SessionLocal = sessionmaker(bind=engine)


def init_db():
    global DATABASE_URL, engine, SessionLocal
    # Test connection; if local PostgreSQL is unreachable on localhost, fallback to SQLite
    try:
        with engine.connect() as conn:
            pass
    except Exception:
        db_str = str(DATABASE_URL)
        if "localhost" in db_str or "127.0.0.1" in db_str:
            os.makedirs("data", exist_ok=True)
            sqlite_url = "sqlite:///data/local_typosquat.db"
            print(f"[*] Local PostgreSQL unreachable on localhost. Using local SQLite at {sqlite_url}")
            configure_database(sqlite_url)

    Base.metadata.create_all(engine)
    _migrate_candidate_columns()


def _migrate_candidate_columns():
    """Ensure candidate table has all enterprise columns even across legacy schemas."""
    try:
        inspector = inspect(engine)
        if "candidates" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("candidates")}
    except Exception:
        return

    additions = {
        "analyst_notes": "TEXT NOT NULL DEFAULT ''",
        "evidence_status": "VARCHAR NOT NULL DEFAULT 'pending'",
        "risk_breakdown": "TEXT",
        "suspicious_phrase_count": "INTEGER NOT NULL DEFAULT 0",
        "last_seen_at": "VARCHAR",
        "seen_count": "INTEGER NOT NULL DEFAULT 1",
        "organization_id": "INTEGER",
        "brand_id": "INTEGER",
        "registered_domain": "VARCHAR",
        "tld": "VARCHAR",
        "event_category": "VARCHAR NOT NULL DEFAULT 'newly_observed'",
        "confidence_level": "VARCHAR DEFAULT 'MEDIUM'",
        "recommended_action": "TEXT",
        "first_seen_at": "VARCHAR",
        "discovered_at": "VARCHAR",
        "imported_at": "VARCHAR",
        "certificate_issued_at": "VARCHAR",
        "registered_at": "VARCHAR",
        "last_investigated_at": "VARCHAR",
        "last_alerted_at": "VARCHAR",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                try:
                    connection.exec_driver_sql(
                        f"ALTER TABLE candidates ADD COLUMN {name} {definition}"
                    )
                except Exception:
                    pass


# ---------------------------------------------------------
# Candidate Core API (Backwards-Compatible)
# ---------------------------------------------------------

def insert_candidate(
    domain,
    matched_brand,
    decoded_domain=None,
    organization_id=None,
    brand_id=None,
    event_category="newly_observed",
    source="ct_stream",
    observed_at=None,
    imported_at=None,
):
    session = SessionLocal()
    try:
        candidate = (
            session.query(Candidate)
            .filter_by(domain=domain, matched_brand=matched_brand, organization_id=organization_id)
            .order_by(Candidate.id.desc())
            .first()
        )
        now = utc_now_iso()
        obs_date = observed_at or now
        imp_date = imported_at or now

        if candidate:
            candidate.last_seen_at = now
            candidate.seen_count = (candidate.seen_count or 1) + 1
            if candidate.event_category != "historical":
                candidate.event_category = "previously_known"
            if organization_id and not candidate.organization_id:
                candidate.organization_id = organization_id
            if brand_id and not candidate.brand_id:
                candidate.brand_id = brand_id
            session.commit()
            cid = candidate.id
        else:
            candidate = Candidate(
                domain=domain,
                decoded_domain=decoded_domain,
                matched_brand=matched_brand,
                detected_at=now,
                first_seen_at=now,
                last_seen_at=now,
                discovered_at=obs_date,
                imported_at=imp_date,
                organization_id=organization_id,
                brand_id=brand_id,
                event_category=event_category,
            )
            session.add(candidate)
            session.commit()
            session.refresh(candidate)
            cid = candidate.id

        # Also register discovery observation
        obs = DiscoveryObservation(
            candidate_id=cid,
            source=source,
            observed_at=obs_date,
            imported_at=imp_date,
            raw_data=json.dumps({"domain": domain, "matched_brand": matched_brand}),
        )
        session.add(obs)
        session.commit()
        return cid
    finally:
        session.close()


def update_liveness(candidate_id, is_live):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate:
            candidate.is_live = 1 if is_live else 0
            session.commit()
    finally:
        session.close()


def update_screenshot_path(candidate_id, path):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate:
            candidate.screenshot_path = path
            session.commit()
    finally:
        session.close()


def update_visual_similarity(candidate_id, score):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate:
            candidate.visual_similarity = float(score) if score is not None else None
            session.commit()
    finally:
        session.close()


def update_content_signals(candidate_id, has_login_form):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate:
            candidate.has_login_form = 1 if has_login_form else 0
            session.commit()
    finally:
        session.close()


def update_risk_score(candidate_id, score, level, confidence="MEDIUM", reasons=None, recommended_action=None):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate:
            candidate.risk_score = float(score) if score is not None else None
            candidate.risk_level = level
            candidate.confidence_level = confidence
            if recommended_action:
                candidate.recommended_action = recommended_action
            session.commit()

            # Record in RiskAssessment history
            ra = RiskAssessment(
                candidate_id=candidate_id,
                score=float(score) if score is not None else 0.0,
                level=level or "LOW",
                confidence=confidence or "MEDIUM",
                breakdown=candidate.risk_breakdown,
                reasons=json.dumps(reasons or []),
                recommended_action=recommended_action,
            )
            session.add(ra)
            session.commit()
    finally:
        session.close()


def update_evidence_details(
    candidate_id,
    evidence_status,
    suspicious_phrase_count=0,
    risk_breakdown=None,
):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate is None:
            raise ValueError(f"Candidate {candidate_id} does not exist")
        candidate.evidence_status = evidence_status
        candidate.suspicious_phrase_count = int(suspicious_phrase_count or 0)
        candidate.risk_breakdown = (
            json.dumps(risk_breakdown, sort_keys=True)
            if risk_breakdown is not None
            else None
        )
        candidate.last_investigated_at = utc_now_iso()
        session.commit()
    finally:
        session.close()


def update_candidate_review(candidate_id, status, analyst_notes):
    allowed_statuses = {
        "new",
        "under_investigation",
        "false_positive",
        "resolved",
        "takedown_requested",
    }
    if status not in allowed_statuses:
        raise ValueError(f"Unsupported candidate status: {status}")

    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        if candidate is None:
            raise ValueError(f"Candidate {candidate_id} does not exist")
        candidate.status = status
        candidate.analyst_notes = str(analyst_notes or "").strip()[:10000]
        session.commit()
    finally:
        session.close()


def get_all_candidates(org_id=None, brand_id=None, min_risk=None, severity=None, status=None, search=None):
    session = SessionLocal()
    try:
        query = session.query(Candidate)
        if org_id is not None:
            query = query.filter(Candidate.organization_id == org_id)
        if brand_id is not None:
            query = query.filter(Candidate.brand_id == brand_id)
        if min_risk is not None:
            query = query.filter(Candidate.risk_score >= min_risk)
        if severity:
            query = query.filter(Candidate.risk_level == severity.upper())
        if status:
            query = query.filter(Candidate.status == status)
        if search:
            query = query.filter(
                (Candidate.domain.ilike(f"%{search}%")) |
                (Candidate.matched_brand.ilike(f"%{search}%"))
            )

        candidates = query.order_by(Candidate.risk_score.desc().nullslast(), Candidate.detected_at.desc()).all()
        return [
            {
                "id": c.id,
                "domain": c.domain,
                "decoded_domain": c.decoded_domain,
                "matched_brand": c.matched_brand,
                "detected_at": c.detected_at,
                "is_live": c.is_live,
                "visual_similarity": c.visual_similarity,
                "has_login_form": c.has_login_form,
                "risk_score": c.risk_score,
                "risk_level": c.risk_level,
                "screenshot_path": c.screenshot_path,
                "status": c.status,
                "analyst_notes": c.analyst_notes or "",
                "evidence_status": c.evidence_status,
                "risk_breakdown": c.risk_breakdown,
                "suspicious_phrase_count": c.suspicious_phrase_count or 0,
                "last_seen_at": c.last_seen_at,
                "seen_count": c.seen_count or 1,
                "organization_id": c.organization_id,
                "brand_id": c.brand_id,
                "event_category": c.event_category,
                "confidence_level": c.confidence_level,
                "recommended_action": c.recommended_action,
                "first_seen_at": c.first_seen_at,
                "discovered_at": c.discovered_at,
                "imported_at": c.imported_at,
                "last_investigated_at": c.last_investigated_at,
                "last_alerted_at": c.last_alerted_at,
            }
            for c in candidates
        ]
    finally:
        session.close()


def get_candidate(candidate_id):
    session = SessionLocal()
    try:
        c = session.get(Candidate, candidate_id)
        if not c:
            return None
        return {
            "id": c.id,
            "domain": c.domain,
            "decoded_domain": c.decoded_domain,
            "matched_brand": c.matched_brand,
            "detected_at": c.detected_at,
            "is_live": c.is_live,
            "visual_similarity": c.visual_similarity,
            "has_login_form": c.has_login_form,
            "risk_score": c.risk_score,
            "risk_level": c.risk_level,
            "screenshot_path": c.screenshot_path,
            "status": c.status,
            "analyst_notes": c.analyst_notes or "",
            "evidence_status": c.evidence_status,
            "risk_breakdown": c.risk_breakdown,
            "suspicious_phrase_count": c.suspicious_phrase_count or 0,
            "last_seen_at": c.last_seen_at,
            "seen_count": c.seen_count or 1,
            "organization_id": c.organization_id,
            "brand_id": c.brand_id,
            "event_category": c.event_category,
            "confidence_level": c.confidence_level,
            "recommended_action": c.recommended_action,
            "first_seen_at": c.first_seen_at,
            "discovered_at": c.discovered_at,
            "imported_at": c.imported_at,
            "last_investigated_at": c.last_investigated_at,
            "last_alerted_at": c.last_alerted_at,
        }
    finally:
        session.close()


# ---------------------------------------------------------
# Enterprise Organizations & Users CRUD
# ---------------------------------------------------------

def create_organization(name, slug=None):
    session = SessionLocal()
    try:
        slug = slug or name.lower().replace(" ", "-").replace(".", "-")[:50]
        existing = session.query(Organization).filter_by(slug=slug).first()
        if existing:
            return existing.id
        org = Organization(name=name, slug=slug)
        session.add(org)
        session.commit()
        session.refresh(org)
        return org.id
    finally:
        session.close()


def get_organization_by_slug(slug):
    session = SessionLocal()
    try:
        org = session.query(Organization).filter_by(slug=slug).first()
        if not org:
            return None
        return {"id": org.id, "name": org.name, "slug": org.slug, "created_at": org.created_at}
    finally:
        session.close()


def create_user(organization_id, email, hashed_password, full_name=None, role="analyst"):
    session = SessionLocal()
    try:
        existing = session.query(User).filter_by(email=email).first()
        if existing:
            raise ValueError(f"User with email {email} already exists")
        user = User(
            organization_id=organization_id,
            email=email,
            hashed_password=hashed_password,
            full_name=full_name,
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id
    finally:
        session.close()


def get_user_by_email(email):
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return None
        return {
            "id": user.id,
            "organization_id": user.organization_id,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
        }
    finally:
        session.close()


# ---------------------------------------------------------
# Enterprise Brands & Scope CRUD
# ---------------------------------------------------------

def create_or_update_brand(
    organization_id,
    name,
    official_domain,
    official_website_url=None,
    keywords=None,
    monitoring_enabled=True,
    check_interval_minutes=5,
    alert_threshold=70,
    telegram_alerts_enabled=True,
    email_alerts_enabled=False,
    email_recipients=None,
):
    session = SessionLocal()
    try:
        brand = (
            session.query(Brand)
            .filter_by(organization_id=organization_id, official_domain=official_domain)
            .first()
        )
        kw_json = json.dumps(keywords or [])
        recipients_json = json.dumps(email_recipients or [])

        if brand:
            brand.name = name
            brand.official_website_url = official_website_url
            brand.keywords = kw_json
            brand.monitoring_enabled = monitoring_enabled
            brand.check_interval_minutes = check_interval_minutes
            brand.alert_threshold = alert_threshold
            brand.telegram_alerts_enabled = telegram_alerts_enabled
            brand.email_alerts_enabled = email_alerts_enabled
            brand.email_recipients = recipients_json
            brand.updated_at = utc_now_iso()
            session.commit()
            return brand.id

        brand = Brand(
            organization_id=organization_id,
            name=name,
            official_domain=official_domain,
            official_website_url=official_website_url,
            keywords=kw_json,
            monitoring_enabled=monitoring_enabled,
            check_interval_minutes=check_interval_minutes,
            alert_threshold=alert_threshold,
            telegram_alerts_enabled=telegram_alerts_enabled,
            email_alerts_enabled=email_alerts_enabled,
            email_recipients=recipients_json,
        )
        session.add(brand)
        session.commit()
        session.refresh(brand)
        return brand.id
    finally:
        session.close()


def get_brands(organization_id=None):
    session = SessionLocal()
    try:
        query = session.query(Brand)
        if organization_id is not None:
            query = query.filter_by(organization_id=organization_id)
        brands = query.all()
        result = []
        for b in brands:
            result.append({
                "id": b.id,
                "organization_id": b.organization_id,
                "name": b.name,
                "official_domain": b.official_domain,
                "official_website_url": b.official_website_url,
                "keywords": json.loads(b.keywords or "[]"),
                "monitoring_enabled": b.monitoring_enabled,
                "check_interval_minutes": b.check_interval_minutes,
                "alert_threshold": b.alert_threshold,
                "telegram_alerts_enabled": b.telegram_alerts_enabled,
                "email_alerts_enabled": b.email_alerts_enabled,
                "email_recipients": json.loads(b.email_recipients or "[]"),
                "created_at": b.created_at,
                "updated_at": b.updated_at,
            })
        return result
    finally:
        session.close()


def add_approved_domain(brand_id, domain, notes=""):
    session = SessionLocal()
    try:
        existing = session.query(ApprovedDomain).filter_by(brand_id=brand_id, domain=domain).first()
        if existing:
            return existing.id
        appr = ApprovedDomain(brand_id=brand_id, domain=domain, notes=notes)
        session.add(appr)
        session.commit()
        session.refresh(appr)
        return appr.id
    finally:
        session.close()


def get_approved_domains(brand_id=None):
    session = SessionLocal()
    try:
        query = session.query(ApprovedDomain)
        if brand_id:
            query = query.filter_by(brand_id=brand_id)
        return [{"id": a.id, "brand_id": a.brand_id, "domain": a.domain, "notes": a.notes} for a in query.all()]
    finally:
        session.close()


# ---------------------------------------------------------
# Enterprise Investigations & Observations Logging
# ---------------------------------------------------------

def record_investigation(
    candidate_id,
    is_live,
    http_status=None,
    redirect_chain=None,
    final_hostname=None,
    https_available=False,
    page_title=None,
    has_credential_form=False,
    suspicious_keywords_found=None,
    whois_info=None,
    screenshot_path=None,
    visual_similarity=None,
    error_message=None,
):
    session = SessionLocal()
    try:
        whois = whois_info or {}
        inv = DomainInvestigation(
            candidate_id=candidate_id,
            is_live=bool(is_live),
            http_status=http_status,
            redirect_chain=json.dumps(redirect_chain or []),
            final_hostname=final_hostname,
            https_available=bool(https_available),
            page_title=page_title,
            has_credential_form=bool(has_credential_form),
            suspicious_keywords_found=json.dumps(suspicious_keywords_found or []),
            whois_registrar=whois.get("registrar"),
            whois_created_date=str(whois.get("creation_date") or ""),
            whois_expires_date=str(whois.get("expiration_date") or ""),
            whois_nameservers=json.dumps(whois.get("nameservers") or []),
            screenshot_path=screenshot_path,
            visual_similarity=visual_similarity,
            error_message=error_message,
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)
        return inv.id
    finally:
        session.close()


def record_dns_observation(candidate_id, investigation_id, record_type, records, status="OK"):
    session = SessionLocal()
    try:
        obs = DnsObservation(
            candidate_id=candidate_id,
            investigation_id=investigation_id,
            record_type=record_type,
            records=json.dumps(records if isinstance(records, list) else [records]),
            status=status,
        )
        session.add(obs)
        session.commit()
        return obs.id
    finally:
        session.close()


def record_certificate_observation(
    candidate_id,
    investigation_id,
    subject=None,
    issuer=None,
    valid_from=None,
    valid_to=None,
    san_list=None,
    serial_number=None,
    fingerprint_sha256=None,
    is_new=True,
):
    session = SessionLocal()
    try:
        obs = CertificateObservation(
            candidate_id=candidate_id,
            investigation_id=investigation_id,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            san_list=json.dumps(san_list or []),
            serial_number=serial_number,
            fingerprint_sha256=fingerprint_sha256,
            is_new=is_new,
        )
        session.add(obs)
        session.commit()
        return obs.id
    finally:
        session.close()


def record_alert(candidate_id, channel, recipient, status, payload, attempts=1, error_message=None):
    session = SessionLocal()
    try:
        record = AlertRecord(
            candidate_id=candidate_id,
            channel=channel,
            recipient=recipient,
            status=status,
            payload=json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload),
            attempts=attempts,
            error_message=error_message,
            delivered_at=utc_now_iso() if status == "sent" else None,
        )
        session.add(record)
        if status == "sent":
            c = session.get(Candidate, candidate_id)
            if c:
                c.last_alerted_at = utc_now_iso()
        session.commit()
        return record.id
    finally:
        session.close()


def get_alerts(candidate_id=None, limit=100, organization_id=None):
    session = SessionLocal()
    try:
        query = session.query(AlertRecord)
        if organization_id is not None:
            query = query.join(Candidate).filter(Candidate.organization_id == organization_id)
        if candidate_id:
            query = query.filter_by(candidate_id=candidate_id)
        records = query.order_by(desc(AlertRecord.created_at)).limit(limit).all()
        return [
            {
                "id": a.id,
                "candidate_id": a.candidate_id,
                "channel": a.channel,
                "recipient": a.recipient,
                "status": a.status,
                "payload": a.payload,
                "attempts": a.attempts,
                "error_message": a.error_message,
                "created_at": a.created_at,
                "delivered_at": a.delivered_at,
            }
            for a in records
        ]
    finally:
        session.close()


def create_monitoring_job(job_type, brand_id=None):
    session = SessionLocal()
    try:
        job = MonitoringJob(
            brand_id=brand_id,
            job_type=job_type,
            status="running",
            started_at=utc_now_iso(),
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id
    finally:
        session.close()


def update_monitoring_job(job_id, status, items_found=0, items_processed=0, error_message=None):
    session = SessionLocal()
    try:
        job = session.get(MonitoringJob, job_id)
        if job:
            job.status = status
            job.items_found = items_found
            job.items_processed = items_processed
            job.error_message = error_message
            if status in {"completed", "failed"}:
                job.completed_at = utc_now_iso()
            session.commit()
    finally:
        session.close()


def get_monitoring_jobs(limit=50, organization_id=None):
    session = SessionLocal()
    try:
        query = session.query(MonitoringJob)
        if organization_id is not None:
            query = query.join(Brand).filter(Brand.organization_id == organization_id)
        jobs = query.order_by(desc(MonitoringJob.started_at)).limit(limit).all()
        return [
            {
                "id": j.id,
                "brand_id": j.brand_id,
                "job_type": j.job_type,
                "status": j.status,
                "items_found": j.items_found,
                "items_processed": j.items_processed,
                "started_at": j.started_at,
                "completed_at": j.completed_at,
                "error_message": j.error_message,
            }
            for j in jobs
        ]
    finally:
        session.close()


def create_audit_log(action, organization_id=None, user_id=None, user_email=None, target_type=None, target_id=None, details=None, ip_address=None):
    session = SessionLocal()
    try:
        log = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            user_email=user_email,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            details=details if isinstance(details, str) else json.dumps(details or {}),
            ip_address=ip_address,
        )
        session.add(log)
        session.commit()
        return log.id
    finally:
        session.close()


def get_audit_logs(organization_id=None, limit=100):
    session = SessionLocal()
    try:
        query = session.query(AuditLog)
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        logs = query.order_by(desc(AuditLog.created_at)).limit(limit).all()
        return [
            {
                "id": l.id,
                "organization_id": l.organization_id,
                "user_id": l.user_id,
                "user_email": l.user_email,
                "action": l.action,
                "target_type": l.target_type,
                "target_id": l.target_id,
                "details": l.details,
                "created_at": l.created_at,
            }
            for l in logs
        ]
    finally:
        session.close()


if __name__ == "__main__":
    init_db()
    safe_url = make_url(DATABASE_URL).render_as_string(hide_password=True)
    print(f"CyberSentinel Database initialized at {safe_url}")
