"""
models.py
Enterprise Relational Database Schema for Fake Website Detector (Typosquad).
Includes Organizations, Users, Brands, Approved Domains, Candidates, Observations,
Investigations, DNS/Cert records, Risk Assessments, Alerts, Monitoring Jobs, and Audit Logs.
"""

from datetime import datetime, timezone
import json
from sqlalchemy import (
    Column, Integer, String, Float, Text, Boolean, DateTime,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    created_at = Column(String, default=utc_now_iso, nullable=False)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    brands = relationship("Brand", back_populates="organization", cascade="all, delete-orphan")
    candidates = relationship("Candidate", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String, default=utc_now_iso, nullable=False)

    organization = relationship("Organization", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")


class Brand(Base):
    __tablename__ = "brands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    official_domain = Column(String(255), nullable=False, index=True)
    official_website_url = Column(String(512), nullable=True)
    keywords = Column(Text, nullable=True, default="[]")  # JSON array
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    check_interval_minutes = Column(Integer, default=5, nullable=False)
    alert_threshold = Column(Integer, default=70, nullable=False)  # 0-100 threshold
    telegram_alerts_enabled = Column(Boolean, default=True, nullable=False)
    email_alerts_enabled = Column(Boolean, default=False, nullable=False)
    email_recipients = Column(Text, nullable=True, default="[]")  # JSON array
    created_at = Column(String, default=utc_now_iso, nullable=False)
    updated_at = Column(String, default=utc_now_iso, onupdate=utc_now_iso, nullable=False)

    organization = relationship("Organization", back_populates="brands")
    approved_domains = relationship("ApprovedDomain", back_populates="brand", cascade="all, delete-orphan")
    candidates = relationship("Candidate", back_populates="brand_rel")
    monitoring_jobs = relationship("MonitoringJob", back_populates="brand")

    __table_args__ = (
        UniqueConstraint("organization_id", "official_domain", name="uq_org_brand_domain"),
    )


class ApprovedDomain(Base):
    __tablename__ = "approved_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    brand_id = Column(Integer, ForeignKey("brands.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    notes = Column(String(512), nullable=True)
    created_at = Column(String, default=utc_now_iso, nullable=False)

    brand = relationship("Brand", back_populates="approved_domains")

    __table_args__ = (
        UniqueConstraint("brand_id", "domain", name="uq_brand_approved_domain"),
    )


class Candidate(Base):
    """
    Candidate table preserving full backwards compatibility with initial MVP
    and extending with enterprise multi-tenant & threat intelligence fields.
    """
    __tablename__ = "candidates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, nullable=False, index=True)
    decoded_domain = Column(String, nullable=True)
    matched_brand = Column(String, nullable=False, index=True)
    detected_at = Column(String, nullable=False)
    is_live = Column(Integer, nullable=True)
    visual_similarity = Column(Float, nullable=True)
    has_login_form = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=True, index=True)
    risk_level = Column(String, nullable=True, index=True)
    screenshot_path = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="new", index=True)
    analyst_notes = Column(Text, nullable=False, default="")
    evidence_status = Column(String, nullable=False, default="pending")
    risk_breakdown = Column(Text, nullable=True)
    suspicious_phrase_count = Column(Integer, nullable=False, default=0)
    last_seen_at = Column(String, nullable=True)
    seen_count = Column(Integer, nullable=False, default=1)

    # Extended Enterprise Fields
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id", ondelete="SET NULL"), nullable=True, index=True)
    registered_domain = Column(String, nullable=True, index=True)
    tld = Column(String, nullable=True)
    event_category = Column(String, default="newly_observed", nullable=False, index=True)
    confidence_level = Column(String, default="MEDIUM", nullable=True)
    recommended_action = Column(Text, nullable=True)
    first_seen_at = Column(String, nullable=True)
    discovered_at = Column(String, nullable=True)
    imported_at = Column(String, nullable=True)
    certificate_issued_at = Column(String, nullable=True)
    registered_at = Column(String, nullable=True)
    last_investigated_at = Column(String, nullable=True)
    last_alerted_at = Column(String, nullable=True)

    organization = relationship("Organization", back_populates="candidates")
    brand_rel = relationship("Brand", back_populates="candidates")
    observations = relationship("DiscoveryObservation", back_populates="candidate", cascade="all, delete-orphan")
    investigations = relationship("DomainInvestigation", back_populates="candidate", cascade="all, delete-orphan")
    dns_records = relationship("DnsObservation", back_populates="candidate", cascade="all, delete-orphan")
    cert_records = relationship("CertificateObservation", back_populates="candidate", cascade="all, delete-orphan")
    risk_assessments = relationship("RiskAssessment", back_populates="candidate", cascade="all, delete-orphan")
    alerts = relationship("AlertRecord", back_populates="candidate", cascade="all, delete-orphan")


class DiscoveryObservation(Base):
    __tablename__ = "discovery_observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)  # crt.sh, certstream, manual, threat_feed
    observed_at = Column(String, default=utc_now_iso, nullable=False)
    imported_at = Column(String, default=utc_now_iso, nullable=False)
    raw_data = Column(Text, nullable=True)

    candidate = relationship("Candidate", back_populates="observations")


class DomainInvestigation(Base):
    __tablename__ = "domain_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    investigated_at = Column(String, default=utc_now_iso, nullable=False)
    is_live = Column(Boolean, default=False, nullable=False)
    http_status = Column(Integer, nullable=True)
    redirect_chain = Column(Text, nullable=True, default="[]")  # JSON array
    final_hostname = Column(String(255), nullable=True)
    https_available = Column(Boolean, default=False, nullable=False)
    page_title = Column(Text, nullable=True)
    has_credential_form = Column(Boolean, default=False, nullable=False)
    suspicious_keywords_found = Column(Text, nullable=True, default="[]")  # JSON array
    whois_registrar = Column(String(255), nullable=True)
    whois_created_date = Column(String, nullable=True)
    whois_expires_date = Column(String, nullable=True)
    whois_nameservers = Column(Text, nullable=True, default="[]")
    screenshot_path = Column(Text, nullable=True)
    visual_similarity = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)

    candidate = relationship("Candidate", back_populates="investigations")
    dns_observations = relationship("DnsObservation", back_populates="investigation", cascade="all, delete-orphan")
    cert_observations = relationship("CertificateObservation", back_populates="investigation", cascade="all, delete-orphan")


class DnsObservation(Base):
    __tablename__ = "dns_observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, ForeignKey("domain_investigations.id", ondelete="CASCADE"), nullable=True, index=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    record_type = Column(String(10), nullable=False)  # A, AAAA, CNAME, MX, NS
    records = Column(Text, nullable=False, default="[]")  # JSON array
    resolved_at = Column(String, default=utc_now_iso, nullable=False)
    status = Column(String(20), default="OK", nullable=False)  # OK, NXDOMAIN, TIMEOUT, ERROR

    investigation = relationship("DomainInvestigation", back_populates="dns_observations")
    candidate = relationship("Candidate", back_populates="dns_records")


class CertificateObservation(Base):
    __tablename__ = "certificate_observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, ForeignKey("domain_investigations.id", ondelete="CASCADE"), nullable=True, index=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    valid_from = Column(String, nullable=True)
    valid_to = Column(String, nullable=True)
    san_list = Column(Text, nullable=True, default="[]")  # JSON array
    serial_number = Column(String(128), nullable=True)
    fingerprint_sha256 = Column(String(64), nullable=True)
    is_new = Column(Boolean, default=True, nullable=False)
    observed_at = Column(String, default=utc_now_iso, nullable=False)

    investigation = relationship("DomainInvestigation", back_populates="cert_observations")
    candidate = relationship("Candidate", back_populates="cert_records")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    assessed_at = Column(String, default=utc_now_iso, nullable=False)
    score = Column(Float, nullable=False)
    level = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(20), default="MEDIUM", nullable=False)
    breakdown = Column(Text, nullable=True)  # JSON dict
    reasons = Column(Text, nullable=True, default="[]")  # JSON array
    missing_evidence = Column(Text, nullable=True, default="[]")  # JSON array
    recommended_action = Column(Text, nullable=True)

    candidate = relationship("Candidate", back_populates="risk_assessments")


class AlertRecord(Base):
    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(Integer, ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(20), nullable=False)  # telegram, email
    recipient = Column(String(255), nullable=True)
    status = Column(String(20), default="pending", nullable=False)  # sent, failed, pending, retrying
    payload = Column(Text, nullable=True)
    attempts = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(String, default=utc_now_iso, nullable=False)
    delivered_at = Column(String, nullable=True)

    candidate = relationship("Candidate", back_populates="alerts")


class MonitoringJob(Base):
    __tablename__ = "monitoring_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    brand_id = Column(Integer, ForeignKey("brands.id", ondelete="SET NULL"), nullable=True, index=True)
    job_type = Column(String(50), nullable=False)  # historical_discovery, ct_stream, investigation
    status = Column(String(20), default="queued", nullable=False)  # queued, running, completed, failed
    items_found = Column(Integer, default=0, nullable=False)
    items_processed = Column(Integer, default=0, nullable=False)
    started_at = Column(String, default=utc_now_iso, nullable=False)
    completed_at = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)

    brand = relationship("Brand", back_populates="monitoring_jobs")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    created_at = Column(String, default=utc_now_iso, nullable=False)

    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")
