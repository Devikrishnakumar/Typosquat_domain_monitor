"""
routes.py
Comprehensive FastAPI Router for CyberSentinel.
All endpoints implement input validation, authorization checks, and multi-tenant isolation.
"""

import json
from uuid import uuid4
from sqlalchemy.exc import IntegrityError
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.schemas import (
    UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse,
    BrandCreateRequest, BrandUpdateRequest, ApprovedDomainRequest,
    CandidateReviewRequest, HistoricalDiscoveryRequest, InvestigationTriggerRequest,
    RiskAssessmentRequest, AlertTestRequest, ReportGenerationRequest
)
from src.api.auth import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, require_roles
)
from src.normalization.domain_normalizer import normalize_domain, is_excluded_domain
from src.discovery.historical_discovery import HistoricalDiscoveryEngine, CrtShProvider
from src.investigation.domain_investigator import DomainInvestigator
from src.scoring.risk_engine import EnterpriseRiskEngine
from src.alerts.notification_manager import notification_manager
from src.reporting.report_generator import generate_report
from src.storage import db
from src.storage.models import Candidate, Brand, ApprovedDomain, DomainInvestigation, MonitoringJob, Organization, User

router = APIRouter(prefix="/api/v1")
risk_evaluator = EnterpriseRiskEngine()
investigator = DomainInvestigator()


def _owned_brand(brand_id: int, user: dict) -> dict:
    with db.SessionLocal() as session:
        brand = session.query(Brand).filter_by(
            id=brand_id, organization_id=user["organization_id"]
        ).first()
        if not brand:
            raise HTTPException(status_code=404, detail="Brand not found")
        return {"id": brand.id, "name": brand.name, "official_domain": brand.official_domain}


def _owned_candidate(candidate_id: int, user: dict) -> dict:
    candidate = db.get_candidate(candidate_id)
    if not candidate or candidate["organization_id"] != user["organization_id"]:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return candidate


# ---------------------------------------------------------
# Auth & User Routes
# ---------------------------------------------------------

@router.post("/auth/register", response_model=TokenResponse)
def register(req: UserRegisterRequest):
    hashed_pw = get_password_hash(req.password)
    try:
        # Public signup creates an independent tenant. Reusing a display name
        # must never grant membership in an existing organization.
        with db.SessionLocal.begin() as session:
            if session.query(User).filter_by(email=req.email).first():
                raise HTTPException(status_code=400, detail="Email is already registered")
            org = Organization(name=req.organization_name, slug=uuid4().hex)
            session.add(org)
            session.flush()
            user = User(organization_id=org.id, email=req.email,
                        hashed_password=hashed_pw, full_name=req.full_name, role=req.role)
            session.add(user)
            session.flush()
            org_id, user_id = org.id, user.id
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Email is already registered")

    token = create_access_token({"sub": req.email, "org_id": org_id, "role": req.role or "analyst"})
    db.create_audit_log("user_registered", organization_id=org_id, user_id=user_id, user_email=req.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user_id, "email": req.email, "organization_id": org_id, "role": req.role or "analyst"},
    }


@router.post("/auth/login", response_model=TokenResponse)
def login(req: UserLoginRequest):
    user = db.get_user_by_email(req.email)
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token({"sub": user["email"], "org_id": user["organization_id"], "role": user["role"]})
    db.create_audit_log("user_login", organization_id=user["organization_id"], user_id=user["id"], user_email=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "organization_id": user["organization_id"],
            "role": user["role"],
            "full_name": user["full_name"],
        },
    }


@router.get("/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


# ---------------------------------------------------------
# Brand Management Routes
# ---------------------------------------------------------

@router.get("/brands")
def list_brands(current_user: dict = Depends(get_current_user)):
    return db.get_brands(organization_id=current_user["organization_id"])


@router.post("/brands")
def create_brand(
    req: BrandCreateRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    norm = normalize_domain(req.official_domain)
    if not norm.is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid official domain: {norm.error}")

    brand_id = db.create_or_update_brand(
        organization_id=current_user["organization_id"],
        name=req.name,
        official_domain=norm.ascii_domain,
        official_website_url=req.official_website_url,
        keywords=req.keywords,
        monitoring_enabled=req.monitoring_enabled,
        check_interval_minutes=req.check_interval_minutes,
        alert_threshold=req.alert_threshold,
        telegram_alerts_enabled=req.telegram_alerts_enabled,
        email_alerts_enabled=req.email_alerts_enabled,
        email_recipients=req.email_recipients,
    )
    db.create_audit_log(
        "brand_created",
        organization_id=current_user["organization_id"],
        user_id=current_user["id"],
        target_type="brand",
        target_id=str(brand_id),
        details={"name": req.name, "domain": norm.ascii_domain},
    )
    return {"id": brand_id, "status": "created", "official_domain": norm.ascii_domain}


@router.post("/brands/{brand_id}/approved-domains")
def add_approved_domain(
    brand_id: int,
    req: ApprovedDomainRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    _owned_brand(brand_id, current_user)
    norm = normalize_domain(req.domain)
    if not norm.is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid domain: {norm.error}")

    appr_id = db.add_approved_domain(brand_id=brand_id, domain=norm.ascii_domain, notes=req.notes or "")
    return {"id": appr_id, "status": "added", "domain": norm.ascii_domain}


@router.get("/brands/{brand_id}/approved-domains")
def list_approved_domains(brand_id: int, current_user: dict = Depends(get_current_user)):
    _owned_brand(brand_id, current_user)
    return db.get_approved_domains(brand_id=brand_id)


# ---------------------------------------------------------
# Candidate Domains & Review Routes
# ---------------------------------------------------------

@router.get("/candidates")
def list_candidates(
    brand_id: Optional[int] = None,
    min_risk: Optional[float] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    return db.get_all_candidates(
        org_id=current_user["organization_id"],
        brand_id=brand_id,
        min_risk=min_risk,
        severity=severity,
        status=status,
        search=search,
    )


@router.get("/candidates/{candidate_id}")
def get_candidate_detail(candidate_id: int, current_user: dict = Depends(get_current_user)):
    return _owned_candidate(candidate_id, current_user)


@router.post("/candidates/{candidate_id}/review")
def review_candidate(
    candidate_id: int,
    req: CandidateReviewRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    _owned_candidate(candidate_id, current_user)
    try:
        db.update_candidate_review(candidate_id, req.status, req.analyst_notes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    db.create_audit_log(
        "candidate_reviewed",
        organization_id=current_user["organization_id"],
        user_id=current_user["id"],
        target_type="candidate",
        target_id=str(candidate_id),
        details={"status": req.status, "notes": req.analyst_notes},
    )
    return {"status": "updated", "candidate_id": candidate_id}


# ---------------------------------------------------------
# Historical Discovery Routes
# ---------------------------------------------------------

@router.post("/discovery/historical")
def trigger_historical_discovery(
    req: HistoricalDiscoveryRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    official_domain = req.official_domain
    brand_name = "Brand"
    if req.brand_id:
        brand = _owned_brand(req.brand_id, current_user)
        official_domain = brand["official_domain"]
        brand_name = brand["name"]

    if not official_domain:
        raise HTTPException(status_code=400, detail="Must supply brand_id or official_domain")

    engine = HistoricalDiscoveryEngine(provider=CrtShProvider())
    result = engine.run_brand_discovery(
        brand_name=brand_name,
        official_domain=official_domain,
        brand_id=req.brand_id,
        organization_id=current_user["organization_id"],
        max_results=req.max_results,
    )
    return result


@router.get("/discovery/sources")
def get_discovery_sources():
    return {
        "sources": [
            {
                "name": "crt.sh",
                "type": "Certificate Transparency Search",
                "coverage": "Public CT logs globally",
                "limitations": "TLS certificate issuance only; does not confirm active hosting or registration.",
            },
            {
                "name": "certstream",
                "type": "Real-time Certificate Transparency Stream",
                "coverage": "Live streaming CT logs",
                "limitations": "Event stream; relies on active network connection.",
            },
        ]
    }


# ---------------------------------------------------------
# Investigation & Risk Routes
# ---------------------------------------------------------

@router.post("/investigation/run")
def run_investigation(
    req: InvestigationTriggerRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    cand = _owned_candidate(req.candidate_id, current_user)

    if req.domain and normalize_domain(req.domain).ascii_domain != cand["domain"]:
        raise HTTPException(status_code=400, detail="Domain must match the candidate")
    domain = cand["domain"]
    official_domain = cand["matched_brand"]

    # Execute investigation
    result = investigator.run_full_investigation(
        candidate_id=req.candidate_id,
        domain=domain,
        official_domain=official_domain,
    )

    # Re-evaluate risk
    assessment = risk_evaluator.evaluate(
        domain=domain,
        official_domain=official_domain,
        is_live=result["is_live"],
        visual_similarity=result["visual_similarity"],
        has_login_form=result["has_login_form"],
        suspicious_phrase_count=result["suspicious_phrase_count"],
        whois_info=result.get("whois"),
    )

    db.update_risk_score(
        candidate_id=req.candidate_id,
        score=assessment.score,
        level=assessment.severity,
        confidence=assessment.confidence,
        reasons=assessment.reasons,
        recommended_action=assessment.recommended_action,
    )

    return {
        "status": "completed",
        "investigation": result,
        "risk_assessment": assessment.to_dict(),
    }


# ---------------------------------------------------------
# Alerts & Notifications Routes
# ---------------------------------------------------------

@router.get("/alerts")
def list_alerts(candidate_id: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    if candidate_id is not None:
        _owned_candidate(candidate_id, current_user)
    return db.get_alerts(candidate_id=candidate_id, organization_id=current_user["organization_id"])


@router.post("/alerts/test")
def test_alert(
    req: AlertTestRequest,
    current_user: dict = Depends(require_roles(["admin", "analyst"])),
):
    ok, message = notification_manager.send_test_alert(channel=req.channel, recipient=req.recipient)
    return {"delivered": ok, "message": message}


# ---------------------------------------------------------
# Operations, Monitoring & Health Routes
# ---------------------------------------------------------

@router.get("/monitoring/jobs")
def list_jobs(current_user: dict = Depends(get_current_user)):
    return db.get_monitoring_jobs(limit=50, organization_id=current_user["organization_id"])


@router.get("/health/system")
def system_health():
    db_ok = True
    try:
        with db.SessionLocal() as session:
            session.execute(db.text("SELECT 1"))
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "database_connected": db_ok,
        "product_name": "CyberSentinel",
    }


@router.get("/audit")
def list_audit_logs(current_user: dict = Depends(require_roles(["admin"]))):
    return db.get_audit_logs(organization_id=current_user["organization_id"])
