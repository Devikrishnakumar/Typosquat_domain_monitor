"""
schemas.py
Pydantic Request & Response Models for CyberSentinel API.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------
# Auth Schemas
# ---------------------------------------------------------

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    organization_name: str
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UserResponse(BaseModel):
    id: int
    organization_id: int
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool


# ---------------------------------------------------------
# Brand Schemas
# ---------------------------------------------------------

class BrandCreateRequest(BaseModel):
    name: str
    official_domain: str
    official_website_url: Optional[str] = None
    keywords: Optional[List[str]] = []
    monitoring_enabled: bool = True
    check_interval_minutes: int = Field(5, ge=1)
    alert_threshold: int = Field(70, ge=0, le=100)
    telegram_alerts_enabled: bool = True
    email_alerts_enabled: bool = False
    email_recipients: Optional[List[str]] = []


class BrandUpdateRequest(BaseModel):
    name: Optional[str] = None
    official_website_url: Optional[str] = None
    keywords: Optional[List[str]] = None
    monitoring_enabled: Optional[bool] = None
    check_interval_minutes: Optional[int] = None
    alert_threshold: Optional[int] = None
    telegram_alerts_enabled: Optional[bool] = None
    email_alerts_enabled: Optional[bool] = None
    email_recipients: Optional[List[str]] = None


class ApprovedDomainRequest(BaseModel):
    domain: str
    notes: Optional[str] = None


# ---------------------------------------------------------
# Candidate & Investigation Schemas
# ---------------------------------------------------------

class CandidateReviewRequest(BaseModel):
    status: str = Field(..., description="new, under_investigation, false_positive, resolved, takedown_requested")
    analyst_notes: str = ""


class HistoricalDiscoveryRequest(BaseModel):
    brand_id: Optional[int] = None
    official_domain: Optional[str] = None
    max_results: int = Field(50, ge=1, le=1000)


class InvestigationTriggerRequest(BaseModel):
    candidate_id: int
    domain: Optional[str] = None


class RiskAssessmentRequest(BaseModel):
    candidate_id: int


class AlertTestRequest(BaseModel):
    channel: str = "telegram"
    recipient: Optional[str] = None


class ReportGenerationRequest(BaseModel):
    candidate_id: int
    format: str = "pdf"
