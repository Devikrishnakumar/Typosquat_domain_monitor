"""
risk_engine.py
Transparent, configurable multi-signal risk scoring and classification engine
for Fake Website Detector (Typosquad).
"""

from datetime import datetime, timezone
import difflib
import math
from typing import Dict, Any, List, Optional, Tuple

SEVERITY_BANDS = {
    "LOW": (0, 29.9),
    "MEDIUM": (30, 59.9),
    "HIGH": (60, 79.9),
    "CRITICAL": (80, 100.0),
}


class RiskAssessmentResult:
    def __init__(
        self,
        score: float,
        severity: str,
        confidence: str,
        breakdown: Dict[str, float],
        reasons: List[str],
        missing_evidence: List[str],
        recommended_action: str,
    ):
        self.score = round(score, 2)
        self.severity = severity
        self.confidence = confidence
        self.breakdown = breakdown
        self.reasons = reasons
        self.missing_evidence = missing_evidence
        self.recommended_action = recommended_action

    def to_dict(self):
        return {
            "score": self.score,
            "severity": self.severity,
            "confidence": self.confidence,
            "breakdown": self.breakdown,
            "reasons": self.reasons,
            "missing_evidence": self.missing_evidence,
            "recommended_action": self.recommended_action,
        }


def get_severity_for_score(score: float, custom_bands: Optional[Dict[str, Tuple[float, float]]] = None) -> str:
    bands = custom_bands or SEVERITY_BANDS
    # Classify by lower thresholds to avoid gaps such as 29.9 < score < 30.
    ordered = sorted(bands.items(), key=lambda item: item[1][0], reverse=True)
    for level, (low, _) in ordered:
        if score >= low:
            return level
    return ordered[-1][0]


def compute_string_similarity(a: str, b: str) -> float:
    """Returns ratio between 0.0 and 1.0 using SequenceMatcher."""
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


class EnterpriseRiskEngine:
    """
    Evaluates multi-signal risk for candidate impersonation domains:
    - Domain similarity and deceptive hostname structure
    - Liveness and network reachability
    - Visual similarity to official brand reference
    - Credential collection indicators (login forms, password inputs)
    - Suspicious text content and brand keywords
    - Domain registration age and passive threat intelligence
    """
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        severity_bands: Optional[Dict[str, Tuple[float, float]]] = None,
    ):
        self.weights = weights or {
            "domain_similarity": 20.0,
            "liveness_dns": 15.0,
            "visual_similarity": 25.0,
            "credential_forms": 25.0,
            "content_phrases": 10.0,
            "domain_age_risk": 5.0,
        }
        self.severity_bands = severity_bands or SEVERITY_BANDS

    def evaluate(
        self,
        domain: str,
        official_domain: str,
        is_live: bool = False,
        visual_similarity: float = 0.0,
        has_login_form: bool = False,
        suspicious_phrase_count: int = 0,
        whois_info: Optional[Dict[str, Any]] = None,
        has_tls: bool = False,
        threat_intel_match: bool = False,
    ) -> RiskAssessmentResult:
        breakdown: Dict[str, float] = {}
        reasons: List[str] = []
        missing_evidence: List[str] = []

        clean_dom = domain.lower().strip()
        clean_off = official_domain.lower().strip()
        brand_stem = clean_off.split(".")[0]

        # 1. Domain Similarity & Structure (Max 20 pts)
        sim_ratio = compute_string_similarity(clean_dom, clean_off)
        domain_pts = 0.0
        if clean_dom == clean_off:
            domain_pts = 0.0  # Official brand domain has 0 risk
        elif brand_stem in clean_dom:
            domain_pts = self.weights["domain_similarity"] * 0.9
            reasons.append(f"Hostname contains official brand name '{brand_stem}'.")
        elif sim_ratio >= 0.8:
            domain_pts = self.weights["domain_similarity"] * sim_ratio
            reasons.append(f"High string similarity ({round(sim_ratio * 100)}%) to official domain '{clean_off}'.")
        elif sim_ratio >= 0.6:
            domain_pts = self.weights["domain_similarity"] * 0.5
            reasons.append(f"Moderate string similarity ({round(sim_ratio * 100)}%) to official domain.")
        breakdown["domain_similarity"] = round(domain_pts, 2)

        # 2. Liveness & Reachability (Max 15 pts)
        live_pts = 0.0
        if is_live:
            live_pts = self.weights["liveness_dns"]
            tls_note = " with active HTTPS/TLS" if has_tls else ""
            reasons.append(f"Domain is actively resolving on the public Internet{tls_note}.")
        else:
            reasons.append("Domain does not currently resolve to an active host.")
        breakdown["liveness"] = round(live_pts, 2)

        # 3. Visual Similarity (Max 25 pts)
        vis_score = float(visual_similarity or 0.0)
        vis_pts = round(vis_score * self.weights["visual_similarity"], 2)
        breakdown["visual_similarity"] = vis_pts
        if vis_score >= 0.7:
            reasons.append(f"Strong visual similarity ({round(vis_score * 100)}%) to authentic brand website.")
        elif vis_score >= 0.4:
            reasons.append(f"Noticeable layout similarity ({round(vis_score * 100)}%) to authentic brand website.")
        elif not is_live:
            missing_evidence.append("Visual similarity check unavailable: site is not live.")

        # 4. Credential Collection / Login Forms (Max 25 pts)
        login_pts = self.weights["credential_forms"] if has_login_form else 0.0
        breakdown["credential_forms"] = round(login_pts, 2)
        if has_login_form:
            reasons.append("Credential entry form or password input detected on webpage.")
        elif not is_live:
            missing_evidence.append("Form analysis unavailable: site is not live.")

        # 5. Suspicious Page Content & Keywords (Max 10 pts)
        phrase_factor = min(int(suspicious_phrase_count or 0), 3) / 3.0
        phrase_pts = round(phrase_factor * self.weights["content_phrases"], 2)
        breakdown["suspicious_phrases"] = phrase_pts
        if suspicious_phrase_count > 0:
            reasons.append(f"Found {suspicious_phrase_count} suspicious security/account verification phrases in page content.")

        # 6. Domain Age / Registration Risk (Max 5 pts)
        age_pts = 0.0
        whois = whois_info or {}
        created_date_str = whois.get("creation_date")
        if created_date_str:
            try:
                # Check if created within last 90 days
                created_dt = datetime.fromisoformat(str(created_date_str).replace("Z", "+00:00"))
                days_old = (datetime.now(timezone.utc) - created_dt).days
                if days_old <= 30:
                    age_pts = self.weights["domain_age_risk"]
                    reasons.append(f"Newly registered domain (registered only {days_old} days ago).")
                elif days_old <= 90:
                    age_pts = self.weights["domain_age_risk"] * 0.5
                    reasons.append(f"Recent domain registration ({days_old} days old).")
            except Exception:
                pass
        else:
            missing_evidence.append("Domain registration date not available in public RDAP.")
        breakdown["domain_age_risk"] = round(age_pts, 2)

        # 7. Threat Intel bonus (if confirmed match)
        if threat_intel_match:
            breakdown["threat_intel_match"] = 20.0
            reasons.append("Confirmed match in threat intelligence feed or reputation database.")

        # Compute total
        total_score = sum(breakdown.values())
        total_score = min(100.0, max(0.0, round(total_score, 2)))

        # Severity
        severity = get_severity_for_score(total_score, self.severity_bands)

        # Confidence level
        if threat_intel_match:
            confidence = "CONFIRMED"
        elif is_live and (has_login_form or vis_score >= 0.7):
            confidence = "HIGH"
        elif is_live:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        # Recommended Action
        if severity == "CRITICAL":
            action = "CRITICAL: Urgent triage required. Initiate brand impersonation takedown and block domain on corporate DNS resolvers."
        elif severity == "HIGH":
            action = "HIGH: Review website evidence, confirm unauthorized brand impersonation, and prepare registrar abuse notification."
        elif severity == "MEDIUM":
            action = "MEDIUM: Monitor candidate domain closely. Schedule automatic re-check in 24 hours for DNS or webpage changes."
        else:
            action = "LOW: Passive monitoring only. No active credential theft or impersonation indicators detected."

        return RiskAssessmentResult(
            score=total_score,
            severity=severity,
            confidence=confidence,
            breakdown=breakdown,
            reasons=reasons,
            missing_evidence=missing_evidence,
            recommended_action=action,
        )
