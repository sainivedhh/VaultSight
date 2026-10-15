"""DSPM Risk Scoring Engine.

Risk = Data Sensitivity x Exposure x Access Breadth
Outputs normalized score (0 to 100), severity levels, and remediation text.
"""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field

from vaultsight.detectors.models import Finding, DetectorCategory
from vaultsight.posture import PostureFinding, PostureSeverity


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScoredRisk(BaseModel):
    """Unified risk evaluation combining data sensitivity, exposure, and access."""
    target_id: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: RiskLevel
    data_sensitivity_factor: float
    exposure_factor: float
    access_breadth_factor: float
    findings_count: int
    posture_issues_count: int
    summary: str
    remediation_steps: List[str]


class RiskScoringEngine:
    """Calculates DSPM tri-factor security risk score."""

    # Data category base weights (1.0 to 10.0)
    CATEGORY_WEIGHTS = {
        DetectorCategory.CREDENTIAL: 10.0,
        DetectorCategory.FINANCIAL: 9.0,
        DetectorCategory.PII: 7.0,
        DetectorCategory.INFRASTRUCTURE: 5.0,
    }

    def calculate_risk(
        self,
        target_id: str,
        findings: List[Finding],
        posture_findings: List[PostureFinding],
        is_publicly_accessible: bool = False,
        access_grant_count: int = 1,
    ) -> ScoredRisk:
        # 1. Data Sensitivity Score (0.0 to 10.0)
        if not findings:
            sensitivity_score = 1.0
        else:
            # Maximum individual category weight * confidence, with volume contribution
            max_item = max(
                self.CATEGORY_WEIGHTS.get(f.category, 5.0) * f.confidence
                for f in findings
            )
            volume_bonus = min(2.0, len(findings) * 0.1)
            sensitivity_score = min(10.0, max_item + volume_bonus)

        # 2. Exposure Factor (1.0 to 10.0)
        # Based on cloud posture issues: public bucket, open ACL, missing encryption
        exposure_points = 2.0  # internal private baseline
        if is_publicly_accessible:
            exposure_points += 5.0
        
        for pf in posture_findings:
            if pf.severity == PostureSeverity.CRITICAL:
                exposure_points += 3.0
            elif pf.severity == PostureSeverity.HIGH:
                exposure_points += 2.0
            elif pf.severity == PostureSeverity.MEDIUM:
                exposure_points += 1.0

        exposure_score = min(10.0, exposure_points)

        # 3. Access Breadth Factor (1.0 to 10.0)
        # Number of users/roles or wildcard privileges
        if access_grant_count > 50 or any("ADMIN-WILDCARD" in pf.check_id for pf in posture_findings):
            access_breadth_score = 10.0
        elif access_grant_count > 10:
            access_breadth_score = 7.0
        elif access_grant_count > 1:
            access_breadth_score = 4.0
        else:
            access_breadth_score = 2.0

        # Normalized Composite Risk: (Sensitivity x Exposure x Access) / 1000 * 100
        raw_composite = (sensitivity_score * exposure_score * access_breadth_score) / 10.0
        composite_score = round(min(100.0, max(0.0, raw_composite)), 1)

        # Map to Risk Level
        if composite_score >= 75.0:
            level = RiskLevel.CRITICAL
        elif composite_score >= 50.0:
            level = RiskLevel.HIGH
        elif composite_score >= 25.0:
            level = RiskLevel.MEDIUM
        elif composite_score >= 10.0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        # Compile remediation steps
        remediations = []
        if is_publicly_accessible or any("PUBLIC" in pf.check_id for pf in posture_findings):
            remediations.append("Immediately revoke public read ACLs and enforce S3 Block Public Access.")
        if any("ENCRYPTION" in pf.check_id for pf in posture_findings):
            remediations.append("Apply default AWS KMS or AES-256 encryption.")
        if any("WILDCARD" in pf.check_id for pf in posture_findings):
            remediations.append("Refactor IAM policies to eliminate Action='*' and Resource='*' wildcards.")
        if findings:
            remediations.append(f"Redact or encrypt {len(findings)} plaintext sensitive items found in data store.")

        if not remediations:
            remediations.append("Maintain continuous monitoring and least-privilege access baseline.")

        summary = (
            f"Target '{target_id}' assessed with {level.value} risk ({composite_score}/100). "
            f"Detected {len(findings)} sensitive data findings and {len(posture_findings)} posture misconfigurations."
        )

        return ScoredRisk(
            target_id=target_id,
            risk_score=composite_score,
            risk_level=level,
            data_sensitivity_factor=round(sensitivity_score, 2),
            exposure_factor=round(exposure_score, 2),
            access_breadth_factor=round(access_breadth_score, 2),
            findings_count=len(findings),
            posture_issues_count=len(posture_findings),
            summary=summary,
            remediation_steps=remediations,
        )
