"""Pydantic schemas for request and response validation using Pydantic v2 conventions."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: Optional[str] = Field("viewer", description="viewer, analyst, admin")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> str:
        allowed = {"viewer", "analyst", "admin"}
        if v not in allowed:
            raise ValueError(f"Role must be one of {allowed}")
        return v or "viewer"


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class StartScanRequest(BaseModel):
    target_type: str = Field(..., pattern=r"^(filesystem|sqlite|s3)$")
    target_path: str = Field(..., min_length=1, max_length=512)

    @field_validator("target_path")
    @classmethod
    def prevent_dangerous_path(cls, v: str) -> str:
        # Prevent obvious path traversal sequences in raw API payload
        if ".." in v or v.startswith("/") or v.startswith("\\") or (len(v) > 1 and v[1] == ":"):
            raise ValueError("Path traversal sequences and absolute paths are forbidden.")
        return v


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    detector: str
    category: str
    confidence: float
    location: str
    redacted_preview: str


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_type: str
    target_path: str
    status: str
    findings_count: int
    risk_score: float
    risk_level: str
    created_at: datetime
    findings: Optional[List[FindingResponse]] = None


class ReportSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_scans: int
    total_findings: int
    critical_findings_count: int
    average_risk_score: float
    scans: List[ScanResponse]
