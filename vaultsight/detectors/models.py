"""Data models for sensitive findings and classification."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class DetectorCategory(str, Enum):
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    CREDENTIAL = "CREDENTIAL"
    INFRASTRUCTURE = "INFRASTRUCTURE"


class Finding(BaseModel):
    """Represents a single sensitive data finding in scanned data."""
    model_config = ConfigDict(frozen=True)

    detector: str = Field(..., description="Name of the detector rule (e.g. aadhaar, aws_access_key)")
    category: DetectorCategory = Field(..., description="High-level security/compliance category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    location: str = Field(..., description="Location identifier (file path, line number, table.column)")
    redacted_preview: str = Field(..., description="Safe preview with sensitive characters masked")
    details: Optional[dict] = Field(default_factory=dict, description="Metadata like match lengths, checksum status")
