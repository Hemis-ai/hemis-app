from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Finding(BaseModel):
    id: str
    scanId: str
    type: str
    owaspCategory: str
    cweId: Optional[str] = None
    severity: Severity
    cvssScore: Optional[float] = None
    cvssVector: Optional[str] = None
    riskScore: int = 0
    title: str
    description: str
    businessImpact: Optional[str] = None
    affectedUrl: str
    affectedParameter: Optional[str] = None
    injectionPoint: Optional[str] = None
    payload: Optional[str] = None
    requestEvidence: Optional[str] = None
    responseEvidence: Optional[str] = None
    remediation: str
    remediationCode: Optional[str] = None
    aiEnrichmentData: Optional[str] = None
    pciDssRefs: list[str] = Field(default_factory=list)
    soc2Refs: list[str] = Field(default_factory=list)
    mitreAttackIds: list[str] = Field(default_factory=list)
    confidenceScore: int = 80
    status: FindingStatus = FindingStatus.OPEN
    isConfirmed: bool = False
