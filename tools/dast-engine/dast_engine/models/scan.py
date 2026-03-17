from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class ScanStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanProfile(str, Enum):
    FULL = "full"
    QUICK = "quick"
    API_ONLY = "api_only"
    DEEP = "deep"


class AuthConfig(BaseModel):
    type: str = "none"
    token: Optional[str] = None
    key: Optional[str] = None
    header: Optional[str] = None
    tokenUrl: Optional[str] = None
    clientId: Optional[str] = None
    clientSecret: Optional[str] = None
    scope: Optional[str] = None
    value: Optional[str] = None
    name: Optional[str] = None
    loginUrl: Optional[str] = None
    usernameField: Optional[str] = None
    passwordField: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ScanCreate(BaseModel):
    name: str
    targetUrl: str
    scanProfile: ScanProfile = ScanProfile.FULL
    authConfig: Optional[AuthConfig] = None
    scope: Optional[dict] = None


class ScanResponse(BaseModel):
    id: str
    name: str
    targetUrl: str
    scanProfile: str
    status: ScanStatus
    progress: int = 0
    currentPhase: str = "created"
    riskScore: Optional[int] = None
    endpointsDiscovered: int = 0
    endpointsTested: int = 0
    payloadsSent: int = 0
    criticalCount: int = 0
    highCount: int = 0
    mediumCount: int = 0
    lowCount: int = 0
    infoCount: int = 0
    executiveSummary: Optional[str] = None
    aiCorrelationData: Optional[str] = None
    aiComplianceData: Optional[str] = None
    techStackDetected: list[str] = Field(default_factory=list)
    reportUrl: Optional[str] = None
    startedAt: Optional[str] = None
    completedAt: Optional[str] = None
    createdAt: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
