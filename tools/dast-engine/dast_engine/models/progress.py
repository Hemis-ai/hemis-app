from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class ScanProgressEvent(BaseModel):
    scanId: str
    status: str
    progress: int
    currentPhase: str
    endpointsDiscovered: int = 0
    endpointsTested: int = 0
    payloadsSent: int = 0
    findingsCount: int = 0
    message: str = ""
    estimatedTimeRemaining: Optional[float] = None  # seconds
    estimatedTotalTime: Optional[float] = None  # seconds
    scanSpeed: Optional[float] = None  # endpoints per second
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
