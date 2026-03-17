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
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
