"""In-memory storage for scans and findings — with asyncio lock for safe concurrent access."""
from __future__ import annotations
import asyncio
from typing import Optional
from ..models.scan import ScanResponse, ScanStatus
from ..models.finding import Finding
from ..models.progress import ScanProgressEvent


class ScanStore:
    """Thread-safe in-memory store for scans, findings, and progress.

    The asyncio.Lock prevents TOCTOU races when multiple concurrent scans
    call add_findings() simultaneously.
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self.scans: dict[str, ScanResponse] = {}
        self.findings: dict[str, list[Finding]] = {}  # scan_id -> findings
        self.progress: dict[str, ScanProgressEvent] = {}

    def create_scan(self, scan: ScanResponse) -> ScanResponse:
        self.scans[scan.id] = scan
        self.findings[scan.id] = []
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def list_scans(self, page: int = 1, page_size: int = 20) -> tuple[list[ScanResponse], int]:
        all_scans = sorted(self.scans.values(), key=lambda s: s.createdAt, reverse=True)
        total = len(all_scans)
        start = (page - 1) * page_size
        return all_scans[start:start + page_size], total

    def update_scan(self, scan_id: str, **kwargs) -> Optional[ScanResponse]:
        scan = self.scans.get(scan_id)
        if scan:
            for key, value in kwargs.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
        return scan

    async def add_findings(self, scan_id: str, new_findings: list[Finding]):
        """Add findings under asyncio lock to prevent TOCTOU race."""
        async with self._lock:
            if scan_id not in self.findings:
                self.findings[scan_id] = []
            self.findings[scan_id].extend(new_findings)

    def get_findings(self, scan_id: str) -> list[Finding]:
        return self.findings.get(scan_id, [])

    def update_progress(self, scan_id: str, progress: ScanProgressEvent):
        self.progress[scan_id] = progress

    def get_progress(self, scan_id: str) -> Optional[ScanProgressEvent]:
        return self.progress.get(scan_id)

    def delete_scan(self, scan_id: str):
        self.scans.pop(scan_id, None)
        self.findings.pop(scan_id, None)
        self.progress.pop(scan_id, None)


# Singleton
store = ScanStore()
