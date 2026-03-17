"""DAST findings endpoints."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from typing import Optional

from ..storage.scan_store import store

router = APIRouter()


@router.get("/findings")
async def list_findings(
    scanId: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    pageSize: int = 50,
):
    if not scanId:
        raise HTTPException(400, "scanId is required")

    findings = store.get_findings(scanId)

    # Filter
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    if status:
        findings = [f for f in findings if f.status.value == status]

    # Sort: severity priority, then CVSS desc
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (sev_order.get(f.severity.value, 5), -(f.cvssScore or 0)))

    total = len(findings)
    start = (page - 1) * pageSize
    paginated = findings[start:start + pageSize]

    return {
        "findings": [f.model_dump() for f in paginated],
        "pagination": {
            "page": page,
            "pageSize": pageSize,
            "total": total,
            "totalPages": max(1, (total + pageSize - 1) // pageSize),
        },
    }


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    # Search across all scan findings
    for scan_id, findings in store.findings.items():
        for f in findings:
            if f.id == finding_id:
                return {"finding": f.model_dump()}
    raise HTTPException(404, "Finding not found")
