"""DAST scan CRUD endpoints."""
from __future__ import annotations
import uuid
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..models.scan import ScanCreate, ScanResponse, ScanStatus, ScanProfile
from ..storage.scan_store import store
from ..orchestrator.scan_runner import run_scan

router = APIRouter()

# Track background tasks so we can cancel them
_running_tasks: dict[str, asyncio.Task] = {}


class ScanCreateRequest(BaseModel):
    name: str
    targetUrl: str
    scanProfile: str = "full"
    authConfig: Optional[dict] = None
    scope: Optional[dict] = None


@router.get("/scans")
async def list_scans(page: int = 1, pageSize: int = 20, status: Optional[str] = None):
    scans, total = store.list_scans(page, pageSize)
    if status:
        scans = [s for s in scans if s.status.value == status]
        total = len(scans)
    return {
        "scans": [s.model_dump() for s in scans],
        "pagination": {
            "page": page,
            "pageSize": pageSize,
            "total": total,
            "totalPages": max(1, (total + pageSize - 1) // pageSize),
        },
    }


@router.post("/scans", status_code=201)
async def create_scan(body: ScanCreateRequest):
    if not body.name.strip():
        raise HTTPException(400, "Scan name is required")
    if not body.targetUrl.strip():
        raise HTTPException(400, "Target URL is required")

    # Validate URL
    from urllib.parse import urlparse
    parsed = urlparse(body.targetUrl)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(400, "Invalid target URL")

    scan_id = f"scan-{uuid.uuid4().hex[:12]}"

    # Map to the scan profile enum
    try:
        profile = ScanProfile(body.scanProfile)
    except ValueError:
        profile = ScanProfile.FULL

    scan = ScanResponse(
        id=scan_id,
        name=body.name.strip(),
        targetUrl=body.targetUrl.strip(),
        scanProfile=profile.value,
        status=ScanStatus.CREATED,
    )
    store.create_scan(scan)

    # Build the ScanCreate config for the runner
    from ..models.scan import AuthConfig
    auth = None
    if body.authConfig:
        auth = AuthConfig(**body.authConfig)

    config = ScanCreate(
        name=body.name.strip(),
        targetUrl=body.targetUrl.strip(),
        scanProfile=profile,
        authConfig=auth,
        scope=body.scope,
    )

    # Fire-and-forget the scan
    task = asyncio.create_task(run_scan(scan_id, config))
    _running_tasks[scan_id] = task

    def _cleanup(t):
        _running_tasks.pop(scan_id, None)
    task.add_done_callback(_cleanup)

    return {"scan": scan.model_dump()}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    progress = store.get_progress(scan_id)
    return {
        "scan": scan.model_dump(),
        "progress": progress.model_dump() if progress else None,
    }


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        # Cancel the running task first
        task = _running_tasks.get(scan_id)
        if task:
            task.cancel()
        store.update_scan(scan_id, status=ScanStatus.CANCELLED)

    store.delete_scan(scan_id)
    return {"success": True}


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status not in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        raise HTTPException(409, f"Cannot cancel scan in {scan.status.value} state")

    task = _running_tasks.get(scan_id)
    if task:
        task.cancel()

    store.update_scan(scan_id, status=ScanStatus.CANCELLED)
    return {"success": True, "scan": store.get_scan(scan_id).model_dump()}
