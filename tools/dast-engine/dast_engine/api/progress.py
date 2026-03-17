"""SSE endpoint for real-time scan progress updates."""
from __future__ import annotations
import asyncio
import json
from fastapi import APIRouter, HTTPException
from sse_starlette.sse import EventSourceResponse

from ..storage.scan_store import store

router = APIRouter()


@router.get("/scans/{scan_id}/progress")
async def scan_progress_stream(scan_id: str):
    """Server-Sent Events stream for scan progress."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    async def event_generator():
        last_progress = -1
        while True:
            progress = store.get_progress(scan_id)
            scan_data = store.get_scan(scan_id)

            if progress and progress.progress != last_progress:
                last_progress = progress.progress
                yield {
                    "event": "progress",
                    "data": json.dumps(progress.model_dump()),
                }

            # Stop streaming when scan is done
            if scan_data and scan_data.status.value in ("COMPLETED", "FAILED", "CANCELLED"):
                yield {
                    "event": "complete",
                    "data": json.dumps({
                        "scanId": scan_id,
                        "status": scan_data.status.value,
                        "progress": 100 if scan_data.status.value == "COMPLETED" else last_progress,
                    }),
                }
                break

            await asyncio.sleep(0.5)

    return EventSourceResponse(event_generator())


@router.get("/scans/{scan_id}/progress/poll")
async def scan_progress_poll(scan_id: str):
    """Simple polling endpoint for scan progress (non-SSE)."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    progress = store.get_progress(scan_id)
    return {
        "scan": scan.model_dump(),
        "progress": progress.model_dump() if progress else None,
    }
