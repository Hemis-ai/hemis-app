"""DAST report generation endpoints."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional

from ..storage.scan_store import store
from ..reports.pdf_generator import generate_pdf, generate_json_report, generate_csv_report

router = APIRouter()


class ReportRequest(BaseModel):
    format: str = "json"  # pdf, json, csv


@router.post("/reports/{scan_id}")
async def generate_report(scan_id: str, body: ReportRequest):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.status.value != "COMPLETED":
        raise HTTPException(400, "Report can only be generated for completed scans")

    findings = store.get_findings(scan_id)
    fmt = body.format.lower()
    timestamp = scan.completedAt or scan.createdAt

    if fmt == "pdf":
        pdf_bytes = generate_pdf(scan, findings)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="hemisx-dast-{scan_id[:8]}-report.pdf"',
            },
        )
    elif fmt == "csv":
        csv_content = generate_csv_report(scan, findings)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="hemisx-dast-{scan_id[:8]}-report.csv"',
            },
        )
    elif fmt == "json":
        json_report = generate_json_report(scan, findings)
        return json_report
    else:
        raise HTTPException(400, f"Unsupported format: {fmt}. Use pdf, json, or csv.")
