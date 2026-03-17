"""DAST scan comparison endpoint."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..storage.scan_store import store

router = APIRouter()


class CompareRequest(BaseModel):
    baselineScanId: str
    currentScanId: str


@router.post("/compare")
async def compare_scans(body: CompareRequest):
    if body.baselineScanId == body.currentScanId:
        raise HTTPException(400, "Cannot compare a scan with itself")

    baseline = store.get_scan(body.baselineScanId)
    current = store.get_scan(body.currentScanId)

    if not baseline or not current:
        raise HTTPException(404, "One or both scans not found")

    baseline_findings = store.get_findings(body.baselineScanId)
    current_findings = store.get_findings(body.currentScanId)

    # Build fingerprints for matching
    def fingerprint(f):
        return f"{f.type}|{f.affectedUrl}|{f.affectedParameter or ''}"

    baseline_fps = {fingerprint(f): f for f in baseline_findings}
    current_fps = {fingerprint(f): f for f in current_findings}

    new_findings = []
    resolved_findings = []
    persistent_findings = []

    for fp, f in current_fps.items():
        if fp not in baseline_fps:
            new_findings.append(f.model_dump())
        else:
            persistent_findings.append(f.model_dump())

    for fp, f in baseline_fps.items():
        if fp not in current_fps:
            resolved_findings.append(f.model_dump())

    # Calculate metric deltas
    def delta(a, b):
        return b - a

    comparison = {
        "baselineScan": {"id": baseline.id, "name": baseline.name, "targetUrl": baseline.targetUrl},
        "currentScan": {"id": current.id, "name": current.name, "targetUrl": current.targetUrl},
        "newFindings": new_findings,
        "resolvedFindings": resolved_findings,
        "persistentFindings": persistent_findings,
        "totalDelta": len(current_findings) - len(baseline_findings),
        "metrics": {
            "riskScoreDelta": delta(baseline.riskScore or 0, current.riskScore or 0),
            "criticalDelta": delta(baseline.criticalCount, current.criticalCount),
            "highDelta": delta(baseline.highCount, current.highCount),
            "mediumDelta": delta(baseline.mediumCount, current.mediumCount),
            "lowDelta": delta(baseline.lowCount, current.lowCount),
            "infoDelta": delta(baseline.infoCount, current.infoCount),
            "endpointsDelta": delta(baseline.endpointsDiscovered, current.endpointsDiscovered),
        },
        "summary": _generate_comparison_summary(
            baseline, current, new_findings, resolved_findings, persistent_findings
        ),
    }

    return {"comparison": comparison}


def _generate_comparison_summary(baseline, current, new_findings, resolved, persistent):
    total_baseline = len(resolved) + len(persistent)
    total_current = len(new_findings) + len(persistent)
    trend = "improved" if total_current < total_baseline else "degraded" if total_current > total_baseline else "unchanged"

    summary = f"Comparison of '{baseline.name}' vs '{current.name}': "
    summary += f"Security posture has {trend}. "
    summary += f"{len(new_findings)} new findings introduced, {len(resolved)} resolved, {len(persistent)} persistent."

    if new_findings:
        critical_new = sum(1 for f in new_findings if f.get("severity") == "CRITICAL")
        high_new = sum(1 for f in new_findings if f.get("severity") == "HIGH")
        if critical_new or high_new:
            summary += f" ⚠ {critical_new} critical and {high_new} high-severity new findings require immediate attention."

    return summary
