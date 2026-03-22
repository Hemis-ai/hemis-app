"""
Gap analysis report generator -- produces structured JSON reports and
formatted summaries from comparison results.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .comparison_engine import ComparisonEngine, ComparisonResult, BROAD_CATEGORIES
from .burp_parser import BurpFinding
from ..models.finding import Finding


def generate_gap_analysis(
    hemisx_findings: list[Finding],
    benchmark_findings: list[BurpFinding],
    scan_id: str = "",
    benchmark_source: str = "Burp Suite",
) -> dict:
    """Run comparison and produce a complete gap analysis report.

    This is the high-level entry point that orchestrates the comparison
    engine and formats the output.
    """
    engine = ComparisonEngine()
    result = engine.compare(hemisx_findings, benchmark_findings)
    gap_report = engine.generate_gap_report(result)

    # Wrap with metadata
    return {
        "gapAnalysis": {
            "metadata": {
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "scanId": scan_id,
                "benchmarkSource": benchmark_source,
                "hemisxFindingsCount": result.total_hemisx,
                "benchmarkFindingsCount": result.total_benchmark,
            },
            **gap_report,
            "coverageMatrix": _build_coverage_matrix(result),
            "improvementRoadmap": _build_roadmap(gap_report["recommendations"]),
            "falsePositiveAnalysis": _build_fp_analysis(result),
        }
    }


def _build_coverage_matrix(result: ComparisonResult) -> dict:
    """Build a detailed coverage matrix showing per-category detection
    status for both tools."""
    matrix: dict[str, dict] = {}

    for cat_name in sorted(BROAD_CATEGORIES.keys()):
        cat_info = result.category_coverage.get(cat_name)
        if cat_info:
            matrix[cat_name] = {
                "hemisx": cat_info["hemisx_detected"],
                "benchmark": cat_info["benchmark_detected"],
                "gap": cat_info["status"] == "benchmark_only",
            }
        else:
            # Category not seen in either tool
            matrix[cat_name] = {
                "hemisx": False,
                "benchmark": False,
                "gap": False,
            }

    # Add any extra categories that appeared but are not in BROAD_CATEGORIES
    for cat_name, info in result.category_coverage.items():
        if cat_name not in matrix:
            matrix[cat_name] = {
                "hemisx": info["hemisx_detected"],
                "benchmark": info["benchmark_detected"],
                "gap": info["status"] == "benchmark_only",
            }

    # Summary stats
    total_cats = len(matrix)
    covered_by_hemisx = sum(1 for v in matrix.values() if v["hemisx"])
    gaps = sum(1 for v in matrix.values() if v["gap"])

    return {
        "categories": matrix,
        "totalCategories": total_cats,
        "coveredByHemisx": covered_by_hemisx,
        "gaps": gaps,
        "categoryConveragePercent": round(
            (covered_by_hemisx / total_cats * 100) if total_cats else 100, 1
        ),
    }


def _build_roadmap(recommendations: list[dict]) -> list[dict]:
    """Transform recommendations into a prioritized improvement roadmap."""
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_recs = sorted(
        recommendations, key=lambda r: priority_order.get(r.get("priority", "INFO"), 4)
    )

    roadmap: list[dict] = []
    for idx, rec in enumerate(sorted_recs, 1):
        effort = _estimate_effort(rec["area"], rec["priority"])
        roadmap.append(
            {
                "step": idx,
                "priority": rec["priority"],
                "area": rec["area"],
                "description": rec["finding"],
                "action": rec["action"],
                "estimatedEffort": effort,
            }
        )

    return roadmap


def _estimate_effort(area: str, priority: str) -> str:
    """Rough effort estimate for a recommendation."""
    if priority == "CRITICAL":
        return "1-2 sprints"
    if area in ("Detection Coverage", "High-Severity Detection"):
        return "2-3 sprints"
    if area == "False Positive Reduction":
        return "1-2 sprints"
    if area == "Severity Calibration":
        return "1 sprint"
    return "1 sprint"


def _build_fp_analysis(result: ComparisonResult) -> dict:
    """Detailed false positive analysis section."""
    fp_by_type: dict[str, list[dict]] = {}
    for f in result.false_positives_likely:
        ftype = f.type
        if ftype not in fp_by_type:
            fp_by_type[ftype] = []
        fp_by_type[ftype].append(
            {
                "id": f.id,
                "title": f.title,
                "url": f.affectedUrl,
                "confidence": f.confidenceScore,
                "severity": f.severity.value,
            }
        )

    # Confirmed findings (matched by benchmark) can help calibrate
    confirmed_types: set[str] = set()
    for m in result.matched_findings:
        confirmed_types.add(m["hemisx"]["type"])

    return {
        "totalCandidates": len(result.false_positives_likely),
        "byType": fp_by_type,
        "confirmedTypes": sorted(confirmed_types),
        "analysis": (
            f"{len(result.false_positives_likely)} HemisX findings with confidence "
            f"below 70% were not confirmed by the benchmark tool. "
            f"These are candidates for false positive review. "
            f"Types with confirmed detections ({len(confirmed_types)} types) have "
            f"validated detection logic."
        ),
    }


def generate_gap_summary_text(gap_report: dict) -> str:
    """Generate a human-readable text summary of the gap analysis."""
    ga = gap_report.get("gapAnalysis", gap_report)
    summary = ga.get("summary", {})
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("  HemisX DAST Gap Analysis Report")
    lines.append("=" * 60)
    lines.append("")

    meta = ga.get("metadata", {})
    if meta:
        lines.append(f"Generated: {meta.get('generatedAt', 'N/A')}")
        lines.append(f"Scan ID:   {meta.get('scanId', 'N/A')}")
        lines.append(f"Benchmark: {meta.get('benchmarkSource', 'N/A')}")
        lines.append("")

    lines.append("--- Summary ---")
    lines.append(f"HemisX findings:      {summary.get('hemisx_total', 0)}")
    lines.append(f"Benchmark findings:   {summary.get('benchmark_total', 0)}")
    lines.append(f"Matched:              {summary.get('matched', 0)}")
    lines.append(f"Coverage:             {summary.get('coverage_percentage', 0)}%")
    lines.append(f"Missed vulns:         {summary.get('missed_vulnerabilities', 0)}")
    lines.append(f"FP candidates:        {summary.get('false_positive_candidates', 0)}")
    lines.append("")

    # Coverage matrix
    cov_matrix = ga.get("coverageMatrix", {})
    categories = cov_matrix.get("categories", {})
    if categories:
        lines.append("--- Category Coverage ---")
        lines.append(f"{'Category':<25} {'HemisX':<10} {'Benchmark':<12} {'Gap':<5}")
        lines.append("-" * 55)
        for cat, info in categories.items():
            h = "Yes" if info.get("hemisx") else "No"
            b = "Yes" if info.get("benchmark") else "No"
            g = "GAP" if info.get("gap") else ""
            lines.append(f"{cat:<25} {h:<10} {b:<12} {g:<5}")
        lines.append("")

    # Missed findings
    missed = ga.get("missed_by_hemisx", [])
    if missed:
        lines.append(f"--- Missed by HemisX ({len(missed)} findings) ---")
        for m in missed:
            sev = m.get("severity", "?")
            lines.append(f"  [{sev}] {m.get('title', '?')} @ {m.get('url', '?')}")
        lines.append("")

    # Roadmap
    roadmap = ga.get("improvementRoadmap", [])
    if roadmap:
        lines.append("--- Improvement Roadmap ---")
        for step in roadmap:
            lines.append(
                f"  {step['step']}. [{step['priority']}] {step['area']}: "
                f"{step['description']} (Est: {step['estimatedEffort']})"
            )
        lines.append("")

    return "\n".join(lines)
