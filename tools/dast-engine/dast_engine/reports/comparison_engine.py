"""
Report comparison engine -- compares HemisX findings against benchmark
DAST tool results (Burp Suite, OWASP ZAP) to identify coverage gaps.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .burp_parser import BurpFinding
from ..models.finding import Finding


# ---------------------------------------------------------------------------
# Vulnerability category mapping -- normalizes different tools' naming
# ---------------------------------------------------------------------------

CATEGORY_MAPPING: dict[str, list[str]] = {
    # Burp names -> HemisX vuln_types
    "Strict transport security not enforced": ["missing_hsts"],
    "Cross-origin resource sharing": ["cors_misconfiguration"],
    "Cross-origin resource sharing: arbitrary origin trusted": ["cors_misconfiguration"],
    "Frameable response (potential Clickjacking)": ["missing_anti_clickjacking"],
    "DOM data manipulation (DOM-based)": ["xss_dom"],
    "Backup file": ["exposed_backup_file"],
    "Cacheable HTTPS response": ["cacheable_https_response"],
    "TLS certificate": [
        "tls_certificate_expired",
        "tls_self_signed",
        "tls_weak_algorithm",
        "tls_hostname_mismatch",
    ],
    "SQL injection": [
        "sql_injection",
        "sql_injection_mysql",
        "sql_injection_postgres",
        "sql_injection_mssql",
    ],
    "Cross-site scripting (reflected)": ["xss_reflected"],
    "Cross-site scripting (stored)": ["xss_stored"],
    "Open redirection (reflected)": ["open_redirect"],
    "Server-side template injection": ["ssti"],
    "OS command injection": ["command_injection"],
    "Path traversal": ["directory_traversal"],
    "Server-side request forgery (SSRF)": ["ssrf"],
    "Missing or insecure Content-Security-Policy": ["missing_csp"],
    "Cookie without HttpOnly flag set": ["cookie_missing_httponly"],
    "Cookie without Secure flag set": ["cookie_missing_secure"],
    "Information disclosure": ["information_disclosure", "server_version_leak"],
    "XML injection": ["xml_injection"],
    "LDAP injection": ["ldap_injection"],
    "HTTP response header injection": ["header_injection"],
    "Email header injection": ["email_header_injection"],
    "File path manipulation": ["directory_traversal"],
    "Out-of-band resource load (HTTP)": ["ssrf"],
    "Input returned in response (reflected)": ["xss_reflected"],
    "Content type incorrectly stated": ["content_type_mismatch"],
    "Password field with autocomplete enabled": ["password_autocomplete"],
}

# Reverse mapping: HemisX type -> broad category name
_REVERSE_MAP: dict[str, str] = {}
for _burp_name, _hemisx_types in CATEGORY_MAPPING.items():
    for _ht in _hemisx_types:
        # Keep first mapping (most specific Burp name)
        if _ht not in _REVERSE_MAP:
            _REVERSE_MAP[_ht] = _burp_name

# Broad categories for grouping (used in category_coverage)
BROAD_CATEGORIES: dict[str, list[str]] = {
    "Injection": [
        "sql_injection", "sql_injection_mysql", "sql_injection_postgres",
        "sql_injection_mssql", "command_injection", "ssti", "xml_injection",
        "ldap_injection", "header_injection", "email_header_injection",
    ],
    "XSS": ["xss_reflected", "xss_stored", "xss_dom"],
    "SSRF": ["ssrf"],
    "Path Traversal": ["directory_traversal"],
    "Open Redirect": ["open_redirect"],
    "TLS/SSL": [
        "tls_certificate_expired", "tls_self_signed", "tls_weak_algorithm",
        "tls_hostname_mismatch",
    ],
    "Security Headers": [
        "missing_hsts", "missing_csp", "missing_anti_clickjacking",
        "cors_misconfiguration",
    ],
    "Cookie Security": ["cookie_missing_httponly", "cookie_missing_secure"],
    "Information Disclosure": [
        "information_disclosure", "server_version_leak", "exposed_backup_file",
    ],
}

# Reverse: hemisx type -> broad category
_TYPE_TO_BROAD: dict[str, str] = {}
for _cat, _types in BROAD_CATEGORIES.items():
    for _t in _types:
        _TYPE_TO_BROAD[_t] = _cat


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ComparisonResult:
    """Result of comparing two scan reports."""

    hemisx_findings: list[Finding]
    benchmark_findings: list[BurpFinding]

    matched_findings: list[dict] = field(default_factory=list)
    hemisx_only: list[Finding] = field(default_factory=list)
    benchmark_only: list[BurpFinding] = field(default_factory=list)

    # Coverage analysis
    category_coverage: dict[str, dict] = field(default_factory=dict)
    coverage_percentage: float = 0.0

    # Summary
    total_hemisx: int = 0
    total_benchmark: int = 0
    total_matched: int = 0

    false_positives_likely: list[Finding] = field(default_factory=list)
    false_negatives: list[BurpFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ComparisonEngine:
    """Compares scan results from different tools."""

    def compare(
        self,
        hemisx_findings: list[Finding],
        benchmark_findings: list[BurpFinding],
    ) -> ComparisonResult:
        """Compare HemisX findings against benchmark findings."""
        result = ComparisonResult(
            hemisx_findings=hemisx_findings,
            benchmark_findings=benchmark_findings,
            total_hemisx=len(hemisx_findings),
            total_benchmark=len(benchmark_findings),
        )

        # Track which findings have been matched
        matched_hemisx_ids: set[str] = set()
        matched_burp_ids: set[str] = set()

        # Try to match each HemisX finding against each benchmark finding
        for hf in hemisx_findings:
            for bf in benchmark_findings:
                if bf.issue_id in matched_burp_ids:
                    continue
                if self._match_finding(hf, bf):
                    result.matched_findings.append(
                        {
                            "hemisx": {
                                "id": hf.id,
                                "title": hf.title,
                                "type": hf.type,
                                "severity": hf.severity.value,
                                "url": hf.affectedUrl,
                                "confidence": hf.confidenceScore,
                            },
                            "benchmark": {
                                "id": bf.issue_id,
                                "title": bf.title,
                                "severity": bf.severity,
                                "url": bf.url,
                                "confidence": bf.confidence,
                            },
                            "severity_match": hf.severity.value == bf.normalized_severity,
                        }
                    )
                    matched_hemisx_ids.add(hf.id)
                    matched_burp_ids.add(bf.issue_id)
                    break

        # Unmatched findings
        result.hemisx_only = [f for f in hemisx_findings if f.id not in matched_hemisx_ids]
        result.benchmark_only = [f for f in benchmark_findings if f.issue_id not in matched_burp_ids]

        result.total_matched = len(result.matched_findings)

        # Classify unmatched findings
        # HemisX-only findings with low confidence are likely false positives
        result.false_positives_likely = [
            f for f in result.hemisx_only if f.confidenceScore < 70
        ]
        # High-confidence benchmark-only findings are likely false negatives
        result.false_negatives = [
            f for f in result.benchmark_only
            if f.confidence in ("Certain", "Firm")
        ]

        # Category coverage analysis
        result.category_coverage = self._compute_category_coverage(
            hemisx_findings, benchmark_findings
        )

        # Overall coverage percentage: what fraction of benchmark findings
        # did HemisX also detect?
        if result.total_benchmark > 0:
            result.coverage_percentage = round(
                (result.total_matched / result.total_benchmark) * 100, 1
            )
        else:
            result.coverage_percentage = 100.0 if result.total_hemisx == 0 else 0.0

        return result

    # ------------------------------------------------------------------
    # Matching logic
    # ------------------------------------------------------------------

    def _match_finding(self, hemisx: Finding, burp: BurpFinding) -> bool:
        """Determine if two findings from different tools refer to the same
        vulnerability.

        Matching criteria (all must hold):
        1. The vulnerability categories are compatible.
        2. The affected URLs are similar (same host + overlapping path).
        """
        # 1. Category match
        if not self._categories_match(hemisx.type, burp.title):
            return False

        # 2. URL similarity
        if not self._urls_similar(hemisx.affectedUrl, burp.url):
            return False

        return True

    def _categories_match(self, hemisx_type: str, burp_title: str) -> bool:
        """Check whether a HemisX finding type matches a Burp finding title."""
        hemisx_lower = hemisx_type.lower()

        # Direct lookup: does the Burp title map to types that include our type?
        for burp_name, hemisx_types in CATEGORY_MAPPING.items():
            if burp_name.lower() in burp_title.lower():
                if hemisx_lower in [t.lower() for t in hemisx_types]:
                    return True

        # Fuzzy: same broad category
        hemisx_broad = _TYPE_TO_BROAD.get(hemisx_lower)
        if hemisx_broad:
            for burp_name, hemisx_types in CATEGORY_MAPPING.items():
                if burp_name.lower() in burp_title.lower():
                    for ht in hemisx_types:
                        if _TYPE_TO_BROAD.get(ht) == hemisx_broad:
                            return True

        # Last resort: simple keyword overlap
        burp_words = set(re.findall(r"[a-z]+", burp_title.lower()))
        hemisx_words = set(re.findall(r"[a-z]+", hemisx_lower.replace("_", " ")))
        overlap = burp_words & hemisx_words - {"the", "a", "an", "in", "of", "and", "or"}
        if len(overlap) >= 2:
            return True

        return False

    @staticmethod
    def _urls_similar(url_a: str, url_b: str) -> bool:
        """Check whether two URLs point at roughly the same resource.

        Compares hostname and path prefix. We are lenient because Burp and
        HemisX may record slightly different URL forms.
        """
        if not url_a or not url_b:
            return True  # If either URL is missing, don't fail the match on URL alone

        try:
            pa = urlparse(url_a if "://" in url_a else f"https://{url_a}")
            pb = urlparse(url_b if "://" in url_b else f"https://{url_b}")
        except Exception:
            return False

        # Hostnames must match (ignoring port and scheme)
        host_a = pa.hostname or ""
        host_b = pb.hostname or ""
        if host_a and host_b and host_a.lower() != host_b.lower():
            return False

        # Paths: one should be a prefix of the other, or they share at least
        # the first two segments.
        path_a = pa.path.rstrip("/")
        path_b = pb.path.rstrip("/")
        if path_a == path_b:
            return True
        if path_a.startswith(path_b) or path_b.startswith(path_a):
            return True

        seg_a = [s for s in path_a.split("/") if s]
        seg_b = [s for s in path_b.split("/") if s]
        shared = sum(1 for a, b in zip(seg_a, seg_b) if a == b)
        if shared >= 1 and (shared >= len(seg_a) // 2 or shared >= len(seg_b) // 2):
            return True

        return False

    # ------------------------------------------------------------------
    # Category coverage
    # ------------------------------------------------------------------

    def _compute_category_coverage(
        self,
        hemisx_findings: list[Finding],
        benchmark_findings: list[BurpFinding],
    ) -> dict[str, dict]:
        """Compute per-broad-category coverage matrix."""
        coverage: dict[str, dict] = {}

        # Determine which broad categories each tool found
        hemisx_cats: set[str] = set()
        for f in hemisx_findings:
            cat = _TYPE_TO_BROAD.get(f.type.lower())
            if cat:
                hemisx_cats.add(cat)

        benchmark_cats: set[str] = set()
        for bf in benchmark_findings:
            for burp_name, hemisx_types in CATEGORY_MAPPING.items():
                if burp_name.lower() in bf.title.lower():
                    for ht in hemisx_types:
                        cat = _TYPE_TO_BROAD.get(ht)
                        if cat:
                            benchmark_cats.add(cat)
                    break

        all_cats = hemisx_cats | benchmark_cats
        for cat in sorted(all_cats):
            coverage[cat] = {
                "hemisx_detected": cat in hemisx_cats,
                "benchmark_detected": cat in benchmark_cats,
                "status": (
                    "both"
                    if cat in hemisx_cats and cat in benchmark_cats
                    else "hemisx_only"
                    if cat in hemisx_cats
                    else "benchmark_only"
                ),
            }

        return coverage

    def _categorize_finding(self, finding_type: str) -> str:
        """Map a specific vulnerability type to a broad category."""
        return _TYPE_TO_BROAD.get(finding_type.lower(), "Other")

    # ------------------------------------------------------------------
    # Gap report generation
    # ------------------------------------------------------------------

    def generate_gap_report(self, result: ComparisonResult) -> dict:
        """Generate a detailed gap analysis report."""
        # Matched summary
        matched_summary = []
        for m in result.matched_findings:
            matched_summary.append(
                {
                    "hemisx_id": m["hemisx"]["id"],
                    "benchmark_id": m["benchmark"]["id"],
                    "title": m["benchmark"]["title"],
                    "hemisx_severity": m["hemisx"]["severity"],
                    "benchmark_severity": m["benchmark"]["severity"],
                    "severity_agreement": m["severity_match"],
                    "url": m["benchmark"]["url"],
                }
            )

        # Missed by HemisX
        missed = []
        for bf in result.benchmark_only:
            missed.append(
                {
                    "benchmark_id": bf.issue_id,
                    "title": bf.title,
                    "severity": bf.severity,
                    "confidence": bf.confidence,
                    "url": bf.url,
                    "category": self._categorize_finding_from_burp(bf.title),
                    "remediation_hint": bf.remediation[:300] if bf.remediation else "",
                    "issue_detail": bf.issue_detail[:500] if bf.issue_detail else "",
                }
            )

        # HemisX unique findings
        hemisx_unique = []
        for hf in result.hemisx_only:
            hemisx_unique.append(
                {
                    "hemisx_id": hf.id,
                    "title": hf.title,
                    "type": hf.type,
                    "severity": hf.severity.value,
                    "url": hf.affectedUrl,
                    "confidence": hf.confidenceScore,
                    "likely_false_positive": hf.confidenceScore < 70,
                }
            )

        # Recommendations
        recommendations = self._generate_recommendations(result)

        return {
            "summary": {
                "hemisx_total": result.total_hemisx,
                "benchmark_total": result.total_benchmark,
                "matched": result.total_matched,
                "coverage_percentage": result.coverage_percentage,
                "false_positive_candidates": len(result.false_positives_likely),
                "missed_vulnerabilities": len(result.false_negatives),
            },
            "matched": matched_summary,
            "missed_by_hemisx": missed,
            "hemisx_unique": hemisx_unique,
            "category_coverage": result.category_coverage,
            "recommendations": recommendations,
        }

    def _categorize_finding_from_burp(self, burp_title: str) -> str:
        """Map a Burp finding title to a broad category."""
        for burp_name, hemisx_types in CATEGORY_MAPPING.items():
            if burp_name.lower() in burp_title.lower():
                for ht in hemisx_types:
                    cat = _TYPE_TO_BROAD.get(ht)
                    if cat:
                        return cat
        return "Other"

    def _generate_recommendations(self, result: ComparisonResult) -> list[dict]:
        """Generate actionable improvement recommendations based on gaps."""
        recommendations: list[dict] = []

        # 1. Missed vulnerability categories
        missed_cats: set[str] = set()
        for cat, info in result.category_coverage.items():
            if info["status"] == "benchmark_only":
                missed_cats.add(cat)

        if missed_cats:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "area": "Detection Coverage",
                    "finding": f"HemisX missed {len(missed_cats)} vulnerability categories detected by the benchmark tool: {', '.join(sorted(missed_cats))}.",
                    "action": "Add or improve scanner modules for the missing categories. Review detection rules and payloads for these vulnerability classes.",
                }
            )

        # 2. High-severity misses
        high_sev_missed = [
            bf for bf in result.false_negatives if bf.severity in ("High",)
        ]
        if high_sev_missed:
            titles = list({bf.title for bf in high_sev_missed})
            recommendations.append(
                {
                    "priority": "CRITICAL",
                    "area": "High-Severity Detection",
                    "finding": f"{len(high_sev_missed)} high-severity vulnerabilities were missed: {', '.join(titles[:5])}.",
                    "action": "Investigate why these high-severity issues were not detected. Check if the relevant scanner modules ran, payloads were adequate, and response analysis captured the indicators.",
                }
            )

        # 3. False positive candidates
        if result.false_positives_likely:
            fp_types = list({f.type for f in result.false_positives_likely})
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "area": "False Positive Reduction",
                    "finding": f"{len(result.false_positives_likely)} HemisX findings (low confidence) were not confirmed by the benchmark tool. Types: {', '.join(fp_types[:5])}.",
                    "action": "Review detection logic for these vulnerability types. Consider adding confirmation steps or raising the confidence threshold.",
                }
            )

        # 4. Severity disagreements
        sev_mismatches = [m for m in result.matched_findings if not m["severity_match"]]
        if sev_mismatches:
            recommendations.append(
                {
                    "priority": "LOW",
                    "area": "Severity Calibration",
                    "finding": f"{len(sev_mismatches)} matched findings have different severity ratings between HemisX and the benchmark.",
                    "action": "Review CVSS scoring logic and severity classification. Align with industry-standard severity ratings.",
                }
            )

        # 5. Coverage percentage
        if result.coverage_percentage < 70:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "area": "Overall Coverage",
                    "finding": f"HemisX detected only {result.coverage_percentage}% of benchmark findings.",
                    "action": "Conduct a comprehensive review of scanner modules. Ensure all OWASP Top 10 categories have adequate test coverage.",
                }
            )
        elif result.coverage_percentage < 90:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "area": "Overall Coverage",
                    "finding": f"HemisX coverage is at {result.coverage_percentage}%. Target is 90%+.",
                    "action": "Focus on the missed vulnerability categories and edge cases to close the remaining coverage gap.",
                }
            )

        # 6. HemisX-unique high-confidence findings (potential benchmark gaps)
        unique_high_conf = [
            f for f in result.hemisx_only if f.confidenceScore >= 80
        ]
        if unique_high_conf:
            recommendations.append(
                {
                    "priority": "INFO",
                    "area": "HemisX Advantages",
                    "finding": f"HemisX uniquely detected {len(unique_high_conf)} high-confidence findings not found by the benchmark tool.",
                    "action": "These represent potential advantages of HemisX. Document them as differentiators and verify they are true positives.",
                }
            )

        return recommendations
