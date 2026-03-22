"""
Cacheable HTTPS response detection.

Checks for HTTPS responses that may be cached by intermediaries or browsers,
especially those containing sensitive content like authentication forms or tokens.
Runs per URL (not per domain).
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Patterns that indicate sensitive content which should not be cached
SENSITIVE_PATTERNS = [
    (r'<input[^>]+type=["\']password["\']', "password input field"),
    (r'<form[^>]+action=[^>]*(login|signin|auth)', "login/authentication form"),
    (r'(csrf[_-]?token|authenticity[_-]?token|__RequestVerificationToken)', "CSRF/auth token"),
    (r'(api[_-]?key|access[_-]?token|bearer\s+\w{20,})', "API key or access token"),
    (r'Set-Cookie:\s*\w+', "Set-Cookie header"),
]


class CacheAnalysisPlugin(BasePlugin):
    name = "Cacheable HTTPS Response Analyzer"
    vuln_type = "cacheable_https_response"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        parsed = urlparse(target.url)
        if parsed.scheme != "https":
            return findings

        headers = {k.lower(): v for k, v in target.response_headers.items()}
        cache_control = headers.get("cache-control", "")
        pragma = headers.get("pragma", "")
        cc_lower = cache_control.lower()

        # Determine if response is cacheable
        is_cacheable = False
        cache_issue = ""

        if not cache_control:
            is_cacheable = True
            cache_issue = "No Cache-Control header present"
        elif "public" in cc_lower:
            is_cacheable = True
            cache_issue = f"Cache-Control contains 'public': {cache_control}"
        elif "no-store" not in cc_lower and "private" not in cc_lower:
            is_cacheable = True
            cache_issue = f"Cache-Control lacks 'no-store' and 'private': {cache_control}"

        if not is_cacheable:
            return findings

        # Verify with a fresh request
        resp = await self._send_request(
            ctx,
            target.url,
            headers=target.headers,
            cookies=target.cookies,
        )
        if resp is None:
            return findings

        fresh_cc = resp.headers.get("cache-control", "").lower()
        fresh_pragma = resp.headers.get("pragma", "")

        # Confirm the caching issue persists
        fresh_is_cacheable = (
            not fresh_cc
            or "public" in fresh_cc
            or ("no-store" not in fresh_cc and "private" not in fresh_cc)
        )

        if not fresh_is_cacheable:
            return findings

        # Check for sensitive content in the response body
        body = target.response_body or ""
        sensitive_content = []
        for pattern, desc in SENSITIVE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                sensitive_content.append(desc)

        # Also check Set-Cookie in response headers
        if "set-cookie" in headers:
            sensitive_content.append("Set-Cookie header in response")

        if sensitive_content:
            findings.append(RawFinding(
                vuln_type="cacheable_sensitive_response",
                title="Cacheable HTTPS Response with Sensitive Content",
                description=(
                    f"The HTTPS response is cacheable ({cache_issue}) and contains sensitive content: "
                    f"{', '.join(sensitive_content)}. This may allow shared caches or browser caches "
                    f"to store sensitive data. Verified with two requests."
                ),
                affected_url=target.url,
                severity="LOW",
                remediation=(
                    "Add 'Cache-Control: no-store, no-cache, must-revalidate' and "
                    "'Pragma: no-cache' headers to responses containing sensitive data."
                ),
                confidence=85,
                verified=True,
                response_evidence=f"Cache-Control: {cache_control or '(absent)'}\nSensitive content: {', '.join(sensitive_content)}",
                business_impact="Sensitive data (credentials, tokens) may be stored in shared or browser caches.",
            ))
        else:
            # Report as informational even without sensitive content
            findings.append(RawFinding(
                vuln_type="cacheable_https_response",
                title="Cacheable HTTPS Response",
                description=(
                    f"The HTTPS response is cacheable: {cache_issue}. "
                    f"While no sensitive content was detected in the body, the caching policy "
                    f"should be reviewed. Verified with two requests."
                ),
                affected_url=target.url,
                severity="INFO",
                remediation=(
                    "Review caching policy. For pages that may contain user-specific content, "
                    "add 'Cache-Control: no-store' or 'Cache-Control: private'."
                ),
                confidence=75,
                verified=True,
                response_evidence=f"Cache-Control: {cache_control or '(absent)'}",
                business_impact="HTTPS responses may be cached by proxies, potentially exposing user-specific content.",
            ))

        # Check for missing Pragma header alongside Cache-Control
        if cache_control and "no-cache" not in pragma.lower():
            findings.append(RawFinding(
                vuln_type="missing_pragma_no_cache",
                title="Missing Pragma: no-cache Header",
                description=(
                    "The response sets Cache-Control but does not include 'Pragma: no-cache'. "
                    "HTTP/1.0 proxies may ignore Cache-Control and cache the response."
                ),
                affected_url=target.url,
                severity="INFO",
                remediation="Add 'Pragma: no-cache' alongside Cache-Control for HTTP/1.0 compatibility.",
                confidence=70,
                verified=True,
                response_evidence=f"Cache-Control: {cache_control}\nPragma: {pragma or '(absent)'}",
                business_impact="HTTP/1.0 proxies may cache responses that should not be cached.",
            ))

        return findings
