"""Cookie security analysis (passive - checks Set-Cookie attributes)."""
from __future__ import annotations
import re
from ..base_plugin import BasePlugin, ScanTarget, RawFinding


class CookieAnalysisPlugin(BasePlugin):
    name = "Cookie Security Analyzer"
    vuln_type = "insecure_cookie"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        set_cookies = []

        # Collect Set-Cookie headers
        for key, value in target.response_headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(value)

        # Also parse from raw headers if available
        raw = target.response_headers.get("set-cookie", "")
        if raw and raw not in set_cookies:
            set_cookies.append(raw)

        for cookie_str in set_cookies:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"

            # Skip non-session cookies
            session_indicators = ["session", "sid", "token", "auth", "jwt", "csrf", "phpsess", "jsession", "asp.net"]
            is_session = any(ind in name.lower() for ind in session_indicators)

            if not is_session:
                continue

            if "secure" not in cookie_lower:
                findings.append(RawFinding(
                    vuln_type="missing_secure_flag",
                    title=f"Session Cookie '{name}' Missing Secure Flag",
                    description=f"The cookie '{name}' is not set with the Secure flag, meaning it can be transmitted over unencrypted HTTP.",
                    affected_url=target.url, severity="LOW",
                    remediation="Set the Secure flag on all session cookies.",
                    confidence=90,
                    response_evidence=f"Set-Cookie: {cookie_str[:100]}",
                    business_impact="Session tokens can be intercepted in man-in-the-middle attacks.",
                ))

            if "httponly" not in cookie_lower:
                findings.append(RawFinding(
                    vuln_type="missing_httponly",
                    title=f"Session Cookie '{name}' Missing HttpOnly Flag",
                    description=f"The cookie '{name}' is not set with the HttpOnly flag, making it accessible to JavaScript.",
                    affected_url=target.url, severity="LOW",
                    remediation="Set the HttpOnly flag on all session cookies to prevent JavaScript access.",
                    confidence=90,
                    response_evidence=f"Set-Cookie: {cookie_str[:100]}",
                    business_impact="XSS attacks can steal session tokens via document.cookie.",
                ))

            if "samesite" not in cookie_lower:
                findings.append(RawFinding(
                    vuln_type="missing_samesite",
                    title=f"Session Cookie '{name}' Missing SameSite Attribute",
                    description=f"The cookie '{name}' does not have a SameSite attribute, increasing CSRF risk.",
                    affected_url=target.url, severity="LOW",
                    remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                    confidence=85,
                    response_evidence=f"Set-Cookie: {cookie_str[:100]}",
                    business_impact="Missing SameSite makes cookies vulnerable to cross-site request forgery.",
                ))

        return findings
