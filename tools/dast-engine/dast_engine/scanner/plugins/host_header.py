"""
Host header injection detection.

Tests for host header manipulation vulnerabilities including reflected host,
X-Forwarded-Host injection, and port manipulation. Runs once per domain.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


class HostHeaderPlugin(BasePlugin):
    name = "Host Header Injection Scanner"
    vuln_type = "host_header_injection"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        parsed = urlparse(target.url)
        hostname = parsed.netloc
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Only run once per domain from root URL
        dedup_key = f"host_header_{parsed.netloc}"
        if dedup_key in ctx.reported_domains:
            return findings

        if target.url.rstrip("/") != origin and parsed.path not in ("", "/", "/index.html"):
            return findings

        ctx.reported_domains.add(dedup_key)

        evil_host = "evil.attacker.com"

        # --- Test 1: Direct Host header injection ---
        resp = await self._send_request(
            ctx,
            target.url,
            headers={**target.headers, "Host": evil_host},
            cookies=target.cookies,
            follow_redirects=False,
        )

        if resp is not None:
            body = resp.text[:10000] if hasattr(resp, 'text') else ""
            resp_headers_str = str(dict(resp.headers))

            if evil_host in body or evil_host in resp_headers_str:
                # Verify
                verify = await self._send_request(
                    ctx,
                    target.url,
                    headers={**target.headers, "Host": evil_host},
                    cookies=target.cookies,
                    follow_redirects=False,
                )
                if verify is not None:
                    v_body = verify.text[:10000] if hasattr(verify, 'text') else ""
                    v_headers = str(dict(verify.headers))
                    if evil_host in v_body or evil_host in v_headers:
                        evidence_location = "response body" if evil_host in v_body else "response headers"
                        findings.append(RawFinding(
                            vuln_type="host_header_injection",
                            title="Host Header Injection — Reflected in Response",
                            description=(
                                f"The injected Host header value '{evil_host}' is reflected in the "
                                f"{evidence_location}. This can be exploited for password reset poisoning, "
                                f"cache poisoning, or SSRF. Verified with two independent requests."
                            ),
                            affected_url=target.url,
                            severity="HIGH",
                            payload=f"Host: {evil_host}",
                            request_evidence=f"Host: {evil_host}",
                            response_evidence=self._extract_evidence(v_body, v_headers, evil_host),
                            remediation=(
                                "Validate the Host header against a whitelist of expected hostnames. "
                                "Do not use the Host header to generate URLs in responses or emails."
                            ),
                            confidence=90,
                            verified=True,
                            business_impact="Password reset poisoning, web cache poisoning, or SSRF attacks.",
                        ))

        # --- Test 2: X-Forwarded-Host injection ---
        resp = await self._send_request(
            ctx,
            target.url,
            headers={**target.headers, "X-Forwarded-Host": evil_host},
            cookies=target.cookies,
            follow_redirects=False,
        )

        if resp is not None:
            body = resp.text[:10000] if hasattr(resp, 'text') else ""
            resp_headers_str = str(dict(resp.headers))

            if evil_host in body or evil_host in resp_headers_str:
                # Verify
                verify = await self._send_request(
                    ctx,
                    target.url,
                    headers={**target.headers, "X-Forwarded-Host": evil_host},
                    cookies=target.cookies,
                    follow_redirects=False,
                )
                if verify is not None:
                    v_body = verify.text[:10000] if hasattr(verify, 'text') else ""
                    v_headers = str(dict(verify.headers))
                    if evil_host in v_body or evil_host in v_headers:
                        evidence_location = "response body" if evil_host in v_body else "response headers"
                        findings.append(RawFinding(
                            vuln_type="x_forwarded_host_injection",
                            title="X-Forwarded-Host Injection — Reflected in Response",
                            description=(
                                f"The injected X-Forwarded-Host header value '{evil_host}' is reflected in the "
                                f"{evidence_location}. Applications behind reverse proxies may trust this header, "
                                f"enabling cache poisoning and redirect attacks. Verified with two requests."
                            ),
                            affected_url=target.url,
                            severity="HIGH",
                            payload=f"X-Forwarded-Host: {evil_host}",
                            request_evidence=f"X-Forwarded-Host: {evil_host}",
                            response_evidence=self._extract_evidence(v_body, v_headers, evil_host),
                            remediation=(
                                "Do not trust X-Forwarded-Host for generating URLs. Configure the reverse proxy "
                                "to strip or validate this header before passing to the application."
                            ),
                            confidence=85,
                            verified=True,
                            business_impact="Cache poisoning, password reset poisoning via X-Forwarded-Host.",
                        ))

        # --- Test 3: Host header with port manipulation ---
        port_host = f"{hostname}:@{evil_host}"
        resp = await self._send_request(
            ctx,
            target.url,
            headers={**target.headers, "Host": port_host},
            cookies=target.cookies,
            follow_redirects=False,
        )

        if resp is not None:
            body = resp.text[:10000] if hasattr(resp, 'text') else ""
            if evil_host in body:
                # Verify
                verify = await self._send_request(
                    ctx,
                    target.url,
                    headers={**target.headers, "Host": port_host},
                    cookies=target.cookies,
                    follow_redirects=False,
                )
                if verify is not None:
                    v_body = verify.text[:10000] if hasattr(verify, 'text') else ""
                    if evil_host in v_body:
                        findings.append(RawFinding(
                            vuln_type="host_header_port_injection",
                            title="Host Header Port Manipulation — Attacker Domain Reflected",
                            description=(
                                f"The Host header with port manipulation '{port_host}' causes the attacker "
                                f"domain to be reflected in the response. This bypasses some Host header "
                                f"validation. Verified with two requests."
                            ),
                            affected_url=target.url,
                            severity="MEDIUM",
                            payload=f"Host: {port_host}",
                            request_evidence=f"Host: {port_host}",
                            response_evidence=self._extract_evidence(v_body, "", evil_host),
                            remediation=(
                                "Validate the entire Host header including port. Use URL parsing "
                                "that correctly handles the userinfo@host syntax."
                            ),
                            confidence=80,
                            verified=True,
                            business_impact="Host validation bypass may enable cache poisoning or redirect attacks.",
                        ))

        # --- Test 4: Password reset poisoning check ---
        # Look for password reset forms and test if host is used in generated links
        if target.response_body:
            body_lower = target.response_body.lower()
            has_reset_form = any(kw in body_lower for kw in [
                "password reset", "forgot password", "reset your password",
                "forgot-password", "resetpassword",
            ])
            if has_reset_form:
                findings.append(RawFinding(
                    vuln_type="potential_password_reset_poisoning",
                    title="Password Reset Form Detected — Review for Host Header Poisoning",
                    description=(
                        "A password reset form was detected on this page. If the application uses "
                        "the Host header to generate reset links in emails, an attacker could poison "
                        "the link to steal reset tokens. Manual verification recommended."
                    ),
                    affected_url=target.url,
                    severity="INFO",
                    remediation=(
                        "Ensure password reset emails use a hardcoded base URL from server configuration, "
                        "not the Host header from the incoming request."
                    ),
                    confidence=50,
                    verified=False,
                    business_impact="Password reset poisoning could allow account takeover.",
                ))

        return findings

    @staticmethod
    def _extract_evidence(body: str, headers_str: str, marker: str) -> str:
        """Extract the portion of body or headers containing the marker."""
        for text in [body, headers_str]:
            idx = text.find(marker)
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(text), idx + len(marker) + 50)
                return text[start:end]
        return f"Marker '{marker}' found in response"
