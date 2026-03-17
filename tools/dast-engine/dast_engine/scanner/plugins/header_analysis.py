"""Security header analysis (passive - no injection)."""
from __future__ import annotations
from ..base_plugin import BasePlugin, ScanTarget, RawFinding


REQUIRED_HEADERS = [
    {
        "header": "content-security-policy",
        "vuln_type": "missing_csp",
        "title": "Missing Content-Security-Policy Header",
        "description": "The application does not set a Content-Security-Policy header, leaving it more susceptible to XSS and data injection attacks.",
        "remediation": "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
        "business_impact": "Increases the attack surface for cross-site scripting and data injection attacks.",
    },
    {
        "header": "strict-transport-security",
        "vuln_type": "missing_hsts",
        "title": "Missing Strict-Transport-Security Header",
        "description": "The application does not enforce HTTPS via HSTS, allowing potential downgrade attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "business_impact": "Users may be tricked into using unencrypted HTTP connections, exposing credentials.",
    },
    {
        "header": "x-frame-options",
        "vuln_type": "missing_anti_clickjacking",
        "title": "Missing X-Frame-Options Header",
        "description": "The application can be embedded in iframes, making it vulnerable to clickjacking attacks.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
        "business_impact": "Attackers can trick users into performing unintended actions via invisible iframes.",
    },
    {
        "header": "x-content-type-options",
        "vuln_type": "missing_x_content_type_options",
        "title": "Missing X-Content-Type-Options Header",
        "description": "The browser may MIME-sniff responses, potentially interpreting non-executable content as executable.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "business_impact": "MIME-sniffing can lead to security vulnerabilities when user-uploaded content is served.",
    },
    {
        "header": "referrer-policy",
        "vuln_type": "missing_referrer_policy",
        "title": "Missing Referrer-Policy Header",
        "description": "The application does not control referrer information leakage to external sites.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "business_impact": "Sensitive URL paths and query parameters may be leaked to third-party sites via the Referer header.",
    },
    {
        "header": "permissions-policy",
        "vuln_type": "missing_permissions_policy",
        "title": "Missing Permissions-Policy Header",
        "description": "The application does not restrict browser features like camera, microphone, geolocation.",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "business_impact": "Embedded third-party scripts may access sensitive browser APIs without restriction.",
    },
]


class HeaderAnalysisPlugin(BasePlugin):
    name = "Security Header Analyzer"
    vuln_type = "security_headers"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        headers = {k.lower(): v for k, v in target.response_headers.items()}

        for check in REQUIRED_HEADERS:
            if check["header"] not in headers:
                findings.append(RawFinding(
                    vuln_type=check["vuln_type"],
                    title=check["title"],
                    description=check["description"],
                    affected_url=target.url,
                    severity="LOW",
                    remediation=check["remediation"],
                    confidence=100,
                    business_impact=check.get("business_impact", ""),
                    request_evidence=f"GET {target.url}",
                    response_evidence=f"Header '{check['header']}' is not present in the response.",
                ))

        # Check for information disclosure headers
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            findings.append(RawFinding(
                vuln_type="server_version_leak",
                title="Server Version Information Disclosure",
                description=f"The Server header reveals version information: '{server}'",
                affected_url=target.url, severity="LOW",
                remediation="Remove or obfuscate the Server header to prevent technology fingerprinting.",
                confidence=100,
                response_evidence=f"Server: {server}",
                business_impact="Aids attacker reconnaissance by revealing the web server software and version.",
            ))

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            findings.append(RawFinding(
                vuln_type="information_disclosure",
                title="X-Powered-By Information Disclosure",
                description=f"The X-Powered-By header reveals technology stack: '{x_powered}'",
                affected_url=target.url, severity="LOW",
                remediation="Remove the X-Powered-By header from responses.",
                confidence=100,
                response_evidence=f"X-Powered-By: {x_powered}",
                business_impact="Technology stack disclosure aids targeted attacks.",
            ))

        return findings
