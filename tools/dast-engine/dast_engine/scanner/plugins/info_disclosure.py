"""Information disclosure detection (exposed files, error messages, stack traces)."""
from __future__ import annotations
import re
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

SENSITIVE_PATHS = [
    ("/.env", [r"DB_PASSWORD", r"API_KEY", r"SECRET", r"AWS_", r"DATABASE_URL"], "Environment file"),
    ("/.git/config", [r"\[core\]", r"\[remote", r"repositoryformatversion"], "Git configuration"),
    ("/.git/HEAD", [r"ref: refs/heads/"], "Git HEAD reference"),
    ("/wp-config.php.bak", [r"DB_NAME", r"DB_PASSWORD", r"table_prefix"], "WordPress config backup"),
    ("/phpinfo.php", [r"phpinfo\(\)", r"PHP Version", r"Configuration File"], "PHP Info page"),
    ("/server-status", [r"Apache Server Status", r"Server uptime"], "Apache server-status"),
    ("/debug", [r"Traceback|stacktrace|stack trace|DEBUG", r"Exception"], "Debug endpoint"),
    ("/.DS_Store", [r"Bud1"], "macOS directory metadata"),
    ("/crossdomain.xml", [r"allow-access-from.*domain=\"\*\""], "Overly permissive crossdomain.xml"),
    ("/robots.txt", [r"Disallow:.*admin|Disallow:.*secret|Disallow:.*backup"], "Sensitive paths in robots.txt"),
]

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at\s+[\w.$]+\([\w.]+:\d+\)", "Java/Node.js stack trace"),
    (r"Fatal error:.*in\s+/", "PHP fatal error with file path"),
    (r"Exception in thread", "Java thread exception"),
    (r"Microsoft\.AspNetCore|System\.Web", ".NET stack trace"),
    (r"SQLSTATE\[", "Database error with state code"),
]


class InfoDisclosurePlugin(BasePlugin):
    name = "Information Disclosure Scanner"
    vuln_type = "information_disclosure"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Check current page for error patterns
        if target.response_body:
            for pattern, desc in ERROR_PATTERNS:
                match = re.search(pattern, target.response_body, re.IGNORECASE)
                if match:
                    evidence = target.response_body[max(0, match.start()-30):match.end()+100]
                    findings.append(RawFinding(
                        vuln_type="debug_error_messages",
                        title=f"Detailed Error Messages Exposed ({desc})",
                        description=f"The page exposes {desc} in its response, potentially revealing internal implementation details.",
                        affected_url=target.url, severity="LOW",
                        response_evidence=evidence[:200],
                        remediation="Disable verbose error messages in production. Return generic error responses.",
                        confidence=85,
                        business_impact="Reveals file paths, framework internals, and aids attacker reconnaissance.",
                    ))
                    break  # One error finding per page

        # Probe for sensitive files
        from urllib.parse import urljoin
        base_url = target.url.rstrip("/")
        # Extract origin
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, detect_patterns, file_desc in SENSITIVE_PATHS:
            resp = await self._send_request(
                f"{origin}{path}",
                headers=target.headers,
                cookies=target.cookies,
            )
            if resp is None or resp.status_code >= 400:
                continue

            for pattern in detect_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    evidence = resp.text[max(0, match.start()-20):match.end()+50] if match else ""
                    findings.append(RawFinding(
                        vuln_type="exposed_sensitive_file",
                        title=f"Exposed Sensitive File: {file_desc}",
                        description=f"The file '{path}' is publicly accessible and contains sensitive information.",
                        affected_url=f"{origin}{path}", severity="HIGH" if "credential" in file_desc.lower() or ".env" in path else "MEDIUM",
                        payload=path,
                        response_evidence=evidence[:200],
                        remediation=f"Block access to '{path}' via web server configuration. Never expose configuration or version control files.",
                        confidence=90,
                        business_impact=f"Exposure of {file_desc} may reveal credentials, internal paths, or deployment details.",
                    ))
                    break

        return findings
