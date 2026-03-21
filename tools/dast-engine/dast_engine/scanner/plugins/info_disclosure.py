"""
Information disclosure detection — exposed files, error messages, stack traces.

Validates that sensitive file content is actually present (not just a 200 status on
a custom 404 page), and that error patterns are specific enough to avoid false positives.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

SENSITIVE_PATHS = [
    ("/.env", [r"DB_PASSWORD\s*=", r"API_KEY\s*=", r"SECRET\s*=", r"AWS_ACCESS_KEY", r"DATABASE_URL\s*="], "Environment file"),
    ("/.git/config", [r"\[core\][\s\S]*repositoryformatversion"], "Git configuration"),
    ("/.git/HEAD", [r"^ref: refs/heads/\w+"], "Git HEAD reference"),
    ("/phpinfo.php", [r"<title>phpinfo\(\)</title>", r"PHP Version \d+\.\d+"], "PHP Info page"),
    ("/server-status", [r"Apache Server Status for", r"Server uptime:"], "Apache server-status"),
    ("/.DS_Store", [r"Bud1"], "macOS directory metadata"),
    ("/crossdomain.xml", [r'allow-access-from\s+domain="\*"'], "Overly permissive crossdomain.xml"),
]

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\):", "Python stack trace"),
    (r"at\s+[\w.$]+\([\w.]+\.java:\d+\)", "Java stack trace"),
    (r"Fatal error:.*in\s+/\S+\.php\s+on\s+line\s+\d+", "PHP fatal error with file path"),
    (r"Exception in thread.*at\s+", "Java thread exception"),
    (r"Microsoft\.AspNetCore\.\w+|System\.Web\.\w+", ".NET stack trace"),
]


class InfoDisclosurePlugin(BasePlugin):
    name = "Information Disclosure Scanner"
    vuln_type = "information_disclosure"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Check current page for error patterns (only on HTML pages)
        if target.response_body and target.content_type and "html" in target.content_type:
            for pattern, desc in ERROR_PATTERNS:
                match = re.search(pattern, target.response_body, re.IGNORECASE)
                if match:
                    evidence = target.response_body[max(0, match.start() - 30):match.end() + 100]
                    findings.append(RawFinding(
                        vuln_type="debug_error_messages",
                        title=f"Detailed Error Messages Exposed ({desc})",
                        description=(
                            f"The page exposes {desc} in its response, revealing internal "
                            f"implementation details like file paths and framework internals."
                        ),
                        affected_url=target.url, severity="LOW",
                        response_evidence=evidence[:200],
                        remediation="Disable verbose error messages in production. Return generic error responses.",
                        confidence=85, verified=True,
                        business_impact="Reveals file paths, framework internals, and aids attacker reconnaissance.",
                    ))
                    break

        # Probe for sensitive files (only run from root URL to avoid duplicates)
        parsed = urlparse(target.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Only probe once per domain
        if target.url.rstrip("/") != origin and parsed.path not in ("", "/", "/index.html"):
            return findings

        for path, detect_patterns, file_desc in SENSITIVE_PATHS:
            resp = await self._send_request(
                f"{origin}{path}",
                headers=target.headers,
                cookies=target.cookies,
            )
            if resp is None or resp.status_code >= 400:
                continue

            # Validate response is meaningful (not a custom 404 page)
            # Custom 404 pages often have the same template with generic HTML
            ct = resp.headers.get("content-type", "").lower()

            for pattern in detect_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if not match:
                    continue

                # Verification: check again to rule out intermittent responses
                verify = await self._send_request(
                    f"{origin}{path}",
                    headers=target.headers,
                    cookies=target.cookies,
                )
                if verify is None or verify.status_code >= 400:
                    continue
                if not re.search(pattern, verify.text, re.IGNORECASE):
                    continue

                evidence = resp.text[max(0, match.start() - 20):match.end() + 50]
                severity = "HIGH" if any(x in path for x in [".env", ".git/config", "phpinfo"]) else "MEDIUM"
                findings.append(RawFinding(
                    vuln_type="exposed_sensitive_file",
                    title=f"Exposed Sensitive File: {file_desc}",
                    description=(
                        f"The file '{path}' is publicly accessible and contains sensitive information. "
                        f"Verified with two independent requests."
                    ),
                    affected_url=f"{origin}{path}", severity=severity,
                    payload=path,
                    response_evidence=evidence[:200],
                    remediation=f"Block access to '{path}' via web server configuration. Never expose configuration or VCS files.",
                    confidence=90, verified=True,
                    business_impact=f"Exposure of {file_desc} may reveal credentials, internal paths, or deployment details.",
                ))
                break

        return findings
